"""pyscan command-line entrypoint.

Usage:
  python3 -m pyscan run --product-config PATH --source-repo PATH [options]
  python3 -m pyscan build-cve-corpus --product-config PATH --source-repo PATH
  python3 -m pyscan check-egress [--allow-egress]
  python3 -m pyscan check-model

It drives the deterministic orchestrator against the local model endpoint.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from . import capabilities, cve_corpus, semgrep_rules
from .config import HUNT_MODES, LLMConfig, ProductConfig, RunContext, is_unset
from .llm import LocalLLM
from .netguard import check_egress
from .orchestrator import Orchestrator


def _detect_semgrep() -> str | None:
    env = os.environ.get("SEMGREP_BIN")
    if env and Path(env).exists():
        return env
    return shutil.which("semgrep")


def _build_context(args: argparse.Namespace) -> RunContext:
    product = ProductConfig.load(args.product_config)
    source_repo = Path(args.source_repo).resolve()
    if not source_repo.is_dir():
        raise SystemExit(f"source repo not found: {source_repo}")

    export_root = Path(__file__).resolve().parent.parent
    hunt_mode = args.hunt_mode or product.default_hunt_mode or "FULL_48H"
    if hunt_mode not in HUNT_MODES:
        raise SystemExit(f"unsupported hunt mode: {hunt_mode}")

    rulesets_env = os.environ.get("SEMGREP_RULESETS")
    rulesets = rulesets_env.split() if rulesets_env else list(semgrep_rules.DEFAULT_RULESETS)

    optional = args.optional_keywords or product.default_optional_keywords or "not enabled"

    # Output dir defaults to the source tree (.hunt there), but can be pointed
    # elsewhere so the source can be mounted read-only in the sandbox.
    if args.output_dir:
        hunt_dir = Path(args.output_dir).resolve() / ".hunt"
    else:
        hunt_dir = source_repo / ".hunt"

    return RunContext(
        product=product,
        llm=LLMConfig.from_env(),
        source_repo=source_repo,
        hunt_dir=hunt_dir,
        agents_dir=export_root / "agents",
        prompts_dir=export_root / "runtime-prompts",
        export_root=export_root,
        hunt_mode=hunt_mode,
        optional_keywords=optional,
        native_tooling=product.native_tooling,
        semgrep_bin=_detect_semgrep(),
        semgrep_rulesets=rulesets,
        semgrep_rules_cache=semgrep_rules.cache_dir(export_root),
        offline=not getattr(args, "allow_egress", False),
        dry_run=args.dry_run,
    )


RECON_MODES = ("RECON_ONLY", "FULL_48H")


def _corpus_location(ctx: RunContext) -> Path:
    """The product config's cve_corpus_dir, else this target's folder in the
    corpus that ships with pyscan."""
    if not is_unset(ctx.product.cve_corpus_dir):
        return Path(ctx.product.cve_corpus_dir).resolve()
    return cve_corpus.default_root(ctx.export_root) / cve_corpus.safe_name(ctx.product.product_key)


def _build_command(args: argparse.Namespace) -> str:
    return (f"python3 -m pyscan build-cve-corpus --product-config {args.product_config} "
            f"--source-repo {args.source_repo}")


def cmd_run(args: argparse.Namespace) -> int:
    ctx = _build_context(args)
    # Egress isolation is mandatory unless explicitly waived (local dev only).
    if not args.allow_egress:
        check_egress(ctx.llm.base_url, strict=True)
    else:
        print("WARNING: egress check waived (--allow-egress); not for production scans.")

    plan = None
    found: dict = {}
    if ctx.hunt_mode in RECON_MODES:
        location = _corpus_location(ctx)
        ctx.cve_corpus = cve_corpus.language_dirs(location)
        found = cve_corpus.discover(ctx.source_repo)
        missing = [] if "any" in ctx.cve_corpus else [
            lang for lang in found if lang not in ctx.cve_corpus]
        can_build = args.allow_egress and not args.no_cve_build
        plan = capabilities.CorpusPlan(
            location=location, languages=sorted(found), existing=dict(ctx.cve_corpus),
            to_build=missing if can_build else [], build_command=_build_command(args))
    caps = capabilities.assess(ctx, offline=not args.allow_egress, corpus=plan)
    if args.dry_run:
        print(capabilities.report(caps))
        print()
        print("DRY RUN -- resolved context:")
        print(f"  product:      {ctx.product.product_name}")
        print(f"  source repo:  {ctx.source_repo}")
        print(f"  hunt mode:    {ctx.hunt_mode}")
        print(f"  model:        {ctx.llm.model} @ {ctx.llm.base_url}")
        print(f"  semgrep:      {ctx.semgrep_bin or 'not available'}")
        print(f"  unconstrained:{ctx.unconstrained_requested}")
        return 0

    assume_yes = args.yes or capabilities.accepted_by_env()
    if not capabilities.confirm(caps, assume_yes=assume_yes):
        print("Hunt not started.")
        return 2
    if plan and plan.to_build:
        try:
            ctx.cve_corpus.update(cve_corpus.build(
                ctx.source_repo, plan.location, product=ctx.product.product_name,
                languages=plan.to_build, found=found))
        except RuntimeError as exc:
            print(f"WARNING: could not build the CVE corpus ({exc}); recon will "
                  "derive a class-history inventory instead.")
    return Orchestrator(ctx).run()


def cmd_build_cve_corpus(args: argparse.Namespace) -> int:
    product = ProductConfig.load(args.product_config)
    source_repo = Path(args.source_repo).resolve()
    if not source_repo.is_dir():
        raise SystemExit(f"source repo not found: {source_repo}")
    export_root = Path(__file__).resolve().parent.parent
    if args.out:
        out = Path(args.out).resolve()
    elif not is_unset(product.cve_corpus_dir):
        out = Path(product.cve_corpus_dir).resolve()
    else:
        out = cve_corpus.default_root(export_root) / cve_corpus.safe_name(product.product_key)
    print(f"Building the CVE corpus for {product.product_name} in {out}")
    print("Library names and versions are sent to api.osv.dev.")
    built = cve_corpus.build(source_repo, out, product=product.product_name,
                             languages=args.language)
    return 0 if built else 1


def cmd_cache_semgrep_rules(args: argparse.Namespace) -> int:
    export_root = Path(__file__).resolve().parent.parent
    out = Path(args.out).resolve() if args.out else (
        semgrep_rules.cache_dir(export_root) or semgrep_rules.default_cache(export_root))
    env = os.environ.get("SEMGREP_RULESETS")
    rulesets = args.ruleset or (env.split() if env else list(semgrep_rules.DEFAULT_RULESETS))
    try:
        semgrep_rules.download(rulesets, out)
    except RuntimeError as exc:
        print(f"FAIL: {exc}")
        return 1
    print(f"Rules cached in {out}. Scans use them automatically from offline-bundle/;"
          " elsewhere set SEMGREP_RULES_CACHE to this folder.")
    return 0


def cmd_check_egress(args: argparse.Namespace) -> int:
    base = os.environ.get("PYSCAN_LLM_BASE_URL", LLMConfig().base_url)
    report = check_egress(base, strict=not args.report_only)
    print(report.detail)
    return 0 if report.ok else 1


def cmd_check_model(args: argparse.Namespace) -> int:
    llm = LocalLLM(LLMConfig.from_env())
    if llm.health():
        print(f"OK: model endpoint healthy at {llm.config.base_url} ({llm.config.model})")
        return 0
    print(f"FAIL: cannot reach model at {llm.config.base_url}")
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pyscan", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="run a hunt")
    r.add_argument("--product-config", required=True)
    r.add_argument("--source-repo", required=True)
    r.add_argument("--output-dir",
                   help="where to write .hunt output (default: inside the source tree). "
                        "Set this when the source is mounted read-only.")
    r.add_argument("--hunt-mode", choices=HUNT_MODES)
    r.add_argument("--optional-keywords")
    r.add_argument("--allow-egress", action="store_true",
                   help="skip the egress isolation check (local dev only)")
    r.add_argument("--dry-run", action="store_true")
    r.add_argument("--no-cve-build", action="store_true",
                   help="do not build a CVE corpus when none is found")
    r.add_argument("-y", "--yes", action="store_true",
                   help="run even if recommended tools or inputs are missing "
                        "(same as PYSCAN_ACCEPT_MISSING_TOOLS=1)")
    r.set_defaults(func=cmd_run)

    b = sub.add_parser("build-cve-corpus",
                       help="build the CVE corpus for a repository from OSV (needs internet)")
    b.add_argument("--product-config", required=True)
    b.add_argument("--source-repo", required=True)
    b.add_argument("--language", action="append", choices=sorted(cve_corpus.ECOSYSTEM),
                   help="only these languages (default: every language found)")
    b.add_argument("--out", help="output folder (default: the product's corpus folder)")
    b.set_defaults(func=cmd_build_cve_corpus)

    c = sub.add_parser("cache-semgrep-rules",
                       help="download semgrep rule sets for offline scans (needs internet)")
    c.add_argument("--ruleset", action="append",
                   help="registry rule set, e.g. p/python (default: SEMGREP_RULESETS or "
                        + " ".join(semgrep_rules.DEFAULT_RULESETS) + ")")
    c.add_argument("--out", help="cache folder (default: SEMGREP_RULES_CACHE or "
                                 "offline-bundle/semgrep-rules)")
    c.set_defaults(func=cmd_cache_semgrep_rules)

    e = sub.add_parser("check-egress", help="verify network isolation")
    e.add_argument("--report-only", action="store_true",
                   help="print the report without failing on bad egress")
    e.set_defaults(func=cmd_check_egress)

    m = sub.add_parser("check-model", help="verify the local model endpoint")
    m.set_defaults(func=cmd_check_model)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
