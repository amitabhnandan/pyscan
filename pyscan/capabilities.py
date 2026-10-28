"""Pre-run capability check.

Before a hunt starts, list the tools and inputs that make the review stronger,
say which are missing, what each gap costs, and how to close it. The run only
continues past a gap when the operator accepts it: interactively, with --yes,
or with PYSCAN_ACCEPT_MISSING_TOOLS=1 for unattended runs.
"""
from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from .config import RunContext, is_unset

# Text the product-config template ships with; still present means unedited.
_TEMPLATE_ASSET = "The most valuable compromise outcome for this product"
_TEMPLATE_ENTRY = "Network endpoint, protocol, job, listener, parser, or API entry point"


@dataclass
class Capability:
    name: str
    available: bool
    detail: str
    impact: str  # what the hunt loses without it
    fix: str  # how the operator closes the gap
    label: str = ""  # shown instead of ok/MISSING, e.g. "build"


@dataclass
class CorpusPlan:
    """What the run knows about the CVE corpus before it starts."""
    location: Path  # where this target's corpus lives (or will be built)
    languages: list[str] = field(default_factory=list)  # libraries found for
    existing: dict[str, Path] = field(default_factory=dict)
    to_build: list[str] = field(default_factory=list)
    build_command: str = ""


def _corpus_caps(plan: CorpusPlan) -> list[Capability]:
    impact = ("The CVE inventory comes from the model's general knowledge, which may "
              "be outdated or wrong, instead of advisories for the libraries in use.")
    if "any" in plan.existing:
        return [Capability("CVE corpus", True, f"staged at {plan.existing['any']}", impact, "")]
    if not plan.languages:
        return [Capability(
            "CVE corpus", bool(plan.existing),
            "no Python libraries found to build one from",
            impact, "set cve_corpus_dir to a staged corpus (see docs/offline-inputs.md)")]
    caps = []
    for lang in plan.languages:
        name = f"CVE corpus ({lang})"
        if lang in plan.existing:
            caps.append(Capability(name, True, str(plan.existing[lang]), impact, ""))
        elif lang in plan.to_build:
            caps.append(Capability(
                name, True,
                f"not found; will be built in {plan.location / lang} before recon. "
                "Library names and versions are sent to api.osv.dev",
                impact, "", label="build"))
        else:
            caps.append(Capability(
                name, False, f"not found in {plan.location}", impact,
                "build it on a machine with internet: " + plan.build_command
                + " (or rerun with --allow-egress to build it now)"))
    return caps


def assess(ctx: RunContext, *, offline: bool, corpus: CorpusPlan | None = None) -> list[Capability]:
    p = ctx.product
    caps = [
        Capability(
            "semgrep",
            bool(ctx.semgrep_bin),
            ctx.semgrep_bin or "not found on PATH or in SEMGREP_BIN",
            "No rule-based sweep of the whole repo; the model only reviews code "
            "it chooses to open within its tool-call budget.",
            "brew install semgrep (or set SEMGREP_BIN to the binary)",
        ),
    ]
    if ctx.semgrep_bin and offline:
        from . import semgrep_rules
        _, missing = semgrep_rules.resolve(ctx.semgrep_rulesets, ctx.semgrep_rules_cache)
        caps.append(Capability(
            "semgrep rules (offline cache)",
            not missing,
            (f"{len(ctx.semgrep_rulesets)} rule set(s) cached in {ctx.semgrep_rules_cache}"
             if not missing else f"not cached: {', '.join(missing)}"
             + (f" (cache: {ctx.semgrep_rules_cache})" if ctx.semgrep_rules_cache
                else " (no cache folder)")),
            "With no internet, semgrep cannot download registry rule sets, so "
            "the uncached ones are skipped.",
            "on a machine with internet: python3 -m pyscan cache-semgrep-rules",
        ))
    rg = shutil.which("rg")
    caps.append(Capability(
        "ripgrep",
        bool(rg),
        rg or "not found; falling back to grep",
        "Searches are slower on large repos.",
        "brew install ripgrep",
    ))
    if corpus is not None:
        caps.extend(_corpus_caps(corpus))
    threat = _existing(p.threat_model_doc)
    caps.append(Capability(
        "threat model",
        bool(threat),
        threat or "threat_model_doc is 'not available'",
        "Recon cannot weight the trust boundaries and exposed surfaces your "
        "team already knows about.",
        "set threat_model_doc to a readable threat model in the product config",
    ))
    placeholders = []
    if not p.highest_value_asset or p.highest_value_asset.strip() == _TEMPLATE_ASSET:
        placeholders.append("highest_value_asset")
    if not p.known_entry_points or any(e.strip() == _TEMPLATE_ENTRY for e in p.known_entry_points):
        placeholders.append("known_entry_points")
    caps.append(Capability(
        "product context",
        not placeholders,
        "filled in" if not placeholders else "template text in " + ", ".join(placeholders),
        "The hunt has no stated crown jewels or entry points to prioritise.",
        "fill them in from the template in docs/product-context.md",
    ))
    from . import git_history
    git = git_history.available(ctx.source_repo)
    caps.append(Capability(
        "git history (optional)",
        True,
        "present; recon will summarise it into .hunt/git-history.md" if git
        else "no .git folder (or no git binary); history-based prioritisation is skipped",
        "", "",
        label="ok" if git else "skip",
    ))
    return caps


def _existing(value: str) -> str:
    return value if not is_unset(value) and Path(value).exists() else ""


def report(caps: list[Capability]) -> str:
    lines = ["Capability check -- tools and inputs that improve the review:"]
    for c in caps:
        lines.append(f"  [{c.label or ('ok' if c.available else 'MISSING')}] {c.name}: {c.detail}")
    missing = [c for c in caps if not c.available]
    if missing:
        lines.append("")
        lines.append("Missing, and what it costs:")
        for c in missing:
            lines.append(f"  - {c.name}: {c.impact}")
            lines.append(f"      fix: {c.fix}")
    return "\n".join(lines)


def accepted_by_env() -> bool:
    return os.environ.get("PYSCAN_ACCEPT_MISSING_TOOLS", "").strip().lower() in (
        "1", "true", "yes",
    )


def confirm(
    caps: list[Capability],
    *,
    assume_yes: bool,
    stdin: TextIO = sys.stdin,
    out: TextIO = sys.stdout,
) -> bool:
    """Print the report; True when the run may go ahead."""
    print(report(caps), file=out)
    missing = [c.name for c in caps if not c.available]
    if not missing:
        return True
    if assume_yes:
        print(f"\nContinuing without: {', '.join(missing)} (accepted up front).", file=out)
        return True
    if not stdin.isatty():
        print(
            "\nNot starting: the items above are missing and there is no terminal "
            "to confirm. Fix them, or rerun with --yes (or "
            "PYSCAN_ACCEPT_MISSING_TOOLS=1) to run without them.",
            file=out,
        )
        return False
    print(f"\nRun without {', '.join(missing)}? [y/N] ", end="", file=out, flush=True)
    answer = stdin.readline().strip().lower()
    return answer in ("y", "yes")
