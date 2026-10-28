"""Whole-repository semgrep sweep.

During recon pyscan runs semgrep itself over every configured source root
(not only where a role decides to call it), numbers the matches by severity,
and writes:

  .hunt/semgrep-findings.md                 readable list, S-001, S-002, ...
  .hunt/work/semgrep/full-sweep-matches.json the same list for batching

hunt-semgrep-triage then reviews the matches in batches.
"""
from __future__ import annotations

import collections
import json
from pathlib import Path
from typing import Callable

from .config import RunContext
from .tools import ToolContext, ToolError, t_run_semgrep

SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}
MATCHES_FILE = "work/semgrep/full-sweep-matches.json"


def _rule_id(check_id: str) -> str:
    # Rules loaded from local files get the file's path prefixed to their id.
    return check_id.split(".semgrep-rules.", 1)[-1]


def _code(repo: Path, rel: str, start: int, end: int) -> str:
    """Up to three lines of the matched code, joined, so a match that starts
    on a bare bracket still shows something useful."""
    try:
        text = (repo / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if not 0 < start <= len(text):
        return ""
    lines = [l.strip() for l in text[start - 1:min(max(end, start), start + 2)]]
    return " ".join(l for l in lines if l)[:200]


def run(ctx: RunContext, log: Callable[[str], None]) -> list[dict]:
    """Run the sweep; returns the numbered matches ([] if skipped or none)."""
    if not ctx.semgrep_bin:
        log("semgrep sweep skipped: semgrep not available")
        return []
    roots = [r for r in ctx.product.source_roots if (ctx.source_repo / r).exists()]
    if not roots:
        log("semgrep sweep skipped: no configured source roots exist")
        return []
    tool_ctx = ToolContext(
        source_repo=ctx.source_repo, hunt_dir=ctx.hunt_dir,
        semgrep_bin=ctx.semgrep_bin, semgrep_rulesets=ctx.semgrep_rulesets,
        semgrep_rules_cache=ctx.semgrep_rules_cache, offline=ctx.offline,
    )
    log(f"semgrep sweep: {len(roots)} source root(s)")
    try:
        t_run_semgrep(tool_ctx, {"roots": roots, "shard_name": "full-sweep"})
    except ToolError as exc:
        log(f"semgrep sweep failed: {exc}")
        return []
    raw = json.loads((ctx.hunt_dir / "work" / "semgrep" / "full-sweep.json").read_text(encoding="utf-8"))
    repo_prefix = str(ctx.source_repo) + "/"
    matches = []
    for r in raw.get("results", []):
        extra = r.get("extra", {})
        path = str(r.get("path", "")).replace(repo_prefix, "", 1)
        line = int(r.get("start", {}).get("line") or 0)
        end = int(r.get("end", {}).get("line") or line)
        matches.append({
            "rule": _rule_id(str(r.get("check_id", ""))),
            "severity": str(extra.get("severity", "INFO")).upper(),
            "path": path,
            "line": line,
            "message": " ".join(str(extra.get("message", "")).split())[:300],
            "code": _code(ctx.source_repo, path, line, end),
            "cwe": (extra.get("metadata") or {}).get("cwe") or [],
        })
    matches.sort(key=lambda m: (SEVERITY_ORDER.get(m["severity"], 3), m["path"], m["line"]))
    for i, m in enumerate(matches, 1):
        m["id"] = f"S-{i:03d}"
    write(ctx.hunt_dir, matches, roots)
    log(f"semgrep sweep: {len(matches)} match(es) -> .hunt/semgrep-findings.md")
    return matches


def write(hunt_dir: Path, matches: list[dict], roots: list[str]) -> None:
    (hunt_dir / MATCHES_FILE).parent.mkdir(parents=True, exist_ok=True)
    (hunt_dir / MATCHES_FILE).write_text(json.dumps(matches, indent=1), encoding="utf-8")
    by_sev = collections.Counter(m["severity"] for m in matches)
    by_rule = collections.Counter(m["rule"] for m in matches)
    lines = [
        "# Semgrep findings (whole-repository sweep)",
        f"Roots: {', '.join(roots)}",
        f"Matches: {len(matches)} ("
        + ", ".join(f"{s} {by_sev[s]}" for s in sorted(by_sev, key=lambda s: SEVERITY_ORDER.get(s, 3)))
        + ")",
        "",
        "These are rule matches, not findings. hunt-semgrep-triage reviews them.",
        "",
        "## Matches by rule",
        "| Rule | Count |",
        "|------|------:|",
        *[f"| {rule} | {n} |" for rule, n in by_rule.most_common()],
        "",
        "## Matches (most severe first)",
    ]
    for m in matches:
        cwe = "; ".join(m["cwe"]) if isinstance(m["cwe"], list) else str(m["cwe"])
        lines.append(f"### {m['id']} [{m['severity']}] {m['rule']}")
        lines.append(f"- Location: {m['path']}:{m['line']}")
        if m["code"]:
            lines.append(f"- Code: `{m['code']}`")
        lines.append(f"- Message: {m['message']}")
        if cwe:
            lines.append(f"- CWE: {cwe}")
    (hunt_dir / "semgrep-findings.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def load(hunt_dir: Path) -> list[dict]:
    path = hunt_dir / MATCHES_FILE
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
