"""Finding records: ids, the CSV, duplicates, and the executive summary.

The filer role writes one evidence pack per finding, ending in a
'## Summary Fields' block. Everything with a fixed format is done here in
code, not by the model: the SECSCAN-XXXX id, the CSV row (via the csv
module), duplicate detection, and the executive summary.
"""
from __future__ import annotations

import collections
import csv
import datetime as _dt
import re
import shutil
from pathlib import Path

ID_PREFIX = "SECSCAN"
CSV_NAME = "findings-summary.csv"
HEADER = [
    "finding_id", "title", "cwe_id", "cwe_name", "cvss_score", "cvss_severity",
    "cvss_vector", "config_dependency", "evidence_status", "entry_point_file",
    "entry_point_line", "sink_file", "sink_line", "module", "auth_required",
    "summary", "recommended_fix", "owner_area", "filed_date", "iteration",
    "hunt_track", "persona", "chain_hops",
]
# Filled in by the orchestrator, not the filer.
ORCHESTRATOR_FIELDS = {"finding_id", "filed_date", "iteration", "hunt_track", "persona"}
FILER_FIELDS = [f for f in HEADER if f not in ORCHESTRATOR_FIELDS]
_ID = re.compile(rf"{ID_PREFIX}-(\d{{4,}})")
_SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def read_rows(hunt_dir: Path) -> list[dict]:
    path = hunt_dir / CSV_NAME
    if not path.is_file():
        return []
    try:
        with path.open(newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))
    except (csv.Error, OSError):
        return []


def next_id(hunt_dir: Path) -> str:
    """One past the highest SECSCAN number in the CSV or findings folder."""
    used = [int(m.group(1)) for r in read_rows(hunt_dir)
            for m in [_ID.match(r.get("finding_id", ""))] if m]
    used += [int(m.group(1)) for p in (hunt_dir / "findings").glob(f"{ID_PREFIX}-*.md")
             for m in [_ID.match(p.name)] if m]
    return f"{ID_PREFIX}-{max(used, default=0) + 1:04d}"


def parse_summary_fields(text: str) -> dict[str, str]:
    """`key: value` lines under '## Summary Fields' in an evidence pack."""
    start = text.find("## Summary Fields")
    if start == -1:
        return {}
    fields = {}
    for line in text[start:].splitlines()[1:]:
        if line.startswith("## "):
            break
        m = re.match(r"^\s*[-*]?\s*([a-z_]+)\s*:\s*(.*)$", line)
        if m and m.group(1) in FILER_FIELDS:
            fields[m.group(1)] = " ".join(m.group(2).split())
    return fields


def parse_severity(text: str) -> dict[str, str]:
    """The verifier's 'Severity:' line -> cvss_score/cvss_severity/cvss_vector."""
    m = re.search(r"^\s*Severity:\s*(.+)$", text, re.M)
    if not m:
        return {}
    line = m.group(1)
    out = {}
    score = re.search(r"\b(10(?:\.0)?|\d\.\d)\b", line)
    label = re.search(r"\b(Critical|High|Medium|Low)\b", line, re.I)
    vector = re.search(r"CVSS:3\.[01]/[A-Z:/]+", line)
    if score:
        out["cvss_score"] = score.group(1)
    if label:
        out["cvss_severity"] = label.group(1).capitalize()
    if vector:
        out["cvss_vector"] = vector.group(0)
    return out


def _norm(path: str) -> str:
    return path.strip().strip("`").lstrip("./")


def duplicate_of(rows: list[dict], sink_file: str, sink_line: str, cwe_id: str) -> str:
    """Id of an already-filed finding with the same sink and CWE (or the same
    sink, when the CWE is not known yet), or ''."""
    sink, line, cwe = _norm(sink_file), str(sink_line).strip(), cwe_id.strip().upper()
    if not sink:
        return ""
    for r in rows:
        if (_norm(r.get("sink_file", "")), str(r.get("sink_line", "")).strip()) != (sink, line):
            continue
        # Same sink: a duplicate unless both name different CWEs.
        if not cwe or r.get("cwe_id", "").strip().upper() in ("", cwe):
            return r.get("finding_id", "?")
    return ""


def append_row(hunt_dir: Path, row: dict[str, str]) -> None:
    path = hunt_dir / CSV_NAME
    new = not path.is_file()
    with path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HEADER, extrasaction="ignore")
        if new:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in HEADER})


def set_aside(paths: list[Path], hunt_dir: Path, why: str) -> list[Path]:
    """Move files out of findings/ (strays, duplicates) without deleting them."""
    dest = hunt_dir / "work" / "discarded-filings"
    dest.mkdir(parents=True, exist_ok=True)
    moved = []
    for p in paths:
        target = dest / p.name
        shutil.move(str(p), str(target))
        (dest / (p.name + ".why.txt")).write_text(why + "\n", encoding="utf-8")
        moved.append(target)
    return moved


def write_executive_summary(hunt_dir: Path, product: str, mode: str) -> None:
    rows = read_rows(hunt_dir)
    by_sev = collections.Counter(r.get("cvss_severity", "?") for r in rows)
    by_cwe = collections.Counter(
        f"{r.get('cwe_id', '?')} {r.get('cwe_name', '')}".strip() for r in rows)
    ordered = sorted(rows, key=lambda r: (_SEVERITY_RANK.get(r.get("cvss_severity", ""), 4),
                                          -_float(r.get("cvss_score"))))
    lines = [
        f"# Executive Summary -- {product}",
        f"Generated {_dt.date.today().isoformat()} by pyscan ({mode}).",
        "",
        "Every finding below was confirmed by the blue team, passed the evidence",
        "gates, and was verified independently before filing. Each still needs",
        "review by an engineer before action is taken.",
        "",
        "## Finding Counts",
        f"Total: {len(rows)}",
        *[f"- {sev}: {by_sev[sev]}" for sev in ("Critical", "High", "Medium", "Low") if by_sev[sev]],
        "",
        "## Findings",
        "| ID | Severity | CVSS | CWE | Title | Where |",
        "|----|----------|-----:|-----|-------|-------|",
        *[f"| {r.get('finding_id')} | {r.get('cvss_severity')} | {r.get('cvss_score')} "
          f"| {r.get('cwe_id')} | {r.get('title')} "
          f"| {r.get('sink_file')}:{r.get('sink_line')} |" for r in ordered],
        "",
        "## CWE Distribution",
        *([f"- {cwe}: {n}" for cwe, n in by_cwe.most_common()] or ["none"]),
        "",
        "## Recommended Immediate Actions",
        *([f"- {r.get('finding_id')}: {r.get('recommended_fix')}" for r in ordered[:5]] or ["none"]),
        "",
        "Full evidence for each finding is in findings/<ID>-*.md.",
    ]
    (hunt_dir / "executive-summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
