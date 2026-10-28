"""Optional git history summary for recon and the hunt.

The model has no git tool, so when the target is a git checkout pyscan
itself runs a few read-only `git log` queries at the start of recon and
writes .hunt/git-history.md:

  - files changed most often recently (least-reviewed, most-churned code)
  - files added recently (new attack surface)
  - commits whose messages suggest security fixes (variant-hunting leads)
  - reverts (unstable areas)

recon-test-gap and the hunt read it when it exists. Without a .git folder
or a git binary the step is skipped and nothing else changes.

The target is untrusted, so git runs with the system and global config
ignored and with the repo settings that can run commands (fsmonitor,
hooks, pager, external diff) overridden; only log metadata is read.
"""
from __future__ import annotations

import collections
import datetime as _dt
import os
import re
import shutil
import subprocess
from pathlib import Path

SINCE = "18 months ago"
TOP = 40
# Matched against commit subjects only; bodies mention these words too often.
SECURITY_SUBJECT = re.compile(
    r"\b(secur\w*|vulnerab\w*|cve-\d+|cwe-\d+|xss|csrf|ssrf|xxe|inject\w*|"
    r"travers\w*|sanitiz\w*|escap\w*|authenticat\w*|authoriz\w*|permission\w*|"
    r"privilege\w*|overflow|exploit\w*|harden\w*|unsafe|deserializ\w*|redos|"
    r"denial of service|leak\w*|secret\w*|password\w*|bypass\w*)\b",
    re.I,
)
TEST_PATH = re.compile(r"(^|/)(tests?|testing|__tests__|spec)(/|$)|(^|/)test_[^/]*$|_test\.[a-z]+$")

# Python source is the only code pyscan reviews; other files are left out.
RELEVANT_SUFFIXES = {".py", ".pyi"}

_SAFE_CONFIG = [
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.pager=cat",
    "-c", "diff.external=",
    "-c", "log.showSignature=false",
]


def available(repo: Path) -> bool:
    return (repo / ".git").exists() and shutil.which("git") is not None


def _git(repo: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    proc = subprocess.run(
        ["git", "--no-pager", *_SAFE_CONFIG, "-C", str(repo), *args],
        capture_output=True, text=True, timeout=120, env=env, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip()[:300] or f"git exited {proc.returncode}")
    return proc.stdout


def _relevant(path: str) -> bool:
    p = Path(path)
    return not TEST_PATH.search(path) and p.suffix.lower() in RELEVANT_SUFFIXES


def summarize(repo: Path, out: Path, since: str = SINCE) -> bool:
    """Write the summary to `out`. False (and nothing written) when the repo
    has no usable history."""
    if not available(repo):
        return False
    try:
        changed = _git(repo, "log", f"--since={since}", "--no-merges",
                       "--name-only", "--pretty=format:")
        added = _git(repo, "log", f"--since={since}", "--no-merges", "--diff-filter=A",
                     "--name-only", "--pretty=format:")
        history = _git(repo, "log", f"--since={since}", "--no-merges", "--date=short",
                       "--pretty=format:@@%h|%ad|%s", "--name-only")
        reverts = _git(repo, "log", f"--since={since}", "-i", "--grep=^revert",
                       "--date=short", "--pretty=format:%h|%ad|%s")
        total = _git(repo, "rev-list", "--count", f"--since={since}", "HEAD").strip()
        shallow = _git(repo, "rev-parse", "--is-shallow-repository").strip() == "true"
    except (RuntimeError, OSError, subprocess.TimeoutExpired):
        return False

    churn = collections.Counter(p for p in changed.splitlines() if p.strip())
    new_files = [p for p in dict.fromkeys(added.splitlines()) if p.strip()]
    commits = []
    for block in history.split("@@")[1:]:
        lines = [l for l in block.splitlines() if l.strip()]
        sha, date, subject = (lines[0].split("|", 2) + ["", ""])[:3]
        if SECURITY_SUBJECT.search(subject):
            commits.append((sha, date, subject, lines[1:]))

    def files(paths, limit=TOP):
        source = [p for p in paths if _relevant(p)]
        return source[:limit]

    lines = [
        "# Git history summary",
        f"Generated {_dt.date.today().isoformat()} from `git log --since=\"{since}\"`: "
        f"{total} commits.{' Shallow clone: older history is missing.' if shallow else ''}",
        "",
        "Use this to choose where to read first. It is prioritisation evidence,",
        "not proof of a vulnerability. Lists cover code and configuration files;",
        "tests and docs are left out.",
        "",
        f"## Most frequently changed files (top {TOP})",
        "Heavily changed code has had the least time to settle and be reviewed.",
        "| File | Commits |",
        "|------|--------:|",
        *[f"| {p} | {n} |" for p, n in churn.most_common() if _relevant(p)][:TOP],
        "",
        f"## Recently added files (top {TOP})",
        "New files are new attack surface that may lack tests and review.",
        *([f"- {p}" for p in files(new_files)] or ["none"]),
        "",
        f"## Commits that look like security fixes ({len(commits)})",
        "Matched on words in the commit subject. A fix in one place often has an",
        "unfixed sibling: check similar code near these files for the same flaw.",
    ]
    if not commits:
        lines.append("none")
    for sha, date, subject, paths in commits[:TOP]:
        touched = files(paths, 8)
        lines.append(f"- {sha} {date} {subject}")
        if touched:
            lines.append("  files: " + ", ".join(touched))
    lines += ["", "## Reverts"]
    lines += [f"- {r.replace('|', ' ', 2)}" for r in reverts.splitlines()[:20]] or ["none"]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True
