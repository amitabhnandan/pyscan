"""Sandboxed tools exposed to the local model.

The model gets no shell and no `danger-full-access`. Each role gets a small,
fixed, read-biased tool set, and every
path is confined to the source repo or the .hunt/ output tree. The only writer
tool is write_hunt_file, and it can only write under .hunt/.

This matters because a local model is prone to wander, and the whole point of
the sandbox is that a scan cannot touch anything outside the tree it was
pointed at.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import semgrep_rules


class ToolError(Exception):
    """Returned to the model as a tool result; never crashes the run."""


MAX_READ_BYTES = 200_000
MAX_SEARCH_MATCHES = 400
# Stands in for file content the agent drops from older write calls. Models
# copy it as if it were content, so the write tool refuses it.
COMPACTED_WRITE_MARKER = "content omitted from history"
# Dependency and build directories that would drown real source hits; the
# target may not be a git repo, so .gitignore cannot be relied on to skip them.
SEARCH_EXCLUDE_DIRS = (
    ".git", ".venv", "venv", "env", "site-packages", "node_modules",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", "build", "dist",
    ".idea",
)
MAX_TOOL_RESULT_CHARS = 24_000
# pyscan reviews Python only: source searches and semgrep are limited to these.
SOURCE_GLOBS = ("*.py", "*.pyi")


@dataclass
class ToolContext:
    source_repo: Path
    hunt_dir: Path
    semgrep_bin: str | None
    semgrep_rulesets: list[str]
    semgrep_rules_cache: Path | None = None
    offline: bool = False
    # Extra read-only roots (e.g. an offline CVE corpus).
    extra_read_roots: list[Path] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.source_repo = self.source_repo.resolve()
        self.hunt_dir = self.hunt_dir.resolve()
        self.extra_read_roots = [p.resolve() for p in (self.extra_read_roots or [])]

    def read_roots(self) -> list[Path]:
        return [self.source_repo, self.hunt_dir, *self.extra_read_roots]

    def in_source(self, path: Path) -> bool:
        """True for paths in the source tree, not in .hunt/ or an extra root
        (an output dir or corpus may sit inside the source tree)."""
        for root in [self.hunt_dir, *self.extra_read_roots]:
            try:
                path.relative_to(root)
                return False
            except ValueError:
                pass
        try:
            path.relative_to(self.source_repo)
            return True
        except ValueError:
            return False


def _norm_hunt(ctx: ToolContext, raw: str) -> Path | None:
    """Map a '.hunt/...' or 'hunt/...' path to the real output dir, which may
    live outside the (read-only) source tree. Returns None if not a hunt path."""
    s = str(raw).replace("\\", "/")
    for prefix in (".hunt/", "hunt/"):
        if s.startswith(prefix):
            return ctx.hunt_dir / s[len(prefix):]
    if s in (".hunt", "hunt"):
        return ctx.hunt_dir
    return None


def _resolve_within(ctx: ToolContext, raw: str, roots: list[Path]) -> Path:
    """Resolve raw and confirm it stays inside one of roots. '.hunt/...' paths
    are mapped to the output dir (which may be outside source). Blocks traversal
    and symlink escape."""
    if raw is None or str(raw).strip() == "":
        raise ToolError("path is required")
    hunt_mapped = _norm_hunt(ctx, raw)
    if hunt_mapped is not None:
        candidate = hunt_mapped
    else:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = ctx.source_repo / candidate
    try:
        resolved = candidate.resolve()
    except (OSError, RuntimeError) as e:
        raise ToolError(f"cannot resolve path: {e}") from e
    for root in roots:
        try:
            resolved.relative_to(root)
            return resolved
        except ValueError:
            continue
    raise ToolError(
        f"path escapes the allowed roots: {raw} "
        f"(allowed: {', '.join(str(r) for r in roots)})"
    )


def _rel(ctx: ToolContext, p: Path) -> str:
    try:
        return str(p.relative_to(ctx.source_repo))
    except ValueError:
        return str(p)


def _truncate(text: str, limit: int = MAX_TOOL_RESULT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, {len(text) - limit} more chars]"


# -- tool implementations ---------------------------------------------------


def t_list_dir(ctx: ToolContext, args: dict[str, Any]) -> str:
    target = _resolve_within(ctx, args.get("path", "."), ctx.read_roots())
    if not target.exists():
        raise ToolError(f"no such directory: {args.get('path')}")
    if not target.is_dir():
        raise ToolError(f"not a directory: {args.get('path')}")
    entries = []
    for child in sorted(target.iterdir()):
        kind = "dir" if child.is_dir() else "file"
        size = child.stat().st_size if child.is_file() else ""
        entries.append(f"{kind}\t{size}\t{_rel(ctx, child)}")
    return _truncate("\n".join(entries) or "(empty)")


def t_read_file(ctx: ToolContext, args: dict[str, Any]) -> str:
    target = _resolve_within(ctx, args.get("path", ""), ctx.read_roots())
    if not target.exists() or not target.is_file():
        raise ToolError(f"no such file: {args.get('path')}")
    start = int(args.get("start_line", 1) or 1)
    max_lines = int(args.get("max_lines", 400) or 400)
    raw = target.read_bytes()[:MAX_READ_BYTES]
    text = raw.decode("utf-8", "replace")
    lines = text.splitlines()
    chunk = lines[max(start - 1, 0) : max(start - 1, 0) + max_lines]
    numbered = "\n".join(
        f"{i}\t{line}" for i, line in enumerate(chunk, start=max(start, 1))
    )
    header = f"# {_rel(ctx, target)} lines {start}-{start + len(chunk) - 1} of {len(lines)}\n"
    return _truncate(header + numbered)


def t_search(ctx: ToolContext, args: dict[str, Any]) -> str:
    pattern = args.get("pattern")
    if not pattern:
        raise ToolError("pattern is required")
    search_root = _resolve_within(ctx, args.get("path", "."), ctx.read_roots())
    globs = args.get("globs") or []
    if isinstance(globs, str):
        globs = [globs]
    if ctx.in_source(search_root):
        # Only Python source is searched; .hunt/ and corpus files stay searchable.
        globs = [g for g in globs if g.endswith((".py", ".pyi"))] or list(SOURCE_GLOBS)
    # Patterns are extended regex. Models often write grep-BRE alternation
    # (a\|b); treat it as a|b so either style works with rg and grep -E.
    pattern = pattern.replace("\\\\|", "|").replace("\\|", "|")
    ignore_case = bool(args.get("ignore_case"))
    rg = shutil.which("rg")
    if rg:
        cmd = [rg, "--line-number", "--no-heading", "--color", "never",
               "--max-count", "20", "-e", pattern]
        if ignore_case:
            cmd.append("--ignore-case")
        for g in globs:
            cmd += ["--glob", g]
        for d in SEARCH_EXCLUDE_DIRS:
            cmd += ["--glob", f"!{d}/"]
        cmd.append(str(search_root))
        out = _run(cmd, cwd=ctx.source_repo, timeout=120, allow_exit=(0, 1))
    else:
        # grep fallback keeps the framework working without ripgrep installed.
        cmd = ["grep", "-rnE", "--color=never"]
        if ignore_case:
            cmd.append("-i")
        for g in globs:
            cmd += ["--include", g]
        for d in SEARCH_EXCLUDE_DIRS:
            cmd += ["--exclude-dir", d]
        cmd += ["-e", pattern, str(search_root)]
        out = _run(cmd, cwd=ctx.source_repo, timeout=120, allow_exit=(0, 1))
    lines = out.splitlines()
    if len(lines) > MAX_SEARCH_MATCHES:
        lines = lines[:MAX_SEARCH_MATCHES] + [
            f"... [{len(lines) - MAX_SEARCH_MATCHES} more matches; narrow the pattern]"
        ]
    # Rewrite absolute paths to repo-relative for cleaner model context.
    rel_lines = [ln.replace(str(ctx.source_repo) + os.sep, "") for ln in lines]
    return _truncate("\n".join(rel_lines) or "(no matches)")


def t_run_semgrep(ctx: ToolContext, args: dict[str, Any]) -> str:
    if not ctx.semgrep_bin:
        raise ToolError(
            "semgrep is not available in this sandbox; rely on search and "
            "read_file instead and note degraded coverage"
        )
    roots = args.get("roots") or ["."]
    if isinstance(roots, str):
        roots = [roots]
    resolved_roots = [_resolve_within(ctx, r, [ctx.source_repo]) for r in roots]
    shard = args.get("shard_name", "shard").replace("/", "_")
    out_dir = ctx.hunt_dir / "work" / "semgrep"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{shard}.json"
    configs, missing = semgrep_rules.resolve(ctx.semgrep_rulesets, ctx.semgrep_rules_cache)
    note = ""
    if ctx.offline and missing:
        # Offline, a registry name would make semgrep try to download it.
        configs = [c for c, rs in zip(configs, ctx.semgrep_rulesets) if rs not in missing]
        if not configs:
            raise ToolError(
                "semgrep rules are not cached for offline use (missing: "
                f"{', '.join(missing)}); rely on search and read_file and note "
                "degraded coverage"
            )
        note = f" (skipped uncached rule sets: {', '.join(missing)})"
    cmd = [ctx.semgrep_bin, "scan", "--metrics=off", "--disable-version-check",
           "--quiet", "--json", "--output", str(out_file)]
    for config in configs:
        cmd += ["--config", config]
    for g in SOURCE_GLOBS:
        cmd += ["--include", g]
    cmd += [str(r) for r in resolved_roots]
    try:
        _run(cmd, cwd=ctx.source_repo, timeout=1500, allow_exit=(0, 1),
             env=semgrep_rules.OFFLINE_ENV if ctx.offline else None)
    except ToolError as e:
        # With --json --output, semgrep reports its errors in the JSON file.
        raise ToolError(f"{e}{_semgrep_errors(out_file)}") from e
    try:
        parsed = json.loads(out_file.read_text(encoding="utf-8"))
        results = parsed.get("results", [])
        summary = [f"semgrep wrote {len(results)} results to {_rel(ctx, out_file)}{note}"]
        repo_prefix = str(ctx.source_repo) + os.sep
        for r in results[:60]:
            # Rules loaded from local files get the file's path prefixed to
            # their id; keep only the registry id.
            check_id = str(r.get("check_id", "")).split(".semgrep-rules.", 1)[-1]
            path = str(r.get("path", "")).replace(repo_prefix, "", 1)
            summary.append(f"{path}:{r.get('start', {}).get('line')} {check_id}")
        if len(results) > 60:
            summary.append(f"... [{len(results) - 60} more in the JSON file]")
        return _truncate("\n".join(summary))
    except (json.JSONDecodeError, OSError) as e:
        raise ToolError(f"semgrep ran but JSON was unreadable: {e}") from e


def _semgrep_errors(out_file: Path) -> str:
    try:
        errors = json.loads(out_file.read_text(encoding="utf-8")).get("errors", [])
    except (OSError, json.JSONDecodeError):
        return ""
    return "".join(f"\n  semgrep: {str(e.get('message', e))[:300]}" for e in errors[:3])


def t_write_hunt_file(ctx: ToolContext, args: dict[str, Any]) -> str:
    """The single writer tool. Confined to .hunt/ and ASCII-cleaned."""
    rel = args.get("path", "")
    content = args.get("content", "")
    if not rel:
        raise ToolError("path is required")
    target = _resolve_within(ctx, rel, [ctx.hunt_dir])
    if content is None:
        raise ToolError("content is required")
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = args.get("mode", "overwrite")
    text = str(content)
    if COMPACTED_WRITE_MARKER in text and len(text) < 500:
        raise ToolError(
            "that is a history placeholder, not file content. Nothing was "
            f"written. read_file {rel} to see the current version, then write "
            "the complete updated document."
        )
    if (mode != "append" and target.exists() and len(text) < 200
            and target.stat().st_size > 2000):
        raise ToolError(
            f"refusing to replace {rel} ({target.stat().st_size} chars) with "
            f"{len(text)} chars. Write the complete document, or use "
            "mode='append' to add to it."
        )
    if mode == "append" and target.exists():
        existing = target.read_text(encoding="utf-8")
        text = existing + ("\n" if not existing.endswith("\n") else "") + text
    target.write_text(text, encoding="utf-8")
    return f"wrote {len(text)} chars to {_rel(ctx, target)}"


def _run(
    cmd: list[str],
    cwd: Path,
    timeout: int,
    allow_exit: tuple[int, ...] = (0,),
    env: dict[str, str] | None = None,
) -> str:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            env={**os.environ, **env} if env else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as e:
        raise ToolError(f"required tool not installed: {cmd[0]}") from e
    except subprocess.TimeoutExpired as e:
        raise ToolError(
            f"command timed out after {timeout}s: {shlex.join(cmd[:3])}..."
        ) from e
    if proc.returncode not in allow_exit:
        raise ToolError(
            f"command exited {proc.returncode}: {shlex.join(cmd[:4])}\n"
            f"{(proc.stderr or '')[:500]}"
        )
    return proc.stdout


# -- registry ---------------------------------------------------------------

# OpenAI tool schema for each tool. The orchestrator hands each role a subset.
TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "list_dir": {
        "type": "function",
        "function": {
            "name": "list_dir",
            "description": "List files and subdirectories under a path in the source repo or .hunt tree.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "Relative or absolute path within an allowed root."}},
                "required": ["path"],
            },
        },
    },
    "read_file": {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a slice of a text file with line numbers. Use start_line/max_lines to page through large files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "start_line": {"type": "integer", "description": "1-based first line (default 1)."},
                    "max_lines": {"type": "integer", "description": "Max lines to return (default 400)."},
                },
                "required": ["path"],
            },
        },
    },
    "search": {
        "type": "function",
        "function": {
            "name": "search",
            "description": "Extended-regex search across the source repo (use | for alternation). Returns file:line matches. Source-tree searches cover Python files only (*.py, *.pyi); globs can narrow further, e.g. 'app/**/*.py'. Files under .hunt/ and the CVE corpus are searched as-is. Dependency dirs such as .venv and node_modules are skipped.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "path": {"type": "string", "description": "Subtree to search (default repo root)."},
                    "globs": {"type": "array", "items": {"type": "string"}},
                    "ignore_case": {"type": "boolean", "description": "Match case-insensitively (default false)."},
                },
                "required": ["pattern"],
            },
        },
    },
    "run_semgrep": {
        "type": "function",
        "function": {
            "name": "run_semgrep",
            "description": "Run the offline semgrep binary over the Python files in the given source roots with the configured rulesets, writing JSON under .hunt/work/semgrep/. Shard large trees by root.",
            "parameters": {
                "type": "object",
                "properties": {
                    "roots": {"type": "array", "items": {"type": "string"}},
                    "shard_name": {"type": "string", "description": "Stable name for this shard's JSON output."},
                },
                "required": ["roots", "shard_name"],
            },
        },
    },
    "write_hunt_file": {
        "type": "function",
        "function": {
            "name": "write_hunt_file",
            "description": "Write a result file under the .hunt/ output tree. This is the only way to persist output. mode=overwrite|append.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path under .hunt/, e.g. '.hunt/attack-surface.md'."},
                    "content": {"type": "string"},
                    "mode": {"type": "string", "enum": ["overwrite", "append"]},
                },
                "required": ["path", "content"],
            },
        },
    },
}

TOOL_IMPLS: dict[str, Callable[[ToolContext, dict[str, Any]], str]] = {
    "list_dir": t_list_dir,
    "read_file": t_read_file,
    "search": t_search,
    "run_semgrep": t_run_semgrep,
    "write_hunt_file": t_write_hunt_file,
}


def schemas_for(names: list[str]) -> list[dict[str, Any]]:
    return [TOOL_SCHEMAS[n] for n in names if n in TOOL_SCHEMAS]
