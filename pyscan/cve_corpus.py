"""Repository-specific CVE corpus, built from the OSV database.

recon-cve-mapper reads known vulnerabilities from a corpus on disk instead
of the model's memory. When a target has no corpus yet, pyscan builds one
for it: it finds the Python libraries the repository uses, asks
OSV (https://osv.dev) which advisories affect the versions in use, adds each
library's advisory history, and writes Markdown the mapper reads offline:

  cve-corpus/<product_key>/
    README.md
    python/
      INDEX.md                  versions in use, the advisories affecting
                                them, and where each library was found
      packages/<package>.md     one library's advisories with affected and
                                fixed versions

Libraries are found two ways, without running anything from the target:

  manifests  requirements*.txt, pyproject.toml, uv.lock, and installed
             *.dist-info in virtual environments.
  imports    a scan of the source for imported third-party modules, which
             catches libraries used without being declared. Their version is
             unknown, so they get full advisory history.

Building needs network access to api.osv.dev (package names and versions
are sent); scans read the result offline.
"""
from __future__ import annotations

import concurrent.futures
import datetime as _dt
import json
import os
import re
import sys
import sysconfig
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

OSV_API = "https://api.osv.dev/v1"
ECOSYSTEM = {"python": "PyPI"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".tox", ".mypy_cache",
             ".pytest_cache", ".idea", ".hunt"}
VENV_DIRS = {".venv", "venv", "env", "site-packages"}
DETAILS_CHARS = 1200
BATCH = 500
MAX_SOURCE_FILES = 20000

# Import names that differ from the PyPI distribution name.
PY_IMPORT_ALIASES = {
    "yaml": "pyyaml", "PIL": "pillow", "cv2": "opencv-python", "bs4": "beautifulsoup4",
    "jwt": "pyjwt", "Crypto": "pycryptodome", "Cryptodome": "pycryptodomex",
    "dateutil": "python-dateutil", "sklearn": "scikit-learn", "dotenv": "python-dotenv",
    "magic": "python-magic", "git": "gitpython", "jose": "python-jose",
    "multipart": "python-multipart", "OpenSSL": "pyopenssl", "nacl": "pynacl",
    "serial": "pyserial", "usb": "pyusb", "zmq": "pyzmq", "docx": "python-docx",
    "pptx": "python-pptx", "ldap": "python-ldap", "jinja2": "jinja2", "lxml": "lxml",
    "google": "protobuf", "attr": "attrs", "pkg_resources": "setuptools",
    "importlinter": "import-linter", "md2conf": "markdown-to-confluence",
    "key_value": "py-key-value-aio", "websocket": "websocket-client",
    "markdown_it": "markdown-it-py", "mdit_py_plugins": "mdit-py-plugins",
}

Deps = Dict[str, Optional[str]]  # package -> version (None if unknown)


@dataclass
class Libraries:
    """Libraries one language uses, with where each was found."""
    declared: Deps = field(default_factory=dict)  # named in a manifest
    resolved: Deps = field(default_factory=dict)  # exact version known
    imported: Set[str] = field(default_factory=set)  # seen in a source import
    sources: List[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.declared or self.resolved or self.imported)

    def all_names(self) -> Set[str]:
        return set(self.declared) | set(self.resolved) | self.imported


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------

def _walk(root: Path, *, include_venvs: bool = False) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and (include_venvs or d not in VENV_DIRS)
        ]
        for name in filenames:
            yield Path(dirpath) / name


def norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower().strip()


_REQ = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(==|===|>=|~=|<=|>|<|!=)?\s*([^\s;,#]*)")


def _parse_requirement(line: str) -> Optional[Tuple[str, Optional[str]]]:
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith(("-", "git+", "http:", "https:")):
        return None
    m = _REQ.match(line)
    if not m:
        return None
    name, op, version = m.group(1), m.group(2), m.group(3)
    return norm_py(name), (version if op in ("==", "===") and version else None)


def _rel(path: Path, repo: Path) -> str:
    try:
        return str(path.relative_to(repo))
    except ValueError:
        return str(path)


def python_libraries(repo: Path) -> Libraries:
    libs = Libraries()
    import_to_dist: Dict[str, str] = {}
    for path in _walk(repo):
        if re.fullmatch(r"requirements.*\.txt", path.name):
            libs.sources.append(_rel(path, repo))
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                req = _parse_requirement(line)
                if req:
                    libs.declared.setdefault(req[0], req[1])
                    if req[1]:
                        libs.resolved.setdefault(req[0], req[1])
        elif path.name == "pyproject.toml":
            text = path.read_text(encoding="utf-8", errors="replace")
            block = re.search(r"(?ms)^\s*dependencies\s*=\s*\[(.*?)\]", text)
            if block:
                libs.sources.append(_rel(path, repo))
                for item in re.findall(r"[\"']([^\"']+)[\"']", block.group(1)):
                    req = _parse_requirement(item)
                    if req:
                        libs.declared.setdefault(req[0], req[1])
        elif path.name == "uv.lock":
            libs.sources.append(_rel(path, repo))
            text = path.read_text(encoding="utf-8", errors="replace")
            for block in text.split("[[package]]")[1:]:
                name = re.search(r'(?m)^name\s*=\s*"([^"]+)"', block)
                version = re.search(r'(?m)^version\s*=\s*"([^"]+)"', block)
                if name and version:
                    libs.resolved[norm_py(name.group(1))] = version.group(1)
    # Installed environments: exact versions, and which import names each
    # distribution provides (top_level.txt).
    for path in _walk(repo, include_venvs=True):
        if path.parent.name.endswith(".dist-info") and path.name == "METADATA":
            text = path.read_text(encoding="utf-8", errors="replace")
            name = re.search(r"(?m)^Name:\s*(\S+)", text)
            version = re.search(r"(?m)^Version:\s*(\S+)", text)
            if not (name and version):
                continue
            dist = norm_py(name.group(1))
            env = _rel(path.parent.parent, repo)
            if env not in libs.sources:
                libs.sources.append(env)
            libs.resolved[dist] = version.group(1)
            top = path.parent / "top_level.txt"
            if top.is_file():
                for mod in top.read_text(encoding="utf-8", errors="replace").split():
                    import_to_dist.setdefault(mod.strip(), dist)
    for module in python_imports(repo):
        dist = import_to_dist.get(module) or PY_IMPORT_ALIASES.get(module) or norm_py(module)
        libs.imported.add(norm_py(dist))
    for name, version in list(libs.declared.items()):
        if version is None and name in libs.resolved:
            libs.declared[name] = libs.resolved[name]
    return libs


_PY_FROM = re.compile(r"[ \t]*from[ \t]+([A-Za-z_]\w*)[\w.]*[ \t]+import\b")
_PY_IMPORT = re.compile(r"[ \t]*import[ \t]+([A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?(?:[ \t]*,[ \t]*[A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?)*)[ \t]*(?:#.*)?$")
# Standard-library modules newer than the Python running pyscan may know.
_NEWER_STDLIB = {"tomllib", "zoneinfo", "graphlib", "_thread", "__main__"}


def _stdlib_modules() -> Set[str]:
    names = set(getattr(sys, "stdlib_module_names", ())) | set(sys.builtin_module_names)
    stdlib = Path(sysconfig.get_paths()["stdlib"])
    if stdlib.is_dir():
        for p in stdlib.iterdir():
            names.add(p.stem if p.suffix == ".py" else p.name)
        dynload = stdlib / "lib-dynload"  # C extension modules, e.g. fcntl
        if dynload.is_dir():
            names.update(p.name.split(".")[0] for p in dynload.iterdir())
    names.update({"__future__"} | _NEWER_STDLIB)
    return names


def python_imports(repo: Path) -> Set[str]:
    """Top-level third-party modules imported by the repo's own code."""
    files = []
    local: Set[str] = set()
    for path in _walk(repo):
        if path.suffix == ".py":
            files.append(path)
            local.add(path.stem)
            for parent in path.relative_to(repo).parents:
                if parent.name:
                    local.add(parent.name)
        if len(files) >= MAX_SOURCE_FILES:
            break
    stdlib = _stdlib_modules()
    found: Set[str] = set()
    for path in files:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = _PY_FROM.match(line)
            if m:
                names = [m.group(1)]
            else:
                m = _PY_IMPORT.match(line)
                if not m:
                    continue
                names = [part.split()[0].split(".")[0] for part in m.group(1).split(",")]
            for name in names:
                if name and name not in stdlib and name not in local and not name.startswith("_"):
                    found.add(name)
    return found


def discover(repo: Path) -> Dict[str, Libraries]:
    """Libraries per language; empty when nothing was found."""
    libs = python_libraries(repo)
    return {} if libs.empty else {"python": libs}


# ---------------------------------------------------------------------------
# OSV client
# ---------------------------------------------------------------------------

class OSV:
    def __init__(self, base: str = OSV_API):
        self.base = base

    def _request(self, path: str, body: Optional[dict] = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base + path, data=data,
            headers={"Content-Type": "application/json"} if data else {},
            method="POST" if data else "GET",
        )
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    return {}
                if attempt == 3:
                    raise RuntimeError(f"OSV request failed: {path}: {exc}") from exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt == 3:
                    raise RuntimeError(f"OSV request failed: {path}: {exc}") from exc
            time.sleep(2 ** attempt)
        return {}

    def vuln_ids(self, ecosystem: str, packages: Deps) -> Dict[str, List[str]]:
        """package -> advisory ids affecting that version (all, if None)."""
        items = list(packages.items())
        out: Dict[str, List[str]] = {}
        for i in range(0, len(items), BATCH):
            chunk = items[i:i + BATCH]
            queries = []
            for name, version in chunk:
                q: Dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}}
                if version:
                    q["version"] = version
                queries.append(q)
            results = self._request("/querybatch", {"queries": queries}).get("results", [])
            for (name, _), result in zip(chunk, results):
                out[name] = [v["id"] for v in result.get("vulns", [])]
        return out

    def details(self, ids: Iterable[str]) -> Dict[str, dict]:
        ids = sorted(set(ids))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            return dict(zip(ids, pool.map(lambda i: self._request(f"/vulns/{i}"), ids)))


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}


def _label(v: dict) -> str:
    return str((v.get("database_specific") or {}).get("severity") or "").upper()


def _rank(v: dict) -> int:
    return _SEVERITY_ORDER.get(_label(v), 0)


def _severity(v: dict) -> str:
    vectors = [s.get("score", "") for s in v.get("severity", []) if s.get("score")]
    return " ".join(x for x in (_label(v), vectors[0] if vectors else "") if x) or "unrated"


def _ranges(v: dict, ecosystem: str, package: str) -> str:
    parts = []
    for aff in v.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != ecosystem or norm_py(pkg.get("name", "")) != norm_py(package):
            continue
        for r in aff.get("ranges", []):
            introduced = fixed = last = None
            for ev in r.get("events", []):
                introduced = ev.get("introduced", introduced)
                fixed = ev.get("fixed", fixed)
                last = ev.get("last_affected", last)
            if fixed:
                parts.append(f">= {introduced or '0'}, fixed in {fixed}")
            elif last:
                parts.append(f">= {introduced or '0'}, up to {last}")
            elif introduced:
                parts.append(f">= {introduced}, no fix")
    return "; ".join(dict.fromkeys(parts)) or "see advisory"


def _cves(v: dict) -> List[str]:
    return [a for a in v.get("aliases", []) if a.startswith("CVE-")]


def _cwes(v: dict) -> List[str]:
    return list((v.get("database_specific") or {}).get("cwe_ids") or [])


def _advisory_md(v: dict, ecosystem: str, package: str, affects: bool) -> str:
    refs = [r.get("url") for r in v.get("references", []) if r.get("url")][:3]
    details = " ".join((v.get("details") or "").split())
    if len(details) > DETAILS_CHARS:
        details = details[:DETAILS_CHARS] + " ..."
    cves = _cves(v)
    lines = [
        f"### {v.get('id')}{' / ' + ', '.join(cves) if cves else ''}"
        f"{'  [AFFECTS VERSION IN USE]' if affects else ''}",
        f"- Summary: {v.get('summary') or '(none)'}",
        f"- Severity: {_severity(v)}",
        f"- CWE: {', '.join(_cwes(v)) or 'not classified'}",
        f"- Affected versions: {_ranges(v, ecosystem, package)}",
        f"- Published: {(v.get('published') or '')[:10]}",
    ]
    if details:
        lines.append(f"- Details: {details}")
    if refs:
        lines.append("- References: " + " ".join(refs))
    return "\n".join(lines)


def _dedupe(ids: Iterable[str], details: Dict[str, dict]) -> List[str]:
    """One id per vulnerability. OSV often publishes the same issue as a
    GHSA and a PYSEC record that alias each other; keep the GHSA one, which
    carries the severity label."""
    order = {"GHSA": 0, "CVE": 1}
    kept: List[str] = []
    seen: Set[str] = set()
    for vid in sorted(set(ids), key=lambda i: (order.get(i.split("-")[0], 2), i)):
        names = {vid, *details.get(vid, {}).get("aliases", [])}
        if names & seen:
            continue
        seen |= names
        kept.append(vid)
    return sorted(kept)


def safe_name(package: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", package)


def _worst(vulns: Iterable[dict]) -> str:
    worst = max((_rank(v) for v in vulns), default=0)
    return next((k for k, n in _SEVERITY_ORDER.items() if n == worst), "unrated")


def package_md(package: str, ecosystem: str, version: Optional[str],
               vulns: List[dict], affecting: Set[str]) -> str:
    vulns = sorted(vulns, key=lambda v: (v.get("id") not in affecting, -_rank(v),
                                         v.get("published", "")))
    return (
        f"# {package} ({ecosystem})\n\n"
        f"Version in use: {version or 'unknown'}. Known advisories: {len(vulns)} "
        f"({len(affecting)} affect the version in use). Worst severity: {_worst(vulns)}.\n\n"
        + "\n\n".join(_advisory_md(v, ecosystem, package, v.get("id") in affecting) for v in vulns)
        + "\n"
    )


def index_md(product: str, language: str, libs: Libraries,
             affecting: Dict[str, List[str]], history: Dict[str, List[str]],
             details: Dict[str, dict]) -> str:
    ecosystem = ECOSYSTEM[language]
    hit = {p: ids for p, ids in affecting.items() if ids}
    with_files = sorted(p for p in libs.all_names() if history.get(p) or hit.get(p))
    undeclared = sorted(libs.imported - set(libs.declared) - set(libs.resolved))

    def found_in(p: str) -> str:
        where = []
        if p in libs.declared:
            where.append("manifest")
        if p in libs.resolved and p not in libs.declared:
            where.append("lock/env")
        if p in libs.imported:
            where.append("imports")
        return "+".join(where) or "-"

    lines = [
        f"# {product} -- {ecosystem} CVE corpus",
        f"Built {_dt.date.today().isoformat()} from OSV (osv.dev) for this repository.",
        "Sources: " + (", ".join(libs.sources) if libs.sources else "source imports only"),
        "",
        "Start with the advisories affecting the versions in use, then use each",
        "package file for the vulnerability classes the library has a history of.",
        "",
        f"## Advisories affecting the versions in use ({sum(len(v) for v in hit.values())})",
    ]
    if not hit:
        lines.append("None found for the resolved versions.")
    for pkg in sorted(hit, key=lambda p: -max(_rank(details.get(i, {})) for i in hit[p])):
        lines.append(f"\n### {pkg} {libs.resolved.get(pkg, '?')} -> packages/{safe_name(pkg)}.md")
        for vid in hit[pkg]:
            v = details.get(vid, {})
            lines.append(
                f"- {vid} {' '.join(_cves(v))} [{_severity(v)}] {','.join(_cwes(v))} "
                f"-- {v.get('summary') or ''}".rstrip())
    lines += [
        "",
        f"## Libraries with advisory history ({len(with_files)})",
        "| Library | Version | Found in | Advisories | Affect version | Worst | File |",
        "|---------|---------|----------|-----------:|---------------:|-------|------|",
    ]
    for p in sorted(with_files, key=lambda p: (-len(hit.get(p, [])), p)):
        ids = set(history.get(p, [])) | set(hit.get(p, []))
        lines.append(
            f"| {p} | {libs.resolved.get(p) or libs.declared.get(p) or 'unknown'} | {found_in(p)} "
            f"| {len(ids)} | {len(hit.get(p, []))} | {_worst(details.get(i, {}) for i in ids)} "
            f"| packages/{safe_name(p)}.md |")
    lines += [
        "",
        "## Imported in code but not declared in a manifest",
        ", ".join(undeclared) if undeclared else "none",
        "",
        f"## All libraries found ({len(libs.all_names())})",
    ]
    lines += [
        f"- {p} {libs.resolved.get(p) or libs.declared.get(p) or ''} ({found_in(p)})".rstrip()
        for p in sorted(libs.all_names())
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# build / locate
# ---------------------------------------------------------------------------

def default_root(export_root: Path) -> Path:
    return export_root / "cve-corpus"


def language_dirs(corpus: Path) -> Dict[str, Path]:
    """Per-language folders of a corpus. A folder without language
    subfolders (a hand-staged corpus) is returned as 'any'."""
    if not corpus.is_dir():
        return {}
    dirs = {lang: corpus / lang for lang in ECOSYSTEM if (corpus / lang / "INDEX.md").is_file()}
    if not dirs and any(corpus.iterdir()):
        return {"any": corpus}
    return dirs


def build(repo: Path, out: Path, *, product: str,
          languages: Optional[List[str]] = None, osv: Optional[OSV] = None,
          found: Optional[Dict[str, Libraries]] = None,
          log: Callable[[str], None] = print) -> Dict[str, Path]:
    """Build the corpus for one repository; returns its language folders."""
    osv = osv or OSV()
    found = found if found is not None else discover(repo)
    if languages:
        found = {k: v for k, v in found.items() if k in languages}
    if not found:
        log("cve corpus: no Python libraries found; nothing to build")
        return {}
    out.mkdir(parents=True, exist_ok=True)
    built: Dict[str, Path] = {}
    for language, libs in found.items():
        ecosystem = ECOSYSTEM[language]
        lang_dir = out / language
        (lang_dir / "packages").mkdir(parents=True, exist_ok=True)
        log(f"cve corpus [{language}]: {len(libs.declared)} declared, {len(libs.resolved)} with "
            f"versions, {len(libs.imported)} imported, from {len(libs.sources)} source(s)")
        affecting = osv.vuln_ids(ecosystem, {p: v for p, v in libs.resolved.items() if v})
        names = (set(libs.declared) | libs.imported
                 | {p for p, ids in affecting.items() if ids})
        history = osv.vuln_ids(ecosystem, {p: None for p in sorted(names)})
        ids = {i for group in list(affecting.values()) + list(history.values()) for i in group}
        log(f"cve corpus [{language}]: fetching {len(ids)} advisories from OSV")
        details = osv.details(ids)
        affecting = {p: _dedupe(v, details) for p, v in affecting.items()}
        history = {p: _dedupe(v, details) for p, v in history.items()}
        for old in (lang_dir / "packages").glob("*.md"):
            old.unlink()
        for pkg in sorted(names):
            pkg_ids = _dedupe(set(history.get(pkg, [])) | set(affecting.get(pkg, [])), details)
            vulns = [details[i] for i in pkg_ids if details.get(i)]
            if vulns:
                (lang_dir / "packages" / f"{safe_name(pkg)}.md").write_text(
                    package_md(pkg, ecosystem, libs.resolved.get(pkg), vulns,
                               set(affecting.get(pkg, []))),
                    encoding="utf-8")
        (lang_dir / "INDEX.md").write_text(
            index_md(product, language, libs, affecting, history, details), encoding="utf-8")
        hits = sum(1 for v in affecting.values() if v)
        log(f"cve corpus [{language}]: {hits} librar{'y' if hits == 1 else 'ies'} with "
            f"advisories affecting the version in use -> {lang_dir}")
        built[language] = lang_dir
    (out / "README.md").write_text(_readme(product, sorted(built)), encoding="utf-8")
    return built


def _readme(product: str, languages: List[str]) -> str:
    return f"""# CVE corpus: {product}

Built by pyscan from OSV (https://osv.dev) for this repository, and read by
recon-cve-mapper during scans. Languages: {', '.join(languages)}.

- <language>/INDEX.md -- versions in use, advisories affecting them, and
  where each library was found (manifest, lock/env, or source imports)
- <language>/packages/<package>.md -- one library's advisories with affected
  and fixed versions

pyscan builds this automatically when a run finds no corpus and has network
access. Rebuild it before a scan to pick up new advisories:

    python3 -m pyscan build-cve-corpus --product-config ./product-config.json \\
        --source-repo /path/to/code
"""


_SEVERITIES = ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW")


def affecting_from_index(lang_dir: Path) -> List[Dict[str, Any]]:
    """Libraries with advisories affecting their installed version, read back
    from a corpus INDEX.md: [{package, version, file, imported, advisories:
    [{id, severity, line}]}], imported libraries first, then most severe."""
    try:
        text = (lang_dir / "INDEX.md").read_text(encoding="utf-8")
    except OSError:
        return []
    start = text.find("## Advisories affecting")
    if start == -1:
        return []
    end = text.find("\n## ", start + 1)
    section = text[start:end if end != -1 else None]
    libs: List[Dict[str, Any]] = []
    for line in section.splitlines():
        head = re.match(r"^### (\S+) (\S+) -> (packages/\S+\.md)", line)
        if head:
            libs.append({"package": head.group(1), "version": head.group(2),
                         "file": str(lang_dir / head.group(3)), "advisories": []})
        elif line.startswith("- ") and libs:
            sev = re.search(r"\[(" + "|".join(_SEVERITIES) + r")\b", line)
            libs[-1]["advisories"].append({
                "id": line[2:].split()[0],
                "severity": sev.group(1) if sev else "UNRATED",
                "line": line[2:].strip(),
            })

    # "Found in" column of the libraries table: is it imported by the code?
    found_in = {
        m.group(1): m.group(2).strip()
        for m in re.finditer(r"^\| (\S+) \| [^|]+ \| ([^|]+) \|", text, re.M)
    }
    for lib in libs:
        where = found_in.get(lib["package"], "")
        lib["imported"] = "imports" in where
        lib["declared"] = "manifest" in where

    def worst(lib: Dict[str, Any]) -> int:
        return max((_SEVERITY_ORDER.get(a["severity"], 0) for a in lib["advisories"]), default=0)

    # Libraries the code imports directly first: their features are the ones
    # an attacker can most plausibly reach.
    return sorted(libs, key=lambda lib: (not lib["imported"], -worst(lib), -len(lib["advisories"])))


def reachability_targets(lang_dir: Path, limit: int = 8) -> List[Dict[str, Any]]:
    """Libraries worth a reachability check: imported by the code (any
    severity), or declared in a manifest with a HIGH or CRITICAL advisory.
    Packages only seen in lock files or environments are left out; they stay
    in the CVE inventory."""
    picked = [
        lib for lib in affecting_from_index(lang_dir)
        if lib["imported"] or (lib["declared"] and any(
            a["severity"] in ("CRITICAL", "HIGH") for a in lib["advisories"]))
    ]
    return picked[:limit]
