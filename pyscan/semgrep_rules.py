"""Local copies of semgrep registry rule sets, for offline scans.

semgrep normally downloads registry rule sets such as p/security-audit at
scan time. The sandbox has no internet, so the rule sets are downloaded once
beforehand (`pyscan cache-semgrep-rules`) as plain YAML files and run_semgrep
passes those files instead of the registry names.

Registry rules are under the Semgrep Rules License, so the cache lives in
offline-bundle/ (not committed) rather than in the repository.
"""
from __future__ import annotations

import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Optional

REGISTRY_URL = "https://semgrep.dev/c/"
DEFAULT_RULESETS = ["p/security-audit", "p/owasp-top-ten", "p/cwe-top-25"]

# Keep semgrep itself from reaching the network: no version check, no
# metrics. Rules come from local files when a cache is in use.
OFFLINE_ENV = {"SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"}


def default_cache(export_root: Path) -> Path:
    return export_root / "offline-bundle" / "semgrep-rules"


def cache_dir(export_root: Path) -> Optional[Path]:
    """SEMGREP_RULES_CACHE if set, else offline-bundle/semgrep-rules if it
    exists."""
    env = os.environ.get("SEMGREP_RULES_CACHE")
    if env:
        return Path(env)
    default = default_cache(export_root)
    return default if default.is_dir() else None


def cache_file(cache: Path, ruleset: str) -> Path:
    return cache / (ruleset.replace("/", "_").replace(":", "_") + ".yml")


def resolve(rulesets: list[str], cache: Optional[Path]) -> tuple[list[str], list[str]]:
    """(configs to pass to --config, registry rule sets with no local copy).

    A rule set that is already a local file or folder is used as is; a
    registry name is replaced by its cached file when there is one.
    """
    configs, missing = [], []
    cache = cache.resolve() if cache else None  # semgrep runs from the target repo
    for rs in rulesets:
        if Path(rs).exists():
            configs.append(str(Path(rs).resolve()))
        elif cache and cache_file(cache, rs).is_file():
            configs.append(str(cache_file(cache, rs)))
        else:
            configs.append(rs)
            missing.append(rs)
    return configs, missing


def download(rulesets: list[str], cache: Path, log: Callable[[str], None] = print) -> list[Path]:
    """Fetch each registry rule set as YAML into the cache."""
    cache.mkdir(parents=True, exist_ok=True)
    written = []
    for rs in rulesets:
        url = REGISTRY_URL + rs
        try:
            with urllib.request.urlopen(url, timeout=120) as resp:
                body = resp.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f"could not download {rs} from {url}: {exc}") from exc
        if not body.lstrip().startswith(b"rules:"):
            raise RuntimeError(f"{url} did not return a semgrep rules file")
        path = cache_file(cache, rs)
        path.write_bytes(body)
        log(f"cached {rs} -> {path} ({len(body) // 1024} KB)")
        written.append(path)
    return written
