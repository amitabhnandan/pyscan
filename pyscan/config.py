"""Configuration loading and run context for pyscan.

All settings come from the product config JSON and environment variables.
Nothing here reaches the network.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


@dataclass
class LLMConfig:
    """How to reach the local model server.

    base_url points at an OpenAI-compatible endpoint on localhost inside the
    sandbox. No other host is ever contacted.
    """

    base_url: str = "http://127.0.0.1:8000/v1"
    model: str = "qwen3-coder-next-32k"
    api_key: str = "not-needed-local"
    # Qwen3-Coder-Next supports 256K, but 32K keeps memory and latency
    # practical on one machine. The orchestrator compacts context so a single
    # request stays under it.
    context_tokens: int = 32768
    # Room for a full report section per write; with compaction at ~72% of
    # the window, input plus output still fits in 32K.
    max_output_tokens: int = 8192
    # Qwen3-Coder-Next's recommended sampling. Near-greedy settings (for
    # example temperature 0.1) make Qwen3 models repeat the same tool call
    # until the budget runs out. For Qwen2.5-Coder, 0.1 / 0.9 work well.
    temperature: float = 1.0
    top_p: float = 0.95
    # Server-side tool-calling. vLLM: --enable-auto-tool-choice
    # --tool-call-parser qwen3_coder. Ollama: native. If the server lacks it, the
    # agent loop falls back to parsing tool calls out of the text.
    native_tool_calls: bool = True
    request_timeout_s: int = 1800
    max_retries: int = 4

    @classmethod
    def from_env(cls) -> "LLMConfig":
        return cls(
            base_url=os.environ.get("PYSCAN_LLM_BASE_URL", cls.base_url),
            model=os.environ.get("PYSCAN_LLM_MODEL", cls.model),
            api_key=os.environ.get("PYSCAN_LLM_API_KEY", cls.api_key),
            context_tokens=int(
                os.environ.get("PYSCAN_LLM_CONTEXT_TOKENS", cls.context_tokens)
            ),
            max_output_tokens=int(
                os.environ.get("PYSCAN_LLM_MAX_OUTPUT_TOKENS", cls.max_output_tokens)
            ),
            temperature=float(
                os.environ.get("PYSCAN_LLM_TEMPERATURE", cls.temperature)
            ),
            top_p=float(os.environ.get("PYSCAN_LLM_TOP_P", cls.top_p)),
            native_tool_calls=os.environ.get(
                "PYSCAN_LLM_NATIVE_TOOL_CALLS", "1"
            ).strip().lower()
            not in ("0", "false", "no"),
            request_timeout_s=int(
                os.environ.get("PYSCAN_LLM_TIMEOUT_S", cls.request_timeout_s)
            ),
        )


@dataclass
class ProductConfig:
    product_key: str = "unknown-product"
    product_name: str = "Unknown Product"
    product_aliases: list[str] = field(default_factory=list)
    product_versions: str = ""
    source_roots: list[str] = field(default_factory=lambda: ["."])
    native_tooling: str = "not available"
    cve_baseline_doc: str = "not available"
    threat_model_doc: str = "not available"
    highest_value_asset: str = ""
    known_entry_points: list[str] = field(default_factory=list)
    bootstrap_lines: list[str] = field(default_factory=list)
    extra_context_lines: list[str] = field(default_factory=list)
    default_hunt_mode: str = "FULL_48H"
    default_optional_keywords: str = "not enabled"
    # Offline-only additions (see docs/offline-inputs.md):
    cve_corpus_dir: str = "not available"  # pre-fetched advisories/CVEs on disk
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "ProductConfig":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            product_key=str(data.get("product_key", cls.product_key)),
            product_name=str(data.get("product_name", cls.product_name)),
            product_aliases=_as_list(data.get("product_aliases")),
            product_versions=str(data.get("product_versions", "")),
            source_roots=_as_list(data.get("source_roots")) or ["."],
            native_tooling=str(data.get("native_tooling") or "not available"),
            cve_baseline_doc=str(data.get("cve_baseline_doc") or "not available"),
            threat_model_doc=str(data.get("threat_model_doc") or "not available"),
            highest_value_asset=str(data.get("highest_value_asset", "")),
            known_entry_points=_as_list(data.get("known_entry_points")),
            bootstrap_lines=_as_list(data.get("bootstrap_lines")),
            extra_context_lines=_as_list(data.get("extra_context_lines")),
            default_hunt_mode=str(data.get("default_hunt_mode") or "FULL_48H"),
            default_optional_keywords=str(
                data.get("default_optional_keywords") or "not enabled"
            ),
            cve_corpus_dir=str(data.get("cve_corpus_dir") or "not available"),
            raw=data,
        )


def is_unset(value: str | None) -> bool:
    if value is None:
        return True
    v = value.strip().lower()
    return v in ("", "not available", "not_available", "n/a", "none", "not enabled")


HUNT_MODES = ("FULL_48H", "RECON_ONLY", "HUNT_ONLY")


@dataclass
class RunContext:
    """Everything a run needs, resolved once at startup."""

    product: ProductConfig
    llm: LLMConfig
    source_repo: Path
    hunt_dir: Path
    agents_dir: Path
    prompts_dir: Path
    export_root: Path
    hunt_mode: str = "FULL_48H"
    optional_keywords: str = "not enabled"
    native_tooling: str = "not available"
    semgrep_bin: str | None = None
    semgrep_rulesets: list[str] = field(
        default_factory=lambda: ["p/security-audit", "p/owasp-top-ten", "p/cwe-top-25"]
    )
    dry_run: bool = False
    # Language -> CVE corpus folder for this target ("any" for a hand-staged
    # corpus without language folders). Filled in by the CLI at startup.
    cve_corpus: dict[str, Path] = field(default_factory=dict)
    # Local semgrep rule-set files (see semgrep_rules.py), and whether the run
    # is offline, in which case semgrep must not reach the registry.
    semgrep_rules_cache: Path | None = None
    offline: bool = False

    @property
    def unconstrained_requested(self) -> bool:
        return "UNCONSTRAINED_REDTEAM" in (self.optional_keywords or "").upper()

    def hunt_path(self, *parts: str) -> Path:
        return self.hunt_dir.joinpath(*parts)
