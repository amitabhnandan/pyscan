#!/usr/bin/env bash
# Local launcher for the offline hunt (host-run equivalent of the container).
#
# It runs the pyscan orchestrator against a local OpenAI-compatible model
# endpoint.
#
# Prerequisite: a model server is already serving Qwen3-Coder-Next at
# PYSCAN_LLM_BASE_URL (default http://127.0.0.1:8000/v1). See sandbox/README.md
# for vLLM / Ollama / llama.cpp commands.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPORT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  run-local-hunt.sh --product-config PATH --source-repo PATH [options]

Required:
  --product-config PATH   Filled product-config.json
  --source-repo PATH      Existing local source tree to inspect (read-only)

Options:
  --output-dir PATH       Where .hunt output goes (default: inside source tree)
  --hunt-mode MODE        FULL_48H | RECON_ONLY | HUNT_ONLY
  --optional-keywords V   e.g. UNCONSTRAINED_REDTEAM
  --allow-egress          Skip the network-isolation check (local dev only)
  --dry-run               Resolve config and print, without running
  -h, --help              Show help

Environment:
  PYSCAN_LLM_BASE_URL     Local model endpoint (default http://127.0.0.1:8000/v1)
  PYSCAN_LLM_MODEL        Served model name (default qwen3-coder-next-32k)
  SEMGREP_BIN             Absolute semgrep path (optional)
EOF
}

[[ $# -gt 0 ]] || { usage; exit 1; }
case "${1:-}" in -h|--help) usage; exit 0;; esac

command -v python3 >/dev/null 2>&1 || { echo "python3 not found on PATH" >&2; exit 1; }

cd "${EXPORT_ROOT}"
exec python3 -m pyscan run "$@"
