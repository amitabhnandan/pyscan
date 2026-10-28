# Local Runner

This local runner runs the security hunt entirely on your own machine with a
**local LLM**. It assumes:

- the source tree already exists on local Linux or macOS
- a model server is already serving an OpenAI-compatible `/v1` endpoint
  (Qwen3-Coder-Next by default) — see `sandbox/README.md`

No checkout, credential bootstrap, or internet access is required or used.
Orchestration is deterministic Python (`pyscan/`); the model is used only for
the security reasoning inside each role. See `docs/architecture.md`.

## Quick Start

1. Copy `product-config.example.json` to `product-config.json`.
2. Fill in the product fields.
3. Point at your local model and run:

```bash
export PYSCAN_LLM_BASE_URL=http://127.0.0.1:8000/v1
export PYSCAN_LLM_MODEL=qwen3-coder-next-32k

./scripts/run-local-hunt.sh \
  --product-config ./product-config.json \
  --source-repo /path/to/source/repo \
  --output-dir ./scan-output
```

The launcher calls `python3 -m pyscan run`, which verifies the model endpoint,
runs recon, then the iterative hunt loop, writing all
artifacts under `.hunt/` in the output dir. For production use, run it in the
air-gapped sandbox (`sandbox/compose.yaml`) where network isolation is enforced.

## Useful Options

- `--hunt-mode FULL_48H|RECON_ONLY|HUNT_ONLY`
- `--optional-keywords UNCONSTRAINED_REDTEAM`
- `--output-dir PATH` where `.hunt` output is written (use when source is read-only)
- `--allow-egress` skip the network-isolation check (local dev only)
- `--dry-run` resolve and print the run context without running

The model endpoint and semgrep binary are selected via environment variables
(`PYSCAN_LLM_BASE_URL`, `PYSCAN_LLM_MODEL`, `SEMGREP_BIN`, `SEMGREP_RULESETS`).

All hunt output is written under `.hunt/` in the output dir (the source tree by
default, or `--output-dir` when set).

## Product Config Fields

- `product_key`: short local identifier
- `product_name`: official product name used for CVE/advisory research
- `product_aliases`: aliases and component names that should map back to
  this product
- `product_versions`: version family or search window
- `source_roots`: paths relative to `--source-repo`
- `native_tooling`: optional Semgrep tool notes; the runner
  also accepts `--native-tooling` or `PRODUCT_NATIVE_TOOLING`
- `cve_baseline_doc`: optional path relative to source repo
- `cve_corpus_dir`: optional offline CVE/advisory corpus dir (see docs/offline-inputs.md)
- `threat_model_doc`: optional path relative to source repo
- `highest_value_asset`: the most valuable compromise outcome
- `known_entry_points`: externally reachable or attacker-controlled inputs
- `bootstrap_lines`: environment notes injected into the prompt
- `extra_context_lines`: extra product-specific guidance injected into the prompt

## Environment

Run any product-specific source setup before invoking the script. For example:

```bash
cd /path/to/source/repo
source ./env.sh
/path/to/py-scan-local/scripts/run-local-hunt.sh \
  --product-config /path/to/product-config.json \
  --source-repo "$PWD" \
  --output-dir /path/to/output
```

The runner never mutates source files; it writes only under the `.hunt/` output
dir. In the sandbox the source is mounted read-only to enforce this.

If native tools are staged, prefer passing the exact Semgrep binary and
rulesets:

```bash
SEMGREP_BIN="$HOME/.local/bin/semgrep" \
SEMGREP_RULESETS="p/security-audit p/owasp-top-ten p/cwe-top-25" \
./scripts/run-local-hunt.sh \
  --product-config ./product-config.json \
  --source-repo /path/to/source/repo
```

The runner detects executable Semgrep from `SEMGREP_BIN` or PATH and exposes it
to the recon role through the `run_semgrep` tool. Semgrep output is triage
evidence that still needs source review. On large trees the role shards semgrep
by root and writes per-shard JSON under `.hunt/work/semgrep/`. Offline, the
rulesets must be cached locally (see docs/offline-inputs.md); without them,
`run_semgrep` reports degraded coverage and the hunt relies on direct search.
