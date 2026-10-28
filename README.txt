===============================================================================
 pyscan -- Local Offline Security Hunt
===============================================================================

A self-contained security bug-hunt framework that scans a source tree you
already have on disk, using a LOCAL large language model, inside a sandbox with
NO internet access. It leaves a durable .hunt/ evidence trail that another
engineer can validate.

Default model: Qwen3-Coder-Next (served as qwen3-coder-next-32k), over an
OpenAI-compatible /v1 endpoint by vLLM, Ollama, or llama.cpp.


-------------------------------------------------------------------------------
 WHAT IT DOES
-------------------------------------------------------------------------------

A deterministic Python orchestrator drives a sequence of LLM "roles" through
a structured security review:

  1. RECON
       - recon-cve-mapper      -> .hunt/cve-inventory.md (from the CVE corpus)
       - semgrep sweep (code)  -> .hunt/semgrep-findings.md, every source root
       - recon-surface-mapper  -> .hunt/attack-surface.md
       - recon-test-gap        -> .hunt/test-gaps.md

  2. HUNT. Every pass writes candidates, then runs the same pipeline:
       hunt-blueteam (try to disprove them) -> evidence gate (code: demote
       claims built on files the blue team never opened) -> hunt-verifier
       (re-derive the exploit with a concrete input and check every outside
       assumption; only VERIFIED survive, and only if backed by files it
       opened) -> hunt-filer (write the finding).
       Passes, in order:
         Semgrep triage  - hunt-semgrep-triage reviews sweep matches in
                           batches, most severe first
         Dependencies    - hunt-dep-reachability checks whether advisories
                           affecting installed libraries (from the CVE corpus)
                           are reachable through code that uses them
         Iterations 1-4  - hunt-redteam under four attacker personas:
         Iteration 1 - Opportunist (default config, no credentials)
         Iteration 1 - Opportunist (default config, no credentials)
         Iteration 2 - Insider (authenticated standard user)
         Iteration 3 - Chainer (hardening-gap hunter)
         Iteration 4 - Chainer (corner cases)
         Iteration 5 - Unconstrained (only if UNCONSTRAINED_REDTEAM requested)

Final output under .hunt/ :
       findings-summary.csv        (sortable, one row per confirmed finding)
       findings/SECSCAN-XXXX-*.md  (full evidence pack per finding; ids are
                                    assigned by pyscan, not the model)
       executive-summary.md        (counts, CWE distribution, top findings)
       plus all recon and per-iteration artifacts.


-------------------------------------------------------------------------------
 KEY DESIGN CHOICES
-------------------------------------------------------------------------------

  - Orchestration is deterministic Python (pyscan/orchestrator.py), not an LLM
    "dispatcher" session. The model is used ONLY for the security reasoning
    inside each role, so runs are reproducible and the control flow cannot be
    derailed by a confused model.
  - Model access is a small stdlib OpenAI-compatible client (pyscan/llm.py)
    that talks to a localhost endpoint. It has a tool-call fallback parser (for
    servers without native tool calling) and context compaction (for a
    32K-class context window).
  - The model's tools are a fixed, read-biased set confined to the source and
    output trees (pyscan/tools.py). No shell, no arbitrary file access.
  - All knowledge is staged on disk; nothing is fetched at scan time:
       * CVE knowledge -> a CVE corpus pyscan builds for each repository
                          from OSV (cve-corpus/<product_key>/python)
       * semgrep rules -> locally cached rulesets
    See docs/offline-inputs.md.

  The full design is in docs/architecture.md.


-------------------------------------------------------------------------------
 REQUIREMENTS
-------------------------------------------------------------------------------

  - Python 3.10+ (standard library only; no pip packages required to run).
  - ripgrep (rg) recommended for fast search; grep is used as a fallback.
  - semgrep (optional) for static pre-filtering.
  - A local model server exposing an OpenAI-compatible /v1 endpoint, serving
    Qwen3-Coder-Next (or a compatible code model).
  - For the sandboxed workflow: Docker + Docker Compose, and a GPU/host able to
    serve the model.


-------------------------------------------------------------------------------
 QUICK START A -- SANDBOXED, OFFLINE (recommended for real scans)
-------------------------------------------------------------------------------

STEP 1. On a machine WITH internet, build the offline bundle
        (cached semgrep rules):

    ./scripts/prepare-offline-bundle.sh ./offline-bundle

STEP 2. Download the model weights ONCE into a directory you will mount
        read-only, e.g. Qwen3-Coder-Next. Pick the quantization that
        fits your hardware (see "MODEL / HARDWARE NOTES" below).

STEP 3. Build the scanner image:

    docker compose -f sandbox/compose.yaml build scanner

STEP 4. Move the image, the weights, and ./offline-bundle to the air-gapped
        host. Then set the inputs and run:

    export PYSCAN_MODEL_DIR=/path/to/qwen3-coder-next
    export PYSCAN_SOURCE_DIR=/path/to/source/checkout
    export PYSCAN_OUTPUT_DIR=/path/to/writable/output
    export PYSCAN_PRODUCT_CONFIG=/path/to/product-config.json
    export PYSCAN_BUNDLE_DIR=./offline-bundle
    export PYSCAN_HUNT_MODE=FULL_48H          # or RECON_ONLY / HUNT_ONLY

    docker compose -f sandbox/compose.yaml up --abort-on-container-exit

What happens: the scanner container first runs its network-isolation self-test
and REFUSES to start if it can reach the internet, then checks the model
endpoint, then runs the hunt. Findings appear under $PYSCAN_OUTPUT_DIR/.hunt/.

The source is mounted read-only; the scan can never modify the code it reviews.
Full sandbox detail (networks, model serving options) is in sandbox/README.md.


-------------------------------------------------------------------------------
 QUICK START B -- HOST RUN (for development / trying it out)
-------------------------------------------------------------------------------

Use this when you already have a model serving locally and just want to run the
framework directly on the host.

STEP 1. Start a local model server, e.g. one of:

    # vLLM (tool calling enabled)
    vllm serve /models/qwen3-coder-next \
      --served-model-name qwen3-coder-next-32k \
      --max-model-len 32768 \
      --enable-auto-tool-choice --tool-call-parser qwen3_coder

    # Ollama: create qwen3-coder-next-32k as in Quick Start C, then
    #   set PYSCAN_LLM_BASE_URL=http://127.0.0.1:11434/v1

    # llama.cpp
    llama-server -m qwen3-coder-next-q4_k_m.gguf -c 32768 --jinja \
      --alias qwen3-coder-next-32k --port 8000

STEP 2. Create your product config from the template and edit it:

    cp product-config.example.json product-config.json
    # edit product-config.json  (fields documented in docs/local-runner.md)

STEP 3. Point at the model and run:

    export PYSCAN_LLM_BASE_URL=http://127.0.0.1:8000/v1
    export PYSCAN_LLM_MODEL=qwen3-coder-next-32k

    ./scripts/run-local-hunt.sh \
      --product-config ./product-config.json \
      --source-repo    /path/to/source/repo \
      --output-dir     ./scan-output \
      --hunt-mode      FULL_48H

Notes:
  - Before the hunt starts, a capability check lists recommended tools and
    inputs (semgrep, ripgrep, CVE corpus, threat model, product
    context), what each missing one costs, and how to add it. Git history
    is optional: in a git checkout, recon summarises recent changes and
    security-fix commits into .hunt/git-history.md to prioritise reading;
    without one that step is skipped.
    If anything is missing it asks you to confirm. Pass --yes (or set
    PYSCAN_ACCEPT_MISSING_TOOLS=1) to accept the gaps up front, e.g. for
    unattended runs where nobody can answer the prompt.
  - Add --optional-keywords UNCONSTRAINED_REDTEAM to enable the 5th pass.
  - --allow-egress skips the network-isolation check. It is for LOCAL DEV ONLY;
    real scans must run in the sandbox where egress is actually blocked.
  - Equivalent direct form:  python3 -m pyscan run --product-config ... \
                               --source-repo ... --output-dir ...


-------------------------------------------------------------------------------
 QUICK START C -- LOCAL RUN WITH OLLAMA (e.g. from VS Code)
-------------------------------------------------------------------------------

Run pyscan directly on your machine against a Qwen model served by Ollama.
No pip install is needed -- pyscan is standard-library only.

STEP 1. Make the model available in Ollama and give it a 32K context window.
        Ollama defaults to a small context that would truncate the scan, so
        create a variant with a larger num_ctx:

    ollama list                              # see what you have pulled
    ollama pull qwen3-coder-next:q4_K_M      # ~51 GB; needs Ollama 0.15.5+

    cat > Modelfile <<'EOF'
    FROM qwen3-coder-next:q4_K_M
    PARAMETER num_ctx 32768
    EOF
    ollama create qwen3-coder-next-32k -f Modelfile

        Ollama now serves an OpenAI-compatible endpoint at
        http://localhost:11434/v1 with the model name 'qwen3-coder-next-32k'.

STEP 2. Create your product config from the template and edit it:

    cp product-config.example.json product-config.json
    # edit product-config.json  (fields documented in docs/local-runner.md)

STEP 3. Point pyscan at Ollama:

    export PYSCAN_LLM_BASE_URL=http://localhost:11434/v1
    export PYSCAN_LLM_MODEL=qwen3-coder-next-32k   # must match `ollama list`
    export PYSCAN_LLM_CONTEXT_TOKENS=32768
    # If your Ollama build rejects tool calls, use the text fallback parser:
    # export PYSCAN_LLM_NATIVE_TOOL_CALLS=0

    python3 -m pyscan check-model     # verify the endpoint answers

STEP 4. Run the hunt (from the VS Code integrated terminal, or any shell):

    python3 -m pyscan run \
      --product-config ./product-config.json \
      --source-repo    /path/to/code/to/scan \
      --output-dir     ./scan-output \
      --hunt-mode      FULL_48H \
      --allow-egress

        Results land in ./scan-output/.hunt/.
        Progress (every model turn and tool call) prints to the console and
        is appended to a file you can watch from another terminal:

    tail -f ./scan-output/.hunt/local-run/logs/progress.log

Running from VS Code with Run/Debug (F5) instead of the terminal:
  A ready-to-use .vscode/launch.json already ships in the repo with two
  configurations: "pyscan: run hunt (Ollama)" and "pyscan: check-model".
  Select a Python 3.10+ interpreter (command: "Python: Select Interpreter"),
  set the --source-repo arg in launch.json to your target code path, then
  press F5. The committed file looks like:

    {
      "version": "0.2.0",
      "configurations": [
        {
          "name": "pyscan: run hunt",
          "type": "debugpy",
          "request": "launch",
          "module": "pyscan",
          "cwd": "${workspaceFolder}",
          "args": [
            "run",
            "--product-config", "${workspaceFolder}/product-config.json",
            "--source-repo", "/path/to/code/to/scan",
            "--output-dir", "${workspaceFolder}/scan-output",
            "--hunt-mode", "FULL_48H",
            "--allow-egress"
          ],
          "env": {
            "PYSCAN_LLM_BASE_URL": "http://localhost:11434/v1",
            "PYSCAN_LLM_MODEL": "qwen3-coder-next-32k",
            "PYSCAN_LLM_CONTEXT_TOKENS": "32768"
          },
          "console": "integratedTerminal"
        }
      ]
    }

Notes:
  - The first run per model is slow: Ollama loads ~51 GB of weights before
    the first token. `check-model` warms it up.
  - Only one large model fits in 64 GB at a time. Unload any other with
    `ollama stop <name>` before switching.
  - --allow-egress skips the network-isolation check and is for LOCAL DEV ONLY.
    A locked-down scan should run in the sandbox (Quick Start A), where egress
    is actually blocked.
  - Add --optional-keywords UNCONSTRAINED_REDTEAM for the optional 5th pass.

-------------------------------------------------------------------------------
 USEFUL COMMANDS
-------------------------------------------------------------------------------

  # Verify the sandbox has no internet egress (hard-fails if it does):
  python3 -m pyscan check-egress

  # Save semgrep rule sets as local files for offline scans (needs internet):
  python3 -m pyscan cache-semgrep-rules

  # Build or refresh the CVE corpus for a repository (needs internet; a run
  # with --allow-egress also builds it automatically when missing):
  python3 -m pyscan build-cve-corpus --product-config ... --source-repo ...

  # Verify the local model endpoint answers:
  python3 -m pyscan check-model

  # Show the capability check (missing tools/inputs and what they cost)
  # and the resolved run context, without running anything:
  ./scripts/run-local-hunt.sh --product-config ... --source-repo ... --dry-run


-------------------------------------------------------------------------------
 CONFIGURATION
-------------------------------------------------------------------------------

Product config (product-config.json; template product-config.example.json):
  product_name, product_aliases, product_versions
  source_roots         paths relative to --source-repo
  highest_value_asset, known_entry_points, extra_context_lines
                       what an attacker wants and how input gets in; see
                       docs/product-context.md for a guide and template
  cve_corpus_dir       CVE corpus to use (default: cve-corpus/<product_key>/,
                       built from OSV when missing; see docs/offline-inputs.md)
  default_hunt_mode, default_optional_keywords
  (full field list in docs/local-runner.md)

Environment variables:
  PYSCAN_LLM_BASE_URL          local model endpoint (default http://127.0.0.1:8000/v1)
  PYSCAN_LLM_MODEL             served model name (default qwen3-coder-next-32k)
  PYSCAN_LLM_CONTEXT_TOKENS    model context window (default 32768)
  PYSCAN_LLM_NATIVE_TOOL_CALLS set to 0 if the server lacks tool calling
  PYSCAN_LLM_TEMPERATURE       sampling temperature (default 1.0; use 0.1
                               for Qwen2.5-Coder)
  PYSCAN_LLM_TOP_P             nucleus sampling (default 0.95; use 0.9 for
                               Qwen2.5-Coder)
  PYSCAN_MAX_SAME_WRITES       times a role may overwrite a file with ~the
                               same content (>=95% similar) before further
                               rewrites are refused and the role moves on
                               (default 2)
  SEMGREP_BIN                  absolute path to semgrep (optional)
  PYSCAN_ACCEPT_MISSING_TOOLS 1 = run even if the capability check finds
                               gaps (same as --yes)
  PYSCAN_SEMGREP_TRIAGE_MAX    semgrep matches to triage, most severe first
                               (default 60)
  PYSCAN_SEMGREP_BATCH         matches per triage run (default 20)
  PYSCAN_DEP_MAX_PACKAGES      libraries checked by the dependency pass
                               (default 8; imported libraries first)
  SEMGREP_RULESETS             space-separated rulesets (default: p/security-audit
                               p/owasp-top-ten p/cwe-top-25)


-------------------------------------------------------------------------------
 MODEL / HARDWARE NOTES
-------------------------------------------------------------------------------

  Qwen3-Coder-Next is an 80B mixture-of-experts model with ~3B parameters
  active per token, so it is fast for its size but needs memory for all 80B.

  - 48-64 GB GPU(s)  : a 4-bit build (~48-51 GB) plus context.
  - 80 GB+ GPU(s)    : 8-bit / FP8; longer context windows are practical.
  - Apple Silicon 64 GB : the Q4_K_M GGUF via Ollama or llama.cpp (Metal).
                       macOS caps GPU memory at ~75% of RAM by default; raise
                       it with `sudo sysctl iogpu.wired_limit_mb=56000` (until
                       reboot) so the whole model stays on the GPU.
  - Smaller machines : use a smaller code model and set PYSCAN_LLM_MODEL.

  The model supports a 256K context; 32K is the default here to keep memory
  and latency practical. The orchestrator compacts context so a single request
  stays under the window.


-------------------------------------------------------------------------------
 PROJECT LAYOUT
-------------------------------------------------------------------------------

  pyscan/             offline runtime: orchestrator, agent loop, LLM client,
                      sandboxed tools, egress self-test, CLI
  agents/             role definitions (the review methodology, reused as-is)
  runtime-prompts/    offline preamble + per-role overrides layered onto agents/
  sandbox/            Dockerfile, compose (no-egress), entrypoint, sandbox README
  scripts/            run-local-hunt.sh, prepare-offline-bundle.sh
  tests/              mock model server, vulnerable fixture, component tests
  docs/               architecture, offline-inputs, local-runner, output-contract
  security-review-master-plan.md   the review method (unchanged)
  product-config.example.json      product config template


-------------------------------------------------------------------------------
 TESTS (no GPU required)
-------------------------------------------------------------------------------

  # Component tests: tool sandboxing, tool-call parsers, egress logic
  python3 tests/test_components.py

  # Full end-to-end against a mock model (no real LLM needed):
  python3 tests/mock_llm_server.py --port 8099 &
  PYSCAN_LLM_BASE_URL=http://127.0.0.1:8099/v1 PYSCAN_LLM_MODEL=mock-qwen \
    python3 -m pyscan run \
      --product-config tests/fixtures/vuln-app/product-config.json \
      --source-repo    tests/fixtures/vuln-app \
      --output-dir     /tmp/scan-out \
      --allow-egress --yes


-------------------------------------------------------------------------------
 SAFETY MODEL
-------------------------------------------------------------------------------

  - The scan container runs on an internal-only Docker network (no gateway to
    the internet), and the egress self-test hard-fails the run if any external
    host is reachable -- caught before any source is read.
  - The source tree is mounted read-only; only the output directory is writable.
  - The model reaches exactly one host: the local inference endpoint. Its tools
    are a fixed, read-biased set confined to the source and output trees, with
    no shell and no outbound network.
===============================================================================
