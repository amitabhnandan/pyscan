# Sandbox: running the hunt offline

The scan runs in a container with **no internet access**, driving a local
Qwen3-Coder-Next model served by a second container. The source tree is
mounted read-only; findings are written to a separate output directory.

## One-time preparation (on a machine WITH internet)

1. **Download the model weights** (once), e.g. Qwen3-Coder-Next, into a
   directory you will mount read-only. It is an 80B mixture-of-experts model
   (~3B active per token); use the quantization that fits your GPU:
   - 48-64 GB -> a 4-bit build (~48-51 GB)
   - 80 GB+ -> 8-bit / FP8, longer context
   - Apple Silicon 64 GB -> the Q4_K_M GGUF via llama.cpp/Ollama
   - smaller machines -> a smaller code model, and set `PYSCAN_LLM_MODEL`

2. **Build the CVE corpus** for the code you will scan. The sandbox has no
   internet, so it cannot build one itself:
   ```bash
   python3 -m pyscan build-cve-corpus --product-config product-config.json \
       --source-repo /path/to/source/checkout
   ```
   It writes `cve-corpus/<product_key>/`, which ships inside the image.

3. **Build the offline bundle** (semgrep rule sets saved as
   local files, so semgrep needs no internet at scan time):
   ```bash
   ./scripts/prepare-offline-bundle.sh ./offline-bundle
   ```

4. **Build the scanner image:**
   ```bash
   docker compose -f sandbox/compose.yaml build scanner
   ```

Move the image, the weights, and `./offline-bundle` to the air-gapped host.

## Running a scan (air-gapped host)

```bash
export PYSCAN_MODEL_DIR=/path/to/qwen3-coder-next
export PYSCAN_SOURCE_DIR=/path/to/source/checkout
export PYSCAN_OUTPUT_DIR=/path/to/writable/output
export PYSCAN_PRODUCT_CONFIG=/path/to/product-config.json
export PYSCAN_BUNDLE_DIR=./offline-bundle
export PYSCAN_HUNT_MODE=FULL_48H

docker compose -f sandbox/compose.yaml up --abort-on-container-exit
```

The scanner first runs its **egress self-test** and refuses to start if it can
reach the internet, then checks the model endpoint, then runs the **capability
check**. If recommended tools or inputs are missing (semgrep rules cache, CVE
corpus, threat model, product context), it lists them with their cost and
stops; export `PYSCAN_ACCEPT_MISSING_TOOLS=1` to run without them. Then it
runs the hunt. Output
appears under `$PYSCAN_OUTPUT_DIR/.hunt/`.

## Serving the model yourself (without the bundled vLLM service)

Any OpenAI-compatible `/v1` endpoint works. Point `PYSCAN_LLM_BASE_URL` at it.

- **vLLM** (tool calling on):
  ```bash
  vllm serve /models/qwen3-coder-next \
    --served-model-name qwen3-coder-next-32k \
    --max-model-len 32768 \
    --enable-auto-tool-choice --tool-call-parser qwen3_coder
  ```
- **Ollama:** create `qwen3-coder-next-32k` from `qwen3-coder-next:q4_K_M`
  with `num_ctx 32768` (see README.txt, Quick Start C), then set
  `PYSCAN_LLM_BASE_URL=http://host:11434/v1`. Ollama supports tool calling; if
  yours does not, set `PYSCAN_LLM_NATIVE_TOOL_CALLS=0` and the agent loop falls
  back to parsing tool calls from text.
- **llama.cpp:** `llama-server -m qwen3-coder-next-q4_k_m.gguf -c 32768 --jinja --alias qwen3-coder-next-32k --port 8000`.

## Why this is safe

- `networks.frontend` is `internal: true` — Docker gives it no gateway, so
  neither container can route to the internet.
- The egress self-test (`pyscan check-egress`) hard-fails the run if any
  external host is reachable, catching misconfiguration before any source is read.
- The source tree is mounted `:ro`; the only writable location is the output
  dir and (inside the model container) the read-only weights.
- The scanner's tools are a fixed, read-biased set confined to the source and
  output trees — no shell, no arbitrary file access, no outbound requests
  except to the local model.
