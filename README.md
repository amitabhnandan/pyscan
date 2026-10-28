# pyscan: offline security review for Python code

pyscan reviews a Python code base for security vulnerabilities with a **local
LLM**, such as Qwen3-Coder-Next served by Ollama. Nothing leaves your machine:
the model runs locally, the code is only read, and every result is written to
a `.hunt/` folder that another engineer can check line by line.

## Scope

**What it reviews**

- Python source only: `*.py` and `*.pyi` files under the source roots you
  configure. Code search, the semgrep sweep, and git-history prioritisation
  all skip other file types.
- Third-party Python libraries the code uses: it reads `requirements*.txt`,
  `pyproject.toml`, `uv.lock`, installed `*.dist-info` metadata, and the code's
  own imports, then looks up known advisories for those versions.

**What it looks for**

Attacker-reachable flaws, traced from an entry point to a dangerous call, for
example:

- command execution and code evaluation (`subprocess(..., shell=True)`,
  `os.system`, `eval`, `exec`)
- SQL injection, template injection (`render_template_string`, Jinja
  `Template`), and unsafe deserialisation (`pickle`, `yaml.load`, `marshal`)
- path traversal and archive extraction, SSRF through `requests`, `httpx`,
  `urllib`, `aiohttp`
- missing or bypassable authentication and authorisation in FastAPI, Flask,
  Django, Starlette, aiohttp, MCP tools, chat-bot handlers, and background jobs
- prompt injection that reaches LLM agent tools
- weak cryptography, disabled TLS verification, and hard-coded secrets
- vulnerable library versions that the code actually calls

**What it does not do**

- It does not review other languages. If the repository has JavaScript, Go,
  shell, or similar code, the surface map lists it as not reviewed.
- It does not run or modify the target code. The model has no shell and can
  write only under `.hunt/`.
- It does not prove exploitability dynamically. Each finding is a traced code
  path that a blue-team pass tried to disprove and a verifier re-derived; a
  person should still confirm it.
- Deployment files such as a Dockerfile or Kubernetes manifest may be opened
  to decide whether a Python finding is reachable, but they are not scanned.

## How it works

A plain Python orchestrator, not the model, runs the review in fixed steps.
The model only does the security reasoning inside each step.

1. **Recon**
   - summarise recent git history, if the target is a git checkout
   - build a CVE inventory from the advisory corpus (`recon-cve-mapper`)
   - run semgrep over the Python files
   - map entry points, dangerous calls, and auth checks (`recon-surface-mapper`)
   - find code without security tests (`recon-test-gap`)
2. **Hunt**
   - triage the semgrep matches in batches (`hunt-semgrep-triage`)
   - check whether vulnerable library versions are reachable
     (`hunt-dep-reachability`)
   - four red-team passes with different attacker personas: opportunist,
     insider, and two "chainer" passes (`hunt-redteam`)
3. **Prove or drop**: every candidate goes to a blue team that tries to
   disprove it (`hunt-blueteam`). The orchestrator then demotes any
   confirmation whose cited files the model never opened. Next, a verifier
   re-derives the exploit with a concrete input (`hunt-verifier`). Only
   verified, attacker-reachable findings are written up (`hunt-filer`).

Results:

```
<output-dir>/.hunt/
  findings-summary.csv         one row per finding
  findings/SECSCAN-0001-*.md   evidence pack: code path, severity, fix
  executive-summary.md         counts, CWE spread, top findings
  attack-surface.md, cve-inventory.md, test-gaps.md, candidates/ ...
  local-run/logs/progress.log  every model turn and tool call
```

The design is described in `docs/architecture.md`.

## Requirements

- macOS or Linux
- Python 3.10 or newer. pyscan uses only the standard library, so there is
  nothing to `pip install`.
- [Ollama](https://ollama.com) 0.15.5 or newer, which serves the model
- Enough memory for the model. The 4-bit Qwen3-Coder-Next build is about
  51 GB, so plan for 64 GB of unified memory on Apple Silicon, or a 48–64 GB
  GPU. On a smaller machine, use the Qwen2.5-Coder fallback below.
- VS Code with the Python extension (Microsoft), which includes the
  debugger used by the launch configurations
- Recommended:
  - `ripgrep`, for fast search (grep is used without it)
  - `semgrep`, for the rule-based sweep

```bash
brew install ripgrep semgrep
```

## Set up locally

### 1. Get the code

```bash
git clone <your-repo-url> py-scan-local
cd py-scan-local
python3 --version
```

### 2. Create the local role files

Four files are kept out of git and must exist before a scan runs:

| File | Needed for |
|---|---|
| `agents/recon-cve-mapper.toml` | Every scan: the first recon step builds the CVE inventory |
| `agents/recon-test-gap.toml` | Every scan: the recon step that finds untested code |
| `agents/hunt-redteam-unconstrained.toml` | Only with `--optional-keywords UNCONSTRAINED_REDTEAM` |
| `docs/output-contract.md` | Documentation only |

Without the first two, the scan stops with `FileNotFoundError` as soon as
recon starts. Each has a working example next to it. Copy them, then adapt
the instructions to your needs:

```bash
cp agents/recon-cve-mapper.example.toml agents/recon-cve-mapper.toml
```

```bash
cp agents/recon-test-gap.example.toml agents/recon-test-gap.toml
```

```bash
cp agents/hunt-redteam-unconstrained.example.toml agents/hunt-redteam-unconstrained.toml
```

```bash
cp docs/output-contract.example.md docs/output-contract.md
```

When you write your own versions, keep these parts, because the code
depends on them:

- the `developer_instructions = """..."""` block. pyscan reads only this
  block from each `.toml` file.
- the output file each role writes, and its `## Status:` line
- in the red-team file, the candidate format (`### CAND-`, `Entry Point:`,
  `Sink:`, `Chain:`)
- the first sentence of each example. The mock model in `tests/` uses it to
  tell the roles apart.

### 3. Serve Qwen3-Coder-Next with Ollama

Ollama's default context window is too small for this tool, so create a
variant with a 32K context:

```bash
ollama pull qwen3-coder-next:q4_K_M
```

```bash
printf 'FROM qwen3-coder-next:q4_K_M\nPARAMETER num_ctx 32768\n' > Modelfile
```

```bash
ollama create qwen3-coder-next-32k -f Modelfile
```

Ollama now answers at `http://localhost:11434/v1` with the model name
`qwen3-coder-next-32k`. Check that pyscan can reach it:

```bash
PYSCAN_LLM_BASE_URL=http://localhost:11434/v1 PYSCAN_LLM_MODEL=qwen3-coder-next-32k python3 -m pyscan check-model
```

The first request loads about 51 GB of weights, so it can take a few minutes.

### 4. Describe the code you want to scan

```bash
cp product-config.example.json product-config.json
```

Edit `product-config.json`. The fields that matter most:

| Field | What to put in it |
|---|---|
| `product_key` | Short name, used for the CVE corpus folder |
| `product_name` | Name of the application |
| `source_roots` | Folders to review, relative to the repository root, e.g. `["app", "services"]` |
| `highest_value_asset` | What an attacker would most want, e.g. "customer payment records" |
| `known_entry_points` | How input gets in, e.g. "HTTP API on port 8080 (app/api/)" |
| `threat_model_doc` | Path to a threat model, if you have one |

`docs/product-context.md` explains how to fill in the last three, with
examples. `product-config.json` is git-ignored, so your settings stay local.

### 5. Optional: build the CVE corpus

The corpus lets recon use real advisories for your library versions instead
of the model's memory. Building it sends library names and versions to
api.osv.dev:

```bash
python3 -m pyscan build-cve-corpus --product-config ./product-config.json --source-repo /path/to/code/to/scan
```

Without it, the first run with `--allow-egress` builds it automatically, or
recon falls back to a class-based inventory.

## Run it from VS Code

1. Open the `py-scan-local` folder in VS Code, after completing the setup
   steps above.
2. Run **Python: Select Interpreter** from the Command Palette and pick Python
   3.10 or newer.
3. Open `.vscode/launch.json`. In the **pyscan: run hunt (Ollama)**
   configuration, replace `/ABSOLUTE/PATH/TO/CODE/TO/SCAN` with the full path
   of the repository you want to review.
4. Open **Run and Debug** (⇧⌘D), choose **pyscan: check-model**, and press F5.
   You should see `OK: model endpoint healthy`.
5. Choose **pyscan: run hunt (Ollama)** and press F5.

The scan prints a capability check first: whether semgrep, ripgrep, the CVE
corpus, a threat model, and git history are available, and what is lost
without each. In the VS Code terminal, answer `y` to continue without the
missing items. To skip the question, add `"--yes"` to the `args` list.

Progress streams to the terminal. To follow it from another terminal:

```bash
tail -f scan-output/.hunt/local-run/logs/progress.log
```

Results land in `scan-output/.hunt/`. Start with `executive-summary.md`, then
open the evidence packs in `findings/`.

### The launch configurations

| Configuration | What it does |
|---|---|
| pyscan: run hunt (Ollama) | Full review with `qwen3-coder-next-32k` |
| pyscan: check-model | Checks that Ollama answers with `qwen3-coder-next-32k` |
| pyscan: run hunt (qwen2.5-coder fallback) | Full review with `qwen2.5-coder-32k`, for machines without room for Qwen3-Coder-Next |
| pyscan: check-model (qwen2.5-coder fallback) | Checks the fallback model |

The fallback uses temperature 0.1 and top-p 0.9, which suit Qwen2.5-Coder.
Create its 32K variant the same way as in step 2, starting from
`qwen2.5-coder:32b`.

All configurations pass `--allow-egress`. That skips the network-isolation
check, which is fine on a development machine. For a locked-down scan, use
the sandbox described below.

### Useful arguments

Add these to `args` in `launch.json`, or to the command line:

| Argument | Effect |
|---|---|
| `--hunt-mode RECON_ONLY` | Map the code base and stop; `HUNT_ONLY` reuses an earlier recon; `FULL_48H` does both |
| `--optional-keywords UNCONSTRAINED_REDTEAM` | Adds a fifth, free-form red-team pass |
| `--yes` | Continue without asking when a tool or input is missing |
| `--dry-run` | Print the capability check and resolved settings, then stop |
| `--no-cve-build` | Do not build a CVE corpus when none is found |

## Run it from the terminal

The same scan without the debugger, in the VS Code terminal or any shell:

```bash
export PYSCAN_LLM_BASE_URL=http://localhost:11434/v1
export PYSCAN_LLM_MODEL=qwen3-coder-next-32k
export PYSCAN_LLM_CONTEXT_TOKENS=32768
```

```bash
python3 -m pyscan run --product-config ./product-config.json --source-repo /path/to/code/to/scan --output-dir ./scan-output --allow-egress
```

## Model settings

Set these as environment variables, or in the `env` block of a launch
configuration:

| Variable | Default | Meaning |
|---|---|---|
| `PYSCAN_LLM_BASE_URL` | `http://127.0.0.1:8000/v1` | OpenAI-compatible endpoint; Ollama is `http://localhost:11434/v1` |
| `PYSCAN_LLM_MODEL` | `qwen3-coder-next-32k` | Model name exactly as `ollama list` shows it |
| `PYSCAN_LLM_CONTEXT_TOKENS` | `32768` | Must match the model's `num_ctx` |
| `PYSCAN_LLM_TEMPERATURE` / `PYSCAN_LLM_TOP_P` | `1.0` / `0.95` | Qwen3-Coder-Next's recommended sampling |
| `PYSCAN_LLM_NATIVE_TOOL_CALLS` | `1` | Set to `0` if the server rejects tool calls; pyscan then reads tool calls from the text |
| `PYSCAN_LLM_TIMEOUT_S` | `1800` | Seconds to wait for one model reply |
| `SEMGREP_BIN` | from `PATH` | Path to a specific semgrep binary |

## Troubleshooting

- **`cannot reach model`**: check that Ollama is running (`ollama list`) and
  that `PYSCAN_LLM_MODEL` matches a listed name exactly.
- **Very slow first turn**: the model is still loading. Run `check-model`
  first to warm it up.
- **Out of memory, or Ollama unloads the model**: only one large model fits
  in 64 GB at a time. Stop others with `ollama stop <name>`, or use the
  Qwen2.5-Coder fallback.
- **Roles end with "INCOMPLETE"**: the model ran out of tool calls or context.
  Check that `num_ctx` and `PYSCAN_LLM_CONTEXT_TOKENS` are both 32768.
- **Tool calls fail to parse**: set `PYSCAN_LLM_NATIVE_TOOL_CALLS=0`.

## Running fully offline

For scans that must never touch the network, `sandbox/` has a Docker setup.
It runs the model and the scanner on an internal-only network, mounts the
source read-only, and refuses to start if the internet is reachable. Prepare
the semgrep rules and CVE corpus on a connected machine first. See
`sandbox/README.md` and `docs/offline-inputs.md`.

## Project layout

```
pyscan/              orchestrator, agent loop, local LLM client, tools
agents/              methodology for each role; *.example.toml are templates
                     for the git-ignored role files
runtime-prompts/     offline rules and per-role overrides added to each prompt
cve-corpus/          advisory corpora built per target repository
tests/               component tests, mock model server, vulnerable Flask app
sandbox/             Docker image and compose file for air-gapped runs
scripts/             run-local-hunt.sh, prepare-offline-bundle.sh
docs/                architecture, configuration, offline inputs, output format
.vscode/launch.json  VS Code run configurations
```

## Tests

The component tests need no model:

```bash
python3 tests/test_components.py
```

For an end-to-end run without a GPU, start the mock model:

```bash
python3 tests/mock_llm_server.py --port 8099
```

Then scan the bundled vulnerable Flask app from a second terminal:

```bash
PYSCAN_LLM_BASE_URL=http://127.0.0.1:8099/v1 PYSCAN_LLM_MODEL=mock-qwen python3 -m pyscan run --product-config tests/fixtures/vuln-app/product-config.json --source-repo tests/fixtures/vuln-app --output-dir /tmp/scan-out --allow-egress --yes
```

It should file one finding: SQL injection in `app/db.py`.
