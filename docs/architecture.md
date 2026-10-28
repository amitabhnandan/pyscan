# Architecture

pyscan is an offline security-scan framework. A deterministic Python
orchestrator drives a set of LLM "roles" against a local model to review a
source tree and file confirmed vulnerabilities, inside a sandbox with no
internet access. The model supplies security reasoning; everything that must be
reliable -- sequencing, state, finding numbering, verification -- is code.

## Components

- `pyscan/orchestrator.py` -- the controller. Owns the run: recon, the
  iterative hunt loop, and caller propagation. It
  maintains iteration state in `.hunt/state.json`, assigns finding IDs, and
  decides when each phase is done. Because the control flow is ordinary Python,
  a run is reproducible and a confused model cannot derail it.
- `pyscan/agent.py` -- runs one role as a bounded tool-use loop against the
  local model. Enforces a per-role tool-call budget, compacts context when the
  transcript approaches the model's window, and verifies the role's required
  output exists on disk before accepting the role as complete.
- `pyscan/llm.py` -- a standard-library OpenAI-compatible client for the local
  endpoint, with retries, a token estimator, and a tool-call fallback parser
  (so the loop works even against a server with no native tool-calling).
- `pyscan/tools.py` -- the fixed, read-biased tool set exposed to the model
  (`list_dir`, `read_file`, `search`, `run_semgrep`, and the single
  writer `write_hunt_file`). Every path is confined to the source tree or the
  `.hunt/` output tree; there is no shell and no outbound network.
- `pyscan/roles.py` -- composes each role's system prompt from its methodology
  definition, an offline operating preamble, and any per-role override.
- `pyscan/netguard.py` -- the network egress self-test that refuses to run if
  the sandbox can reach the internet.
- `agents/*.toml` -- the review methodology for each role (recon, red team,
  blue team, verifier, and filer).
- `runtime-prompts/overrides/*.md` -- per-role offline specifics layered on top
  of the methodology.

## Flow

```
cli.run
  └─ Orchestrator.run
       ├─ preflight: model health + egress isolation
       ├─ recon:  git history summary (code, optional) -> recon-cve-mapper
       │          -> semgrep sweep (code) -> recon-surface-mapper -> recon-test-gap
       └─ source hunt:
             semgrep triage (hunt-semgrep-triage, per batch of matches)
             dependency pass (hunt-dep-reachability, per affected library)
             iterations 1..4 (+5 if UNCONSTRAINED_REDTEAM): brief -> hunt-redteam
           each set of candidates then goes through:
             hunt-blueteam -> evidence gate (code) -> hunt-verifier
             -> verifier evidence gate (code) -> hunt-filer (per VERIFIED)
             -> update state.json -> caller propagation
```

Each arrow is a Python call that:
1. builds the role prompt (methodology + offline preamble + per-role override),
2. runs the agent loop until the required artifact exists on disk,
3. verifies the artifact in code (the "evidence of execution" rule, enforced
   rather than requested).

## Design choices

- **Orchestration is code, not a model.** Sequencing, iteration state, finding
  numbering, and caller propagation are deterministic Python, so results are
  reproducible and the model is confined to the one thing it is good at:
  reading code and reasoning about vulnerabilities inside a single role.
- **Roles are bounded.** Each role has a tool-call budget, so a model that
  loops or wanders is stopped and the phase is evaluated on what it produced.
- **Context is compacted.** The agent loop summarises older tool output when a
  transcript approaches the model's window, keeping long recon and hunt passes
  within a 32K-class context.
- **Tool calls have a fallback.** If the model server cannot emit structured
  tool calls, the model is instructed to print a fenced `tool_call` JSON block,
  which the client parses into the same shape.
- **Tools are read-biased and sandboxed.** The model can read and search the
  source and run static analysis, but it can only write under `.hunt/`, and no
  tool can reach outside the source and output trees or touch the network.

## How role prompts are composed

`pyscan/roles.py` reads each role's instructions from `agents/*.toml`
(extracted with a regex, so no `tomllib` is needed and it runs on Python 3.10+),
prepends an offline operating preamble that declares the fixed tool set and the
tool-call protocol, and appends any per-role override from
`runtime-prompts/overrides/`. The composed prompt is the role's system message;
the orchestrator then runs it through the agent loop. There is no dispatcher
role -- the orchestrator is the controller.
