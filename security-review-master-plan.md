# Security Review Master Plan

## Purpose

This is the local offline security hunt method. It is intended for an
operator who already has a source checkout and optional compiled artifact
tree on a Linux or macOS host.

The method:

- build threat context before the hunt
- map attacker-controlled entry points and dangerous sinks
- run structured attacker passes
- falsify weak candidates before filing
- leave durable `.hunt/` evidence that another engineer can validate

## Required Inputs

Before running the local script, collect:

- a filled `product-config.json`
- an absolute path to the source repo or source tree
- optional native/polyglot tooling notes, including installed scanners,
  exact Semgrep path when known, and configured Semgrep rulesets
- optional threat model document inside the source tree
- optional checked-in CVE baseline document inside the source tree
- a local model server exposing an OpenAI-compatible endpoint (see sandbox/README.md)

No SCM checkout is performed by this framework. The source path is treated as
the exact tree to inspect.

## Core Planning Flow

Use this sequence for every product:

1. Build or reuse a historical vulnerability and issue baseline.
2. Convert that baseline into attack-surface families.
3. Map those families into code roots, runtime layers, and trust boundaries.
4. Build a direct-search view of the target codebase.
5. Re-rank the work using first-principles attacker reasoning.
6. Apply an active-attacker compression pass for the opening work.
7. Use OWASP Top 10 categories as cross-cutting question generators.
8. Elevate deserialization, object rehydration, parser, resolver, loader,
   dynamic dispatch, and metadata-driven trust-boundary failures when they
   sit on meaningful boundaries.
9. Require every serious finding to preserve enough evidence for later
   engineer validation.
10. Extract reusable static-detection opportunities when a finding exposes a
    mechanically searchable bug shape.

## Scope Rules

- Focus on first-party product-owned code first.
- Include wrapper and integration misuse of bundled components when
  first-party code enables, weakens, or exposes the weakness.
- Exclude third-party CVEs as primary owned findings unless the ownership
  model explicitly requires them.
- Include tests only when they materially change exploitability, validate a
  boundary, or reveal blind spots.
- Treat generated artifacts and build output as low value unless they affect
  the real attack path.

## Recon Method

Recon answers where to spend expensive attention.

The recon package must contain:

- `.hunt/cve-inventory.md`
- `.hunt/attack-surface.md`
- `.hunt/test-gaps.md`
- optional `.hunt/threat-model-summary.md`

Historical vulnerability research should use public CVEs, advisories, exploit
writeups, product bug history available to the operator, and product aliases.
Keep CVE existence separate from exploit maturity and configuration
dependency.

Attack-surface mapping should identify:

- external entry points
- structured input handlers
- parser and resolver behavior
- policy, auth, token, and config boundaries
- naming, lookup, object materialization, and state propagation
- dynamic provider, reflection, classloading, and plugin surfaces
- recent hardening and new boundary code visible in the supplied tree

Test-gap analysis should cross-reference the attack surface and historical
patterns against available tests. Low test density is a multiplier, not a
finding by itself.

## Native And Polyglot Recon Method

For native, OS-code, shell-heavy, or polyglot source trees, source evidence
must include language-aware and build-aware signals when available. Do not
treat Python-focused searches alone as sufficient for native code.

Use these tools as optional accelerators, not as final proof:

- `semgrep`: default no-build source scanner for native and polyglot recon.
  Use it to find suspicious source/sink patterns, dangerous C library calls,
  parser length arithmetic, command execution, file path handling, auth bypass
  seams, and recurring bug shapes. Treat matches as triage seeds requiring
  source review and call-chain tracing.
  When the kickoff supplies an absolute Semgrep path or `SEMGREP_BIN`, invoke
  that exact binary instead of resolving `semgrep` through `PATH`; product
  environment setup scripts can overwrite `PATH`. When the kickoff supplies
  `SEMGREP_RULESETS` or a Semgrep ruleset list in `NATIVE_TOOLING`, pass each
  ruleset as a separate `--config` argument. The default rulesets are
  `p/security-audit`, `p/owasp-top-ten`, and `p/cwe-top-25`.
- `rg`: direct search remains mandatory for exact APIs, alternate spellings,
  generated wrappers, and variant families.
- `ctags` and `cscope`: use for cheap navigation in large C/C++ or operating
  system trees, especially when the full build is not available.
- `clang-tidy`, clang static analyzer tooling, and `cppcheck`: use when
  installed and applicable to the checked-out tree. Prefer build-aware runs
  when a native build or `compile_commands.json` exists. If build metadata is
  missing, record degraded coverage rather than treating clean output as a
  negative result.
- CodeQL or other compiled-language analyzers: use when the product build can
  be captured reliably. These are high-value follow-up inputs for C/C++, C#,
  Go, and similar compiled surfaces, but they are not the default no-build
  recon path.
- Sanitizers and fuzzing harnesses: for parsers, protocol decoders, archive
  handlers, file-format readers, kernel interfaces, and native libraries,
  preserve existing ASan/UBSan/MSan, libFuzzer, AFL-style, or product-native
  fuzz evidence as first-class validation input.

When native tooling is available, `recon-surface-mapper` should:

1. Identify language and build-system composition for each source root.
2. Build a direct-search inventory of native entry points and dangerous sinks
   before broad static scanning.
3. Run a Semgrep pass over in-scope source roots when Semgrep is available. If
   `SEMGREP_BIN` or an absolute Semgrep path is supplied, invoke that path
   directly. Use product-specific rules when present; otherwise run the
   configured rulesets:
   `"$SEMGREP_BIN" scan --config p/security-audit --config p/owasp-top-ten --config p/cwe-top-25 <source-roots>`.
   Preserve the command, rule source, and any failures.
   For large trees, do not run one broad multi-root scan and then kill it
   before output is written. Shard Semgrep by root and, when needed, by
   high-priority subroot or ruleset. Write each shard to
   `.hunt/work/semgrep/<root-or-subroot>.json` with `--json --output`, plus a
   short sidecar note containing the command, rulesets, start/end time, target
   count, exit status, and any stderr summary. Prefer prioritized shards such
   as native roots, externally reachable protocol/parser roots, management
   endpoints, web/REST roots, and recent hardening roots before broad
   whole-tree scans. If Semgrep reports a large target count but is still
   making progress, keep waiting or split the next shard smaller; do not
   manually terminate it just because rule loading or target discovery is
   slow. If a shard must be stopped for wall-clock or resource reasons, record
   the exact limit, elapsed time, roots, rulesets, and whether any JSON was
   emitted, then immediately run a narrower shard that can complete.
4. Use `ctags` or `cscope` to map callers and callees for high-risk C/C++ APIs
   when direct search finds an interesting sink but the build graph is
   unavailable.
5. Run `clang-tidy`, clang static analyzer tooling, or `cppcheck` only where
   the root can support a meaningful run. Prefer compile-database backed
   analysis; label no-build or partial runs as degraded.
6. Rank native candidates by attacker control, trust-boundary crossing,
   parser/protocol exposure, privilege boundary, memory-safety impact, and
   whether the code runs in a privileged process, kernel, driver, daemon,
   setuid helper, or shared library loaded by privileged callers.
7. Write tool output summaries into `.hunt/attack-surface.md` as evidence
   sections, not as filed findings. Serious candidates still need file/line
   evidence, call-chain reasoning, and a concrete validation path.

Typical native and OS-code search targets include:

- externally reachable protocol decoders and daemon request handlers
- file-format parsers, archive handlers, compression/decompression paths,
  image/font/XML/JSON/binary metadata readers
- kernel, driver, ioctl, STREAMS, device, filesystem, mount/import, and zone
  or container boundary code
- setuid/setgid helpers, privilege transitions, PAM/name-service hooks,
  service-management actions, package/update paths, and installer hooks
- unsafe or length-sensitive APIs such as `strcpy`, `strcat`, `sprintf`,
  `memcpy`, `memmove`, `malloc`, `realloc`, integer conversion helpers,
  custom allocators, path normalization helpers, command execution, temp file
  creation, environment-variable reads, and dynamic library loading
- parser state machines where attacker-controlled length, type, offset, count,
  or nesting values influence allocation, copy, dispatch, or loop bounds
- vendored native dependencies linked into reachable parser, protocol, crypto,
  compression, graphics, or storage paths

## Prioritization

Default priority order:

1. attacker-controlled entry points
2. trust-boundary transitions
3. dangerous sinks and exploit chains
4. historical vulnerability overlap
5. new-code and recent hardening signal
6. test blind spots

For a scarce high-reasoning window, use this weighting:

- 45 percent: attacker-surface and exploit-chain review
- 30 percent: historical-vulnerability-guided variant hunting
- 15 percent: recent hardening and branch-new review
- 10 percent: test-blind-spot confirmation and bug-to-test backlog

## Workstreams

Workstream 1: control-plane and pre-auth boundaries.

Look for protocol handlers, transport layers, session/context propagation,
naming, lookup, and object materialization before trust checks.

Workstream 2: externally reachable structured-input surfaces.

Look at SOAP, XML, REST, WSDL, schema, policy, token, auth, and message-header
processing.

Workstream 3: shared parser, runtime, resolver, and binding layers.

Look for parser factory mismatches, unsafe resolver chains, schema/binding
gaps, and lower-layer bypasses.

Workstream 4: dynamic provider, integration, reflection, and metadata-driven
paths.

Look for attacker-shaped metadata that alters provider selection, authority,
dispatch, type mapping, classloading, or execution.

Workstream 5: fresh hardening, new boundaries, and recent defenses.

Ask what invariant was added, where else it is missing, and what fallback path
still accepts the dangerous form.

## First-Two-Hours Compression

Ask:

1. What is the single highest-value asset or control outcome?
2. What is the most likely external or low-friction entry point?
3. What weakness family would give the highest return if it still exists?
4. What defender assumption would an attacker try to bypass?
5. Where would an attacker spend the first two hours to get one severe path?

Compress the opening phase around:

- one fast path to the highest-value privileged outcome
- one fast path from the most exposed structured-input surface

## Evidence Pack Contract

File a finding when the attacker-controlled entry point is clear, the
trust-boundary failure is clear, impact is severe or plausibly severe, the
path is anchored in real files/classes, and the next validation step is
concrete.

Each finding must include:

- one-line issue hypothesis
- CWE classification
- CVSS v3.1 score and vector
- severity bucket
- configuration dependency: `DEFAULT_ON`, `ONE_STEP`, or `MULTI_STEP`
- severity rationale
- attacker preconditions
- entry point with file and line
- trust boundary crossed
- bulletized code path
- exact files and classes involved
- why current hardening appears insufficient
- owner area or module
- validation steps
- missing regression tests
- static-tool opportunity, if any
- evidence status: `CONFIRMED` or `PLAUSIBLE`

## Output Artifacts

Every successful run leaves output under `.hunt/` in the supplied source tree:

- `.hunt/cve-inventory.md`
- `.hunt/attack-surface.md`
- `.hunt/test-gaps.md`
- `.hunt/state.json`
- `.hunt/iteration-[N]-brief.md`
- `.hunt/candidates/iteration-[N]-candidates.md`
- `.hunt/candidates/iteration-[N]-falsified.md`
- `.hunt/findings/SECSCAN-XXXX-*.md`
- `.hunt/findings-summary.csv`
- `.hunt/executive-summary.md`

`SECSCAN-XXXX` is a run-local provisional id. Any later aggregation or external
tracking system owns canonical id assignment.

## Agent Stack Connection

A deterministic Python orchestrator (`pyscan/orchestrator.py`) loads the
included agent role definitions from `agents/` and drives them directly. The
orchestrator -- not a model -- owns sequencing, state, finding numbering, and
caller propagation.

The orchestrator drives these roles:

- `recon-cve-mapper`
- `recon-surface-mapper`
- `recon-test-gap`
- `hunt-redteam`
- `hunt-redteam-unconstrained`
- `hunt-semgrep-triage`
- `hunt-dep-reachability`
- `hunt-blueteam`
- `hunt-verifier`
- `hunt-filer`

No external agent CLI and no nested processes are launched. Each role runs as a
bounded tool-use loop against the local model (see docs/architecture.md).
