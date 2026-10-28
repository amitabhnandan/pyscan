# Output Contract (example)

Copy to `docs/output-contract.md` (git-ignored) and adapt it to your team's
conventions:

```bash
cp docs/output-contract.example.md docs/output-contract.md
```

This page lists what a pyscan run writes under `<output-dir>/.hunt/`.

## Recon

| File | Written by | Contents |
|---|---|---|
| `git-history.md` | pyscan | Recently changed Python files and security-fix commits (only for git checkouts) |
| `cve-inventory.md` | recon-cve-mapper | Advisories and vulnerability classes, in tiers, with search patterns |
| `semgrep-findings.md` | pyscan | Semgrep matches over the Python files, numbered S-001, S-002, ... |
| `attack-surface.md` | recon-surface-mapper | Entry points, dangerous calls, auth checks, high-value paths |
| `test-gaps.md` | recon-test-gap | Security-relevant code without tests, and a Priority 1 list |

## Hunt

| File | Contents |
|---|---|
| `state.json` | Iteration state, confirmed chains, follow-up targets |
| `iteration-[N]-brief.md` | What each red-team pass focuses on |
| `candidates/*-candidates.md` | Red-team candidates (`CAND-*`) |
| `candidates/*-falsified.md` | Blue-team verdicts: CONFIRMED, DOWNGRADED, DISPROVED, INSUFFICIENT EVIDENCE |
| `candidates/*-verified-[K].md` | Verifier verdicts: VERIFIED, REJECTED, UNCERTAIN |

Candidate files come from the semgrep triage (`semgrep-[B]-*`), the
dependency pass (`deps-[P]-*`) and the red-team passes (`iteration-[N]-*`).

## Findings

| File | Contents |
|---|---|
| `findings/SECSCAN-XXXX-[slug].md` | One evidence pack per finding: severity, code path, evidence, fix, and a Summary Fields block |
| `findings-summary.csv` | One row per finding, built from the Summary Fields |
| `executive-summary.md` | Counts by severity, CWE spread, top findings |

Finding ids (`SECSCAN-0001`, ...) are assigned by pyscan in filing order and
are only unique within one run.

## Logs

| File | Contents |
|---|---|
| `local-run/logs/orchestrator.log` | One line per role and milestone |
| `local-run/logs/progress.log` | Every model turn and tool call |
| `local-run/logs/transcripts/` | Full transcript of each role |
| `work/` | Scratch output, such as raw semgrep JSON |
