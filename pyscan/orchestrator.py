"""Deterministic hunt orchestrator.

Orchestration is ordinary Python, not an LLM session: it owns state.json,
writes the iteration briefs, invokes each worker role in order, verifies
artifacts on disk, and runs caller propagation. The model is used only for
the security reasoning inside each worker role.

Keeping sequencing, iteration state, scope briefs, artifact-integrity checks,
caller propagation, and completion in code -- rather than asking a model to
police itself -- makes a run reproducible and keeps a confused model from
derailing the control flow.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
from pathlib import Path

from . import cve_corpus, findings, git_history, sweep
from .agent import Agent, RoleResult
from .config import RunContext
from .llm import LocalLLM
from .roles import available_roles, build_role
from .tools import ToolContext

ITERATIONS = {
    1: ("Opportunist -- Default Config, No Credentials",
        "opportunist",
        "What can be reached and exploited right now with zero friction?",
        "Tier 1 DEFAULT_ON targets, standard HTTP entry points, obvious dangerous sinks"),
    2: ("Insider -- Authenticated Standard User",
        "insider",
        "What can a logged-in standard user do that they should not be able to do?",
        "authenticated endpoints, RBAC seams, IDOR, privilege-boundary operations"),
    3: ("Chainer -- Hardening Gap Hunter",
        "chainer",
        "Where did hardening leave a gap that still accepts the dangerous form?",
        "recent security fixes and the code around them, sibling methods missing a validator"),
    4: ("Chainer -- Corner Case Hunter",
        "chainer",
        "Where would a vulnerability hide that only manifests under specific conditions?",
        "error/exception paths, admin endpoints, deprecated fallbacks, concurrency paths"),
}

# path/to/file.ext:123 as cited in candidate and falsification chains.
_FILE_LINE = re.compile(r"([A-Za-z0-9_][A-Za-z0-9_./-]*\.[A-Za-z0-9]+):(\d+)")
# Wording that marks a chain hop as guessed rather than read.
_ASSUMED = re.compile(r"assum|not provided|not shown|presumab|likely|unknown", re.I)


def _first_file_line(lines: list[str]) -> tuple[str, str] | None:
    for line in lines:
        m = _FILE_LINE.search(line)
        if m:
            return m.group(1), m.group(2)
    return None


def _first_cwe(text: str) -> str:
    m = re.search(r"CWE-\d+", text)
    return m.group(0) if m else ""


def _deployment_reasons(ver_section: str) -> list[str]:
    """A VERIFIED verdict must say how the component is launched and where
    the input comes from, each cited as file:line, and the input must be
    attacker-controlled."""
    reasons = []
    for prefix in ("Launch:", "Input source:"):
        lines = _chain_lines(ver_section, (prefix,))
        if not any(_FILE_LINE.search(line) for line in lines):
            reasons.append(f"no '{prefix}' line cited as file:line")
    source = " ".join(_chain_lines(ver_section, ("Input source:",)))
    if source and "ATTACKER-CONTROLLED" not in source.upper():
        reasons.append("input source is not attacker-controlled")
    return reasons


def _track_of(label: str) -> tuple[str, str, str]:
    """(hunt_track, persona, iteration) for a pass label."""
    if label.startswith("iteration "):
        n = label.split()[1]
        persona = {"1": "opportunist", "2": "insider", "3": "chainer", "4": "chainer",
                   "5": "unconstrained"}.get(n, "redteam")
        return "source", persona, n
    if label.startswith("semgrep"):
        return "source", "semgrep-triage", "S"
    if label.startswith("dependency"):
        return "source", "dependency", "D"
    return "source", "redteam", "?"


def _env_int(name: str, default: int) -> int:
    try:
        return max(0, int(os.environ.get(name, default)))
    except ValueError:
        return default


def name_is_hardening(n: int) -> bool:
    """Iterations whose persona hunts for gaps left by past fixes."""
    return n in ITERATIONS and "Hardening" in ITERATIONS[n][0]


def _section(text: str, cid: str) -> str:
    """Body of the '### <cid> ...' block in a candidates or falsified file."""
    m = re.search(
        rf"^#+\s*{re.escape(cid)}(?![\w-])[^\n]*\n(.*?)(?=^#|\Z)", text, re.M | re.S
    )
    return m.group(1) if m else ""


def _chain_lines(section: str, prefixes: tuple[str, ...]) -> list[str]:
    lines = (line.strip() for line in section.splitlines())
    return [line for line in lines if line.startswith(prefixes)]


def _norm(path: str) -> str:
    return os.path.normpath(path.strip().strip("`")).replace("\\", "/")


class Orchestrator:
    def __init__(self, ctx: RunContext):
        self.ctx = ctx
        self.llm = LocalLLM(ctx.llm)
        self.log = _Logger(ctx.hunt_dir / "local-run" / "logs")

    # -- lifecycle ----------------------------------------------------------

    def run(self) -> int:
        self.ctx.hunt_dir.mkdir(parents=True, exist_ok=True)
        (self.ctx.hunt_dir / "candidates").mkdir(exist_ok=True)
        (self.ctx.hunt_dir / "findings").mkdir(exist_ok=True)
        self._preflight()

        mode = self.ctx.hunt_mode
        self.log.info(f"hunt mode: {mode}")

        if mode in ("RECON_ONLY", "FULL_48H"):
            self._run_recon()
        if mode in ("HUNT_ONLY", "FULL_48H"):
            self._run_source_hunt()

        self._completion()
        return 0

    def _preflight(self) -> None:
        if not self.llm.health():
            raise SystemExit(
                f"HUNT BLOCKED: local model endpoint not reachable at "
                f"{self.ctx.llm.base_url}. Start the model server first "
                f"(see sandbox/README) and retry."
            )
        roles = available_roles(self.ctx)
        self.log.info(f"local model healthy; {len(roles)} role definitions present")

    # -- agent factory ------------------------------------------------------

    def _agent(self, *, extra_reads: list[Path] | None = None) -> Agent:
        tool_ctx = ToolContext(
            source_repo=self.ctx.source_repo,
            hunt_dir=self.ctx.hunt_dir,
            semgrep_bin=self.ctx.semgrep_bin,
            semgrep_rulesets=self.ctx.semgrep_rulesets,
            semgrep_rules_cache=self.ctx.semgrep_rules_cache,
            offline=self.ctx.offline,
            extra_read_roots=extra_reads or [],
        )
        return Agent(
            self.llm, tool_ctx,
            log_dir=self.log.dir / "transcripts",
            progress=self.log.progress,
        )

    def _invoke(self, result: RoleResult) -> RoleResult:
        status = "OK" if result.ok else "INCOMPLETE"
        self.log.info(
            f"role {result.name}: {status} ({result.tool_calls_used} tool calls) -- {result.reason}"
        )
        return result

    # -- recon --------------------------------------------------------------

    def _run_recon(self) -> None:
        if git_history.summarize(self.ctx.source_repo, self.ctx.hunt_path("git-history.md")):
            self.log.info("git history summary written to .hunt/git-history.md")
        else:
            self.log.info("no git history in the source repo; history-based prioritisation skipped")
        corpus = list(self.ctx.cve_corpus.values())

        inv = self.ctx.hunt_path("cve-inventory.md")
        if inv.is_file() and "## Status: COMPLETE" in inv.read_text(encoding="utf-8"):
            self.log.info("reusing existing COMPLETE cve-inventory.md")
        else:
            spec = build_role(self.ctx, "recon-cve-mapper")
            if self.ctx.cve_corpus:
                where = "\n".join(
                    f"- {lang}: {path} (read {path}/INDEX.md first)" if lang != "any"
                    else f"- {path}"
                    for lang, path in self.ctx.cve_corpus.items()
                )
                source = (
                    "using ONLY the offline CVE corpus for this repository and the "
                    "source tree. Corpus folders (read them with read_file using "
                    f"these absolute paths):\n{where}\n"
                    "Each INDEX.md lists the libraries in use, their versions, and "
                    "the advisories that affect them; its package files give each "
                    "library's advisory history. Cite corpus file paths as sources. "
                )
            else:
                source = (
                    "from the source tree only: no offline CVE corpus is available, "
                    "so derive a class-history inventory from the product category "
                    "and the frameworks visible in the code, and mark it clearly. "
                )
            task = (
                f"Build .hunt/cve-inventory.md for this product {source}"
                "Do not attempt internet research. End with '## Status: COMPLETE' "
                "or '## Status: PARTIAL'."
            )
            self._invoke(self._agent(extra_reads=corpus).run_role(spec, task))

        swept = sweep.run(self.ctx, self.log.info)
        spec = build_role(self.ctx, "recon-surface-mapper")
        if swept:  # the sweep covered every root; re-running semgrep wastes the budget
            spec.tools = [t for t in spec.tools if t != "run_semgrep"]
        self._invoke(self._agent().run_role(
            spec,
            "Map the attack surface into .hunt/attack-surface.md. Use search and "
            "read_file across the configured source roots"
            + (f". pyscan already ran semgrep over every source root: "
               f".hunt/semgrep-findings.md lists {len(swept)} matches; use them as "
               "leads for sinks and entry points instead of re-running the full set"
               if swept else "; use run_semgrep in sharded passes if available")
            + ". End with a Status line.",
        ))

        spec = build_role(self.ctx, "recon-test-gap")
        self._invoke(self._agent().run_role(
            spec,
            "Produce .hunt/test-gaps.md from the attack surface and CVE inventory"
            + (" and the version history in .hunt/git-history.md"
               if self.ctx.hunt_path("git-history.md").is_file()
               else "; there is no git history, so skip Step 5 and say so")
            + ". End with '## Status: COMPLETE'.",
        ))

    # -- source hunt loop ---------------------------------------------------

    def _run_source_hunt(self) -> None:
        self._require_recon()
        state = self._load_state()
        max_iter = 5 if self.ctx.unconstrained_requested else 4

        self._semgrep_triage_pass()
        self._dependency_pass()
        self._update_confirmed_paths(state)
        self._save_state(state)

        for n in range(1, max_iter + 1):
            if n == 5 and not self.ctx.unconstrained_requested:
                break
            self._write_brief(n, state)
            role_name = "hunt-redteam-unconstrained" if n == 5 else "hunt-redteam"
            cand = f".hunt/candidates/iteration-{n}-candidates.md"
            fals = f".hunt/candidates/iteration-{n}-falsified.md"

            rt = build_role(self.ctx, role_name, required_outputs=[cand])
            self._invoke(self._agent().run_role(
                rt, f"Run red team iteration {n}. Read .hunt/iteration-{n}-brief.md "
                    f"first, then the recon package. Write candidates to {cand}."))

            filed = self._falsify_and_file(f"iteration {n}", cand, fals)

            state["iteration"] = n
            state["confirmed_this_iteration"] = filed
            self._update_confirmed_paths(state)
            self._caller_propagation(state)
            self._save_state(state)

        state["status"] = "complete"
        self._save_state(state)

    # -- falsify, verify, file ---------------------------------------------

    def _falsify_and_file(self, label: str, cand: str, fals: str,
                          extra_reads: list[Path] | None = None) -> int:
        """Blue team, evidence gate, one verifier run per confirmed finding,
        then filing. Returns how many findings were filed."""
        if not self._has_candidates(cand):
            self.log.info(f"{label}: no candidates to evaluate")
            return 0
        bt = build_role(self.ctx, "hunt-blueteam", required_outputs=[fals])
        bt_result = self._invoke(self._agent(extra_reads=extra_reads).run_role(
            bt, f"Falsify the candidates in {cand}. Write {fals}."))
        self._gate_confirmations(cand, fals, bt_result)
        confirmed = self._confirmed_ids(fals)
        if not confirmed:
            return 0

        verified = []
        for k, cid in enumerate(confirmed, 1):
            ver = fals.replace("-falsified.md", f"-verified-{k}.md")
            vr = build_role(self.ctx, "hunt-verifier", required_outputs=[ver])
            vr_result = self._invoke(self._agent(extra_reads=extra_reads).run_role(
                vr,
                f"Verify finding {cid} ({label}). Candidates: {cand}. "
                f"Blue-team verdicts: {fals}. Write {ver}."))
            if self._verified_ids(cand, ver, [cid], vr_result):
                verified.append((cid, ver))
        self.log.info(f"{label}: {len(confirmed)} confirmed, {len(verified)} verified")

        filed = 0
        for cid, ver in verified:
            if self._file_finding(cid, label, [fals, ver, cand], extra_reads=extra_reads):
                filed += 1
        return filed

    def _file_finding(self, cid: str, label: str, sources: list[str],
                      extra_reads: list[Path] | None = None) -> bool:
        """Have the filer write one evidence pack under an id chosen here,
        then record it in the CSV and executive summary in code."""
        hunt = self.ctx.hunt_dir
        rows = findings.read_rows(hunt)
        cand_text = self._hunt_file(sources[-1]).read_text(encoding="utf-8") \
            if self._hunt_file(sources[-1]).is_file() else ""
        sink = _first_file_line(_chain_lines(_section(cand_text, cid), ("Sink:",)))
        cwe = _first_cwe(_section(cand_text, cid))
        dup = findings.duplicate_of(rows, *sink, cwe) if sink else ""
        if dup:
            self.log.info(f"{label}: {cid} duplicates {dup}; not filed again")
            return False

        fid = findings.next_id(hunt)
        fdir = hunt / "findings"
        fdir.mkdir(exist_ok=True)
        before = set(fdir.glob("*.md"))
        filer = build_role(self.ctx, "hunt-filer")
        self._invoke(self._agent(extra_reads=extra_reads).run_role(
            filer,
            f"File finding {cid} from {label} as {fid}. Read {', '.join(sources)} and "
            f"re-read the cited source. Write exactly one file: "
            f".hunt/findings/{fid}-<short-slug>.md, ending with the '## Summary Fields' "
            f"block. Use the severity from the verification file."))
        new = sorted(set(fdir.glob("*.md")) - before)
        packs = [f for f in new if f.name.startswith(f"{fid}-")]
        strays = [f for f in new if f not in packs[:1]]
        if strays:
            findings.set_aside(strays, hunt, f"written while filing {fid} ({cid}); not its evidence pack")
            self.log.info(f"filer: set aside {len(strays)} extra file(s) in .hunt/work/discarded-filings")
        if not packs:
            self.log.info(f"filer wrote no {fid} evidence pack for {cid}; not filed")
            return False
        pack = packs[0]
        text = pack.read_text(encoding="utf-8")
        row = findings.parse_summary_fields(text)
        ver_text = self._hunt_file(sources[1]).read_text(encoding="utf-8") \
            if len(sources) > 2 and self._hunt_file(sources[1]).is_file() else ""
        row.update(findings.parse_severity(_section(ver_text, cid) or ver_text))
        dup = findings.duplicate_of(rows, row.get("sink_file", ""), row.get("sink_line", ""),
                                    row.get("cwe_id", ""))
        if dup:
            findings.set_aside([pack], hunt, f"duplicate of {dup}")
            self.log.info(f"{label}: {cid} duplicates {dup}; evidence pack set aside")
            return False
        track, persona, iteration = _track_of(label)
        row.update({
            "finding_id": fid, "filed_date": _dt.date.today().isoformat(),
            "iteration": iteration, "hunt_track": track, "persona": persona,
        })
        findings.append_row(hunt, row)
        findings.write_executive_summary(hunt, self.ctx.product.product_name, self.ctx.hunt_mode)
        self.log.info(f"filed {fid} ({cid}, {label}): {row.get('cvss_severity', '?')} "
                      f"{row.get('title', '')[:80]}")
        return True

    def _has_candidates(self, cand_rel: str) -> bool:
        path = self._hunt_file(cand_rel)
        return path.is_file() and bool(
            re.search(r"^#+\s*CAND-", path.read_text(encoding="utf-8"), re.M))

    def _verified_ids(self, cand_rel: str, ver_rel: str,
                      confirmed: list[str], vr: RoleResult) -> list[str]:
        """Confirmed ids the verifier marked VERIFIED and backed with files it
        opened. Anything else is not filed."""
        ver_path = self._hunt_file(ver_rel)
        if not ver_path.is_file():
            self.log.info(f"verifier wrote no {ver_rel}; nothing from it is filed")
            return []
        ver_text = ver_path.read_text(encoding="utf-8")
        cand_text = self._hunt_file(cand_rel).read_text(encoding="utf-8")
        opened = self._files_opened(vr)
        verified, notes = [], []
        for cid in confirmed:
            m = re.search(rf"{re.escape(cid)}\s*--\s*(VERIFIED|REJECTED|UNCERTAIN)\b", ver_text)
            verdict = m.group(1) if m else "MISSING"
            if verdict != "VERIFIED":
                self.log.info(f"verifier: {cid} {verdict.lower()}; not filed")
                continue
            ver_section = _section(ver_text, cid)
            reasons = self._unproven_reasons(
                _chain_lines(_section(cand_text, cid), ("Entry Point:", "Sink:", "Chain:")),
                _chain_lines(ver_section, ("Entry:", "Hop:", "Sink:")),
                opened,
                who="verifier",
            )
            reasons += _deployment_reasons(ver_section)
            if reasons:
                notes.append(f"- {cid}: " + "; ".join(reasons))
                self.log.info(f"evidence gate: verifier's {cid} treated as uncertain -- {'; '.join(reasons)}")
                continue
            verified.append(cid)
        if notes:
            ver_path.write_text(
                ver_text + "\n\n## Orchestrator Evidence Check\n"
                "These VERIFIED verdicts were treated as UNCERTAIN and not filed:\n"
                + "\n".join(notes) + "\n", encoding="utf-8")
        return verified

    # -- extra hunt passes --------------------------------------------------

    def _semgrep_triage_pass(self) -> None:
        matches = sweep.load(self.ctx.hunt_dir)
        if not matches:
            self.log.info("semgrep triage skipped: no sweep matches")
            return
        limit = _env_int("PYSCAN_SEMGREP_TRIAGE_MAX", 60)
        size = max(1, _env_int("PYSCAN_SEMGREP_BATCH", 20))
        chosen = matches[:limit]
        if len(matches) > limit:
            self.log.info(f"semgrep triage: {len(matches)} matches, triaging the {limit} most severe")
        for b, start in enumerate(range(0, len(chosen), size), 1):
            batch = chosen[start:start + size]
            ids = ", ".join(m["id"] for m in batch)
            cand = f".hunt/candidates/semgrep-{b}-candidates.md"
            spec = build_role(self.ctx, "hunt-semgrep-triage", required_outputs=[cand])
            self._invoke(self._agent().run_role(
                spec,
                f"Triage semgrep batch {b}: matches {ids}. Read them in "
                f".hunt/semgrep-findings.md, then the code. Number candidates "
                f"CAND-1-S{b}, CAND-2-S{b}, ... Write candidates to {cand}."))
            self._falsify_and_file(f"semgrep batch {b}", cand,
                                   f".hunt/candidates/semgrep-{b}-falsified.md")

    def _dependency_pass(self) -> None:
        targets = []
        for lang, path in self.ctx.cve_corpus.items():
            if lang != "any":
                targets += [(lang, path, lib) for lib in cve_corpus.reachability_targets(path)]
        if not targets:
            self.log.info("dependency pass skipped: no affected libraries in the CVE corpus")
            return
        limit = _env_int("PYSCAN_DEP_MAX_PACKAGES", 8)
        for p, (lang, path, lib) in enumerate(targets[:limit], 1):
            advisories = "; ".join(f"{a['id']} [{a['severity']}]" for a in lib["advisories"])
            cand = f".hunt/candidates/deps-{p}-candidates.md"
            spec = build_role(self.ctx, "hunt-dep-reachability", required_outputs=[cand])
            self._invoke(self._agent(extra_reads=[path]).run_role(
                spec,
                f"Check dependency {lib['package']} {lib['version']} ({lang}), package "
                f"number {p}. Advisories affecting this version: {advisories}. Advisory "
                f"details: {lib['file']} (read with read_file). Number candidates "
                f"CAND-1-D{p}, CAND-2-D{p}, ... Write candidates to {cand}."))
            self._falsify_and_file(f"dependency {lib['package']}", cand,
                                   f".hunt/candidates/deps-{p}-falsified.md",
                                   extra_reads=[path])

    # -- evidence gate ------------------------------------------------------

    def _gate_confirmations(self, cand_rel: str, fals_rel: str, bt: RoleResult) -> None:
        """Demote CONFIRMED/DOWNGRADED verdicts the blue team did not prove.

        A local model will confirm a candidate it never read, so the bar is
        checked here rather than trusted: the chain must cite an entry point
        and a sink as file:line in the source tree, must not rest on an
        assumed hop, and every cited source file must have been opened with
        read_file during the blue-team role.
        """
        cand_path, fals_path = self._hunt_file(cand_rel), self._hunt_file(fals_rel)
        if not fals_path.is_file():
            return
        cand_text = cand_path.read_text(encoding="utf-8") if cand_path.is_file() else ""
        fals_text = fals_path.read_text(encoding="utf-8")
        opened = self._files_opened(bt)
        notes = []
        for cid in self._confirmed_ids(fals_rel):
            reasons = self._unproven_reasons(
                _chain_lines(_section(cand_text, cid), ("Entry Point:", "Sink:", "Chain:")),
                _chain_lines(_section(fals_text, cid), ("Entry:", "Hop:", "Sink:")),
                opened,
            )
            if not reasons:
                continue
            fals_text = re.sub(
                rf"({re.escape(cid)})\s*--\s*(CONFIRMED|DOWNGRADED)\b",
                r"\1 -- INSUFFICIENT EVIDENCE (auto-demoted)",
                fals_text,
            )
            notes.append(f"- {cid}: " + "; ".join(reasons))
            self.log.info(f"evidence gate: demoted {cid} -- {'; '.join(reasons)}")
        if notes:
            fals_text += (
                "\n\n## Orchestrator Evidence Check\n"
                "These verdicts were demoted to INSUFFICIENT EVIDENCE and will not "
                "be filed:\n" + "\n".join(notes) + "\n"
            )
            fals_path.write_text(fals_text, encoding="utf-8")

    def _unproven_reasons(
        self, cand_lines: list[str], fals_lines: list[str], opened: set[str],
        who: str = "blue team",
    ) -> list[str]:
        reasons = []
        chain = cand_lines + fals_lines
        if any(_ASSUMED.search(line) for line in chain):
            reasons.append("chain relies on an assumed or unread hop")
        cited = {
            p for p, _ in _FILE_LINE.findall("\n".join(chain))
            if (self.ctx.source_repo / p).is_file()
        }
        entry = [l for l in chain if l.startswith(("Entry Point:", "Entry:"))]
        sink = [l for l in chain if l.startswith("Sink:")]
        if not any(_FILE_LINE.search(l) for l in entry) or not any(
            _FILE_LINE.search(l) for l in sink
        ):
            reasons.append("entry point or sink is not cited as file:line")
        unread = sorted(p for p in cited if _norm(p) not in opened)
        if unread:
            reasons.append(f"{who} never opened " + ", ".join(unread))
        return reasons

    def _files_opened(self, result: RoleResult) -> set[str]:
        repo = str(self.ctx.source_repo)
        opened = set()
        for m in result.transcript:
            for call in m.get("tool_calls") or []:
                fn = call.get("function", {})
                if fn.get("name") != "read_file":
                    continue
                try:
                    path = json.loads(fn.get("arguments") or "{}").get("path")
                except json.JSONDecodeError:
                    continue
                if not path:
                    continue
                if path.startswith(repo + "/"):
                    path = path[len(repo) + 1:]
                opened.add(_norm(path))
        return opened

    def _hunt_file(self, rel: str) -> Path:
        s = rel.replace("\\", "/")
        if s.startswith(".hunt/"):
            return self.ctx.hunt_dir / s[len(".hunt/"):]
        return self.ctx.source_repo / rel

    # -- briefs & state -----------------------------------------------------

    def _write_brief(self, n: int, state: dict) -> None:
        if n == 5:
            name, persona = "Unconstrained -- Final High-Entropy Pass", "unconstrained"
            question = "What still looks real after the structured passes?"
            focus = "suspicious targets and insufficient-evidence followups from state.json"
        else:
            name, persona, question, focus = ITERATIONS[n]
        confirmed = state.get("confirmed_finding_paths", [])
        carry = state.get("finding_carryover_files", [])
        lines = [
            f"# Hunt Iteration {n} -- {name}",
            "",
            "## What This Pass Is Looking For",
            question,
            "",
            "## Attacker Persona For This Iteration",
            f"Persona: {persona}. Read every file in scope through this attacker's eyes.",
            "",
            "## Already Confirmed -- Do Not Re-file These Exact Chains",
            *( [f"- {c}" for c in confirmed] or ["None yet"] ),
            "",
            "## Priority Carryover From Confirmed Findings",
        ]
        if carry:
            lines.append("| File | Reason | Finding |")
            lines.append("|------|--------|---------|")
            for c in carry:
                lines.append(f"| {c['file']} | {c['reason']} | {c['finding_id']} |")
        else:
            lines.append("No new caller propagation targets.")
        lines += [
            "",
            "## Focus Areas For This Iteration",
            focus,
            "",
            "## Priority Targets From Briefing Package",
            "Read .hunt/attack-surface.md High-value paths and .hunt/cve-inventory.md Tier 1.",
            *self._history_brief(n),
            "",
            "Full surface is in scope. The persona changes what question is asked of each file.",
        ]
        self.ctx.hunt_path(f"iteration-{n}-brief.md").write_text(
            "\n".join(lines), encoding="utf-8"
        )

    def _history_brief(self, n: int) -> list[str]:
        if not self.ctx.hunt_path("git-history.md").is_file():
            return []
        lines = [
            "Version history: .hunt/git-history.md lists recently changed and added "
            "files and commits that look like security fixes.",
        ]
        if name_is_hardening(n):
            lines.append(
                "This pass hunts hardening gaps: start from those security-fix commits "
                "and check sibling code for the same flaw left unfixed.")
        return lines

    def _load_state(self) -> dict:
        path = self.ctx.hunt_path("state.json")
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        return {
            "product": self.ctx.product.product_name,
            "roots": self.ctx.product.source_roots,
            "optional_keywords": self.ctx.optional_keywords,
            "unconstrained_redteam_requested": self.ctx.unconstrained_requested,
            "iteration": 0,
            "max_iterations": 5 if self.ctx.unconstrained_requested else 4,
            "confirmed_finding_paths": [],
            "finding_carryover_files": [],
            "confirmed_findings_total": 0,
            "status": "running",
        }

    def _save_state(self, state: dict) -> None:
        self.ctx.hunt_path("state.json").write_text(
            json.dumps(state, indent=2), encoding="utf-8"
        )

    def _update_confirmed_paths(self, state: dict) -> None:
        rows = self._read_csv()
        chains = []
        for r in rows:
            ep = f"{r.get('entry_point_file')}:{r.get('entry_point_line')}"
            sink = f"{r.get('sink_file')}:{r.get('sink_line')}"
            chains.append(f"{ep} -> {sink}")
        state["confirmed_finding_paths"] = sorted(set(chains))
        state["confirmed_findings_total"] = len(rows)

    def _caller_propagation(self, state: dict) -> None:
        """Find direct callers of confirmed entry/sink classes and queue them as
        priority-1 carryover for the next brief. Pure repo search, no model."""
        rows = self._read_csv()
        carry = state.get("finding_carryover_files", [])
        known = {c["file"] for c in carry}
        import subprocess
        import shutil
        rg = shutil.which("rg")
        for r in rows:
            for col in ("entry_point_file", "sink_file"):
                f = r.get(col) or ""
                cls = Path(f).stem
                if not cls:
                    continue
                try:
                    if rg:
                        out = subprocess.run(
                            [rg, "-l", rf"\b{re.escape(cls)}\b", str(self.ctx.source_repo),
                             "--glob", "*.py"],
                            capture_output=True, text=True, timeout=60, check=False,
                        ).stdout
                    else:
                        out = subprocess.run(
                            ["grep", "-rlw", "--include=*.py", cls, str(self.ctx.source_repo)],
                            capture_output=True, text=True, timeout=60, check=False,
                        ).stdout
                except (subprocess.TimeoutExpired, OSError):
                    continue
                for caller in out.splitlines()[:5]:
                    rel = caller.replace(str(self.ctx.source_repo) + "/", "")
                    if rel and rel != f and rel not in known:
                        known.add(rel)
                        carry.append({
                            "file": rel,
                            "reason": f"caller of {r.get('finding_id')} ({cls})",
                            "finding_id": r.get("finding_id", "?"),
                        })
        state["finding_carryover_files"] = carry

    # -- helpers ------------------------------------------------------------

    def _require_recon(self) -> None:
        # test-gaps.md only sharpens priorities; the hunt can run without it.
        if not self.ctx.hunt_path("test-gaps.md").is_file():
            self.log.info("test-gaps.md missing; hunting without test-gap priorities")
        missing = [
            f for f in ("cve-inventory.md", "attack-surface.md")
            if not self.ctx.hunt_path(f).is_file()
        ]
        if missing:
            raise SystemExit(
                f"HUNT BLOCKED: recon package incomplete, missing {missing}. "
                f"Run with --hunt-mode RECON_ONLY first, or FULL_48H."
            )

    def _read_csv(self) -> list[dict]:
        return findings.read_rows(self.ctx.hunt_dir)

    def _confirmed_ids(self, rel: str) -> list[str]:
        s = rel.replace("\\", "/")
        if s.startswith(".hunt/"):
            path = self.ctx.hunt_dir / s[len(".hunt/"):]
        else:
            path = self.ctx.source_repo / rel
        if not path.is_file():
            return []
        text = path.read_text(encoding="utf-8")
        ids = []
        for m in re.finditer(
            r"(CAND-[0-9A-Za-z\[\]-]+)\s*--\s*(CONFIRMED|DOWNGRADED)", text
        ):
            ids.append(m.group(1))
        return sorted(set(ids))

    def _completion(self) -> None:
        rows = self._read_csv()
        summary = [
            "HUNT COMPLETE",
            f"Mode: {self.ctx.hunt_mode}",
            f"Confirmed findings filed: {len(rows)}",
            f"See: {self.ctx.hunt_path('findings-summary.csv')}",
            f"See: {self.ctx.hunt_path('executive-summary.md')}",
        ]
        self.log.info("\n".join(summary))
        print("\n".join(summary))


class _Logger:
    """orchestrator.log holds role-level milestones; progress.log holds those
    plus every model turn and tool call, for `tail -f` during a long run."""

    def __init__(self, dir: Path):
        self.dir = dir
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "orchestrator.log"
        self.progress_path = self.dir / "progress.log"

    def info(self, msg: str) -> None:
        line = self._emit(msg)
        self._append(self.path, line)

    def progress(self, msg: str) -> None:
        self._emit(msg)

    def _emit(self, msg: str) -> str:
        stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        line = f"[{stamp}] {msg}"
        print(line, flush=True)
        self._append(self.progress_path, line)
        return line

    @staticmethod
    def _append(path: Path, line: str) -> None:
        try:
            with path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass
