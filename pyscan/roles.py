"""Role registry: compose each role's system prompt.

Each role's review methodology lives in an agents/*.toml file, in a
`developer_instructions = \"\"\"...\"\"\"` block. For a role, this module:

  1. extracts the instructions with a regex (no tomllib -> runs on 3.10+),
  2. drops any section that only describes shell probes, child-agent spawning,
     or internet downloads -- none of which exist in this runtime,
  3. prepends an offline operating preamble that declares the fixed tool set
     and the tool-call protocol,
  4. appends any per-role override from runtime-prompts/overrides/<role>.md.

The orchestrator owns sequencing, state, and verification, so there is no
dispatcher role.
"""
from __future__ import annotations

import re
from pathlib import Path

from .agent import RoleSpec
from .config import RunContext

_DEV_INSTR = re.compile(
    r'developer_instructions\s*=\s*"""(.*?)"""', re.DOTALL
)

# Headings whose entire section is runtime plumbing (shell probes, child-agent
# contracts) and should be dropped from the prompt. Matched against "## <heading>" blocks.
_DROP_SECTIONS = {
    "Runtime Clarification",
    "Child Runtime Health Rules",
    "Nested agent-launch rule",
}

OFFLINE_PREAMBLE = """\
You are a worker agent in an OFFLINE local security-scan framework. You run on
a local model with no internet access and no shell. You interact with the
codebase ONLY through the tools provided to you in this session:

- list_dir, read_file, search: inspect the source tree (read only).
- run_semgrep: offline static scan with preconfigured local rulesets (when available).
- write_hunt_file: the ONLY way to persist output; it writes under .hunt/ only.

Rules for this runtime:
- You cannot run arbitrary shell commands, download anything, or reach the
  network. Any instruction in the methodology below that assumes a shell,
  `curl`, internet CVE research, or spawning other agents does NOT apply; use
  your tools and the on-disk briefing files instead.
- Persist every result with write_hunt_file. A result you only describe in
  chat is lost. Write the required output file(s) before you report completion.
- To call a tool, use the tool-calling interface. If you cannot, emit a single
  fenced block:
  ```tool_call
  {"tool": "read_file", "arguments": {"path": "app/main.py"}}
  ```
  and nothing else in that message.
- Keep going until your required output file exists and is complete, then print
  your completion signal. Do not ask the human questions; make the most
  reasonable assumption and record it in your output.

== PRODUCT AND RUN CONTEXT ==
__CONTEXT_BLOCK__

== REVIEW METHODOLOGY (this tool has no shell or internet; use the tools above) ==
"""


def _strip_runtime_sections(text: str) -> str:
    lines = text.splitlines()
    out: list[str] = []
    skip = False
    for line in lines:
        m = re.match(r"^#{1,3}\s+(.*)", line.strip())
        if m:
            heading = m.group(1).strip()
            skip = heading in _DROP_SECTIONS
        if not skip:
            out.append(line)
    cleaned = "\n".join(out)
    # Remove inline curl/download command blocks that the offline runtime can't use.
    cleaned = re.sub(
        r"curl -L https?://\S+\s+\\\s*\n\s*-o \S+",
        "# [offline: tool downloads are not available; use pre-bundled tools]",
        cleaned,
    )
    return cleaned


def _context_block(ctx: RunContext) -> str:
    p = ctx.product
    lines = [
        f"Product: {p.product_name}",
        f"Aliases: {', '.join(p.product_aliases) or 'not available'}",
        f"Versions in scope: {p.product_versions or 'not specified'}",
        f"Source roots: {', '.join(p.source_roots)}",
        f"Highest-value asset: {p.highest_value_asset or 'not specified'}",
        f"Known entry points: {', '.join(p.known_entry_points) or 'not specified'}",
        f"Hunt mode: {ctx.hunt_mode}",
        "CVE corpus: " + (", ".join(f"{lang} {path}" for lang, path in ctx.cve_corpus.items())
                          or "not available"),
        f"Semgrep available: {'yes' if ctx.semgrep_bin else 'no'}",
    ]
    if p.bootstrap_lines:
        lines.append("Bootstrap notes: " + " | ".join(p.bootstrap_lines))
    if p.extra_context_lines:
        lines.append("Extra context: " + " | ".join(p.extra_context_lines))
    return "\n".join(lines)


def _load_instructions(ctx: RunContext, toml_name: str) -> str:
    toml_path = ctx.agents_dir / toml_name
    raw = toml_path.read_text(encoding="utf-8")
    m = _DEV_INSTR.search(raw)
    if not m:
        raise RuntimeError(f"no developer_instructions found in {toml_name}")
    body = _strip_runtime_sections(m.group(1).strip())

    override_path = ctx.prompts_dir / "overrides" / (toml_name.replace(".toml", ".md"))
    override = ""
    if override_path.is_file():
        override = "\n\n== OFFLINE OVERRIDES (authoritative) ==\n" + override_path.read_text(
            encoding="utf-8"
        )

    preamble = OFFLINE_PREAMBLE.replace("__CONTEXT_BLOCK__", _context_block(ctx))
    return preamble + body + override


# role name -> (toml file, tools, required outputs relative to source repo, budget)
_ROLE_TABLE = {
    "recon-cve-mapper": (
        "recon-cve-mapper.toml",
        ["list_dir", "read_file", "search", "write_hunt_file"],
        [".hunt/cve-inventory.md"],
        80,  # room to read the CVE corpus index and its package files
    ),
    "recon-surface-mapper": (
        "recon-surface-mapper.toml",
        ["list_dir", "read_file", "search", "run_semgrep", "write_hunt_file"],
        [".hunt/attack-surface.md"],
        150,
    ),
    "recon-test-gap": (
        "recon-test-gap.toml",
        ["list_dir", "read_file", "search", "write_hunt_file"],
        [".hunt/test-gaps.md"],
        90,
    ),
    "hunt-redteam": (
        "hunt-redteam.toml",
        ["list_dir", "read_file", "search", "write_hunt_file"],
        [],  # output path is iteration-specific; set per call
        100,
    ),
    "hunt-redteam-unconstrained": (
        "hunt-redteam-unconstrained.toml",
        ["list_dir", "read_file", "search", "write_hunt_file"],
        [],
        80,
    ),
    "hunt-blueteam": (
        "hunt-blueteam.toml",
        ["list_dir", "read_file", "search", "write_hunt_file"],
        [],
        120,
    ),
    "hunt-verifier": (
        "hunt-verifier.toml",
        ["list_dir", "read_file", "search", "write_hunt_file"],
        [],
        80,
    ),
    "hunt-semgrep-triage": (
        "hunt-semgrep-triage.toml",
        ["list_dir", "read_file", "search", "write_hunt_file"],
        [],
        60,
    ),
    "hunt-dep-reachability": (
        "hunt-dep-reachability.toml",
        ["list_dir", "read_file", "search", "write_hunt_file"],
        [],
        60,
    ),
    "hunt-filer": (
        "hunt-filer.toml",
        ["list_dir", "read_file", "search", "write_hunt_file"],
        [],
        60,
    ),
}


def build_role(
    ctx: RunContext,
    name: str,
    *,
    required_outputs: list[str] | None = None,
) -> RoleSpec:
    if name not in _ROLE_TABLE:
        raise KeyError(f"unknown role: {name}")
    toml_name, tools, default_outputs, budget = _ROLE_TABLE[name]
    system_prompt = _load_instructions(ctx, toml_name)
    return RoleSpec(
        name=name,
        system_prompt=system_prompt,
        tools=tools,
        required_outputs=required_outputs
        if required_outputs is not None
        else default_outputs,
        max_tool_calls=budget,
    )


def available_roles(ctx: RunContext) -> list[str]:
    return [n for n in _ROLE_TABLE if (ctx.agents_dir / _ROLE_TABLE[n][0]).is_file()]
