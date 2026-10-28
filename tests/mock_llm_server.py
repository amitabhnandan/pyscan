"""A tiny OpenAI-compatible mock server for end-to-end testing.

It does NOT reason. It inspects the system prompt to see which role is asking,
then issues a deterministic sequence of tool calls (search -> write_hunt_file)
so the orchestrator, agent loop, tools, and artifact verification can all be
exercised without the real Qwen model. This is for CI/plumbing tests only.

Run: python3 tests/mock_llm_server.py --port 8099
"""
from __future__ import annotations

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Per-role canned output. Each entry: the .hunt path to write and its content.
# Keeps content minimal but structurally valid so the orchestrator's parsers
# (status lines, CONFIRMED ids, CSV) all have something to bite on.
_ROLE_OUTPUT = {
    "recon-cve-mapper": (
        ".hunt/cve-inventory.md",
        "# CVE Inventory -- Mock\n## Status: COMPLETE\n## Scope: mock\n\n"
        "## Hunt Priority Matrix\n### Tier 1 -- Hunt First\n"
        "- Deserialization: pickle.loads -> command exec\n",
    ),
    "recon-surface-mapper": (
        ".hunt/attack-surface.md",
        "# Attack Surface Map -- Mock\n## Status: COMPLETE\n## Trees scanned: .\n\n"
        "## High-value paths\n| Entry Point | Sink | Hop Count | Auth Seen? |\n"
        "|---|---|---|---|\n| app/routes.py:20 | "
        "app/db.py:15 | 2 | No |\n",
    ),
    "recon-test-gap": (
        ".hunt/test-gaps.md",
        "# Test Gap Analysis -- Mock\n## Status: COMPLETE\n\n"
        "## Recommended First 2 Hours for Hunt Agents\n1. routes.py -- no tests\n",
    ),
    "recon-test-gap": (
        ".hunt/test-gaps.md",
        "# Test Gap Analysis -- Mock\n## Status: COMPLETE\n\n"
        "## Recommended First 2 Hours for Hunt Agents\n1. routes.py -- no tests\n",
    ),
    "hunt-redteam": (
        ".hunt/candidates/iteration-{N}-candidates.md",
        "# Red Team Candidates -- Iteration {N}\n## Persona Used: Opportunist\n\n"
        "## STRONG Candidates\n### CAND-1-{N}\nHypothesis: SQL injection in login\n"
        "Entry Point: app/routes.py:20 via HTTP POST\n"
        "Sink: app/db.py:15 -- cur.execute\n"
        "Chain: routes.py:20 -> db.py:15\n\n"
        "## Files Reviewed This Iteration\napp/routes.py\n",
    ),
    "hunt-redteam-unconstrained": (
        ".hunt/candidates/iteration-{N}-candidates.md",
        "# Red Team Candidates -- Iteration {N}\n## Persona Used: Unconstrained\n\n"
        "## STRONG Candidates\n(none)\n\n## Files Reviewed This Iteration\nnone\n",
    ),
    "hunt-blueteam": (
        ".hunt/candidates/iteration-{N}-falsified.md",
        "# Blue Team Falsification -- Iteration {N}\n## CONFIRMED: 1\n\n"
        "## CONFIRMED Findings\n### CAND-1-{N} -- CONFIRMED\n"
        "Severity: 9.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n"
        "Config Dependency: DEFAULT_ON\nPromote to finding: YES\n",
    ),
    "hunt-filer": (
        "__FILER__",  # special-cased: append CSV + write bug + exec summary
        "",
    ),
}

_BLUE_TEAM_READS = ["app/routes.py", "app/db.py"]



# Distinctive phrases from each role body, checked most-specific first. Role
# bodies cross-reference each other by name, so matching on names is unreliable;
# these opening-line phrases are unique to each role.
_ROLE_MARKERS = [
    ("hunt-verifier", "reviewing findings before they are"),
    ("hunt-semgrep-triage", "triaging static-analysis results"),
    ("hunt-dep-reachability", "assessing known vulnerabilities in a"),
    ("hunt-redteam-unconstrained", "elite security researcher running the optional final"),
    ("hunt-blueteam", "trying to prove the red team is wrong"),
    ("hunt-filer", "you write confirmed security findings"),
    ("recon-cve-mapper", "threat intelligence analyst"),
    ("recon-surface-mapper", "mapping the attack surface of a large"),
    ("recon-test-gap", "identifying coverage gaps"),
    ("hunt-redteam", "you are a security researcher hunting for vulnerabilities"),
]


def _role_of(system_prompt: str) -> str:
    s = system_prompt.lower()
    for role, marker in _ROLE_MARKERS:
        if marker in s:
            return role
    return "hunt-filer"


def _iter_num(messages: list[dict]) -> str:
    for m in messages:
        mm = re.search(r"iteration[- ](\d+)", str(m.get("content", "")))
        if mm:
            return mm.group(1)
    return "1"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        if self.path.endswith("/models"):
            self._json({"data": [{"id": "mock-qwen"}]})
        else:
            self._json({"ok": True})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        messages = body.get("messages", [])
        system = next((m["content"] for m in messages if m.get("role") == "system"), "")
        role = _role_of(system)

        # If we've already written (a tool result is in the transcript), finish.
        tool_results = sum(1 for m in messages if m.get("role") == "tool")
        has_tool_result = tool_results > 0
        n = _iter_num(messages)

        # The blue team must open every cited file before confirming, or the
        # orchestrator's evidence gate demotes the verdict.
        reads_first = role in ("hunt-blueteam", "hunt-verifier")
        if reads_first and tool_results < len(_BLUE_TEAM_READS):
            self._chat_tool({"name": "read_file",
                             "arguments": {"path": _BLUE_TEAM_READS[tool_results]}})
        elif reads_first and tool_results == len(_BLUE_TEAM_READS):
            self._chat_tool(self._make_write_call(role, n, messages))
        elif not has_tool_result:
            tool_call = self._make_write_call(role, n, messages)
            self._chat_tool(tool_call)
        else:
            self._chat_text(f"{role} complete. Output written. DONE.")

    # -- response builders --------------------------------------------------

    def _make_write_call(self, role: str, n: str, messages: list[dict]) -> dict:
        task = next((str(m.get("content", "")) for m in messages if m.get("role") == "user"), "")
        target = re.search(r"Write (?:candidates to )?(\.hunt/\S+\.md)", task)
        if role == "hunt-verifier":
            ids = re.search(r"Verify findings? (.+?) \(", task)
            body = "# Verification -- mock\n"
            for cid in (ids.group(1).split(", ") if ids else []):
                body += (f"\n### {cid} -- VERIFIED\nExploit input: user=' OR '1'='1\nTrace:\n"
                         f"  Entry: app/routes.py:20 -- user\n"
                         f"  Sink:  app/db.py:15 -- cur.execute\n"
                         f"Launch: Flask route @app.post('/login') (app/routes.py:14)\n"
                         f"Input source: ATTACKER-CONTROLLED -- login form field "
                         f"(app/routes.py:20)\n"
                         f"Severity: 9.8 Critical CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -- unauthenticated\n"
                         f"Reason: concatenated SQL\n")
            return {"name": "write_hunt_file",
                    "arguments": {"path": target.group(1) if target else ".hunt/verified.md",
                                  "content": body}}
        if role in ("hunt-semgrep-triage", "hunt-dep-reachability"):
            return {"name": "write_hunt_file",
                    "arguments": {"path": target.group(1) if target else ".hunt/x.md",
                                  "content": "# Red Team Candidates -- mock\n## STRONG Candidates\n(none)\n"}}
        path, content = _ROLE_OUTPUT[role]
        if path == "__FILER__":
            return self._filer_call(messages)
        path = path.replace("{N}", n)
        content = content.replace("{N}", n)
        return {
            "name": "write_hunt_file",
            "arguments": {"path": path, "content": content},
        }

    def _filer_call(self, messages: list[dict]) -> dict:
        # One evidence pack under the id pyscan assigned; pyscan builds the
        # CSV row from its Summary Fields block.
        task = next((str(m.get("content", "")) for m in messages if m.get("role") == "user"), "")
        fid = re.search(r"as (SECSCAN-\d+)", task)
        fid = fid.group(1) if fid else "SECSCAN-0000"
        content = (
            f"# {fid}: SQL injection in login\n\n## Summary Fields\n"
            "title: SQL injection in login\ncwe_id: CWE-89\ncwe_name: SQL Injection\n"
            "cvss_score: 9.8\ncvss_severity: Critical\n"
            "cvss_vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n"
            "config_dependency: DEFAULT_ON\nevidence_status: CONFIRMED\n"
            "entry_point_file: app/routes.py\nentry_point_line: 20\n"
            "sink_file: app/db.py\nsink_line: 15\nmodule: app\n"
            "auth_required: None\nsummary: Login query built by string concat\n"
            "recommended_fix: Use prepared statements\nowner_area: app\nchain_hops: 2\n"
        )
        return {"name": "write_hunt_file",
                "arguments": {"path": f".hunt/findings/{fid}-sql-injection-login.md",
                              "content": content}}

    def _chat_tool(self, tool_call: dict):
        self._json({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": tool_call["name"],
                            "arguments": json.dumps(tool_call["arguments"]),
                        },
                    }],
                },
                "finish_reason": "tool_calls",
            }],
        })

    def _chat_text(self, text: str):
        self._json({
            "choices": [{
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }],
        })

    def _json(self, obj: dict):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"mock LLM on http://127.0.0.1:{args.port}/v1", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
