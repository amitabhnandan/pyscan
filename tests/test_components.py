"""Component tests that need no model. Run: python3 tests/test_components.py"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pyscan.tools import ToolContext, ToolError, t_read_file, t_search, t_write_hunt_file
from pyscan.llm import LocalLLM
from pyscan.config import LLMConfig

FIX = ROOT / "tests" / "fixtures" / "vuln-app"


def _ctx(tmp_hunt: Path) -> ToolContext:
    return ToolContext(
        source_repo=FIX, hunt_dir=tmp_hunt,
        semgrep_bin=None, semgrep_rulesets=[],
    )


def test_path_escape_blocked(tmp_path):
    ctx = _ctx(tmp_path)
    for bad in ["../../../../etc/passwd", "/etc/passwd"]:
        try:
            t_read_file(ctx, {"path": bad})
            raise AssertionError(f"escape not blocked: {bad}")
        except ToolError:
            pass
    print("ok: path escape blocked")


def test_write_confined_to_hunt(tmp_path):
    ctx = _ctx(tmp_path)
    # writing into source repo must be refused; only .hunt is writable
    try:
        t_write_hunt_file(ctx, {"path": str(FIX / "app/x.py"), "content": "x"})
        raise AssertionError("write outside .hunt not blocked")
    except ToolError:
        pass
    msg = t_write_hunt_file(ctx, {"path": str(tmp_path / "out.md"), "content": "hello"})
    assert "wrote" in msg
    print("ok: writes confined to .hunt")


def test_search_finds_sink(tmp_path):
    ctx = _ctx(tmp_path)
    out = t_search(ctx, {"pattern": "cur[.]execute", "globs": ["*.py"]})
    assert "app/db.py:15" in out, out
    print("ok: search finds the SQL sink")


def test_search_alternation_case_and_dep_dirs(tmp_path):
    import shutil
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / ".venv" / "lib").mkdir(parents=True)
    (repo / "app" / "run.py").write_text("import subprocess\nsubprocess.run(cmd, shell=True)\n")
    (repo / ".venv" / "lib" / "dep.py").write_text("subprocess.run(x, shell=True)\n")
    ctx = ToolContext(source_repo=repo, hunt_dir=tmp_path / "hunt",
                      semgrep_bin=None, semgrep_rulesets=[])
    for pat in ["os[.]system|shell=True", "os.system\\|shell=True"]:
        out = t_search(ctx, {"pattern": pat, "globs": ["*.py"]})
        assert "app/run.py:2" in out, (pat, out)
        assert ".venv" not in out, out
    out = t_search(ctx, {"pattern": "SHELL=TRUE", "globs": ["*.py"], "ignore_case": True})
    assert "app/run.py" in out, out
    shutil.rmtree(repo)
    print("ok: search handles | and \\| alternation, ignore_case, skips .venv")


def test_source_search_is_python_only(tmp_path):
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "run.py").write_text("eval(user_input)\n")
    (repo / "web").mkdir()
    (repo / "web" / "app.js").write_text("eval(userInput)\n")
    hunt = repo / ".hunt"
    hunt.mkdir()
    (hunt / "notes.md").write_text("eval seen in run.py\n")
    ctx = ToolContext(source_repo=repo, hunt_dir=hunt, semgrep_bin=None, semgrep_rulesets=[])
    for globs in ([], ["*.js"], ["*.js", "*.py"]):
        out = t_search(ctx, {"pattern": "eval", "globs": globs})
        assert "app/run.py:1" in out and "app.js" not in out and "notes.md" not in out, (globs, out)
    out = t_search(ctx, {"pattern": "eval", "path": ".hunt"})
    assert "notes.md" in out, out  # .hunt artifacts stay searchable
    print("ok: source searches only cover Python files; .hunt stays searchable")


def test_text_fallback_tool_call():
    llm = LocalLLM(LLMConfig())
    data = {
        "choices": [{
            "message": {"role": "assistant", "content":
                'I will read it.\n```tool_call\n{"tool":"read_file","arguments":{"path":"a.py"}}\n```'},
            "finish_reason": "stop",
        }]
    }
    resp = llm._parse(data)
    assert len(resp.tool_calls) == 1
    assert resp.tool_calls[0].name == "read_file"
    assert resp.tool_calls[0].arguments["path"] == "a.py"
    print("ok: text fallback tool-call parsed")


def test_bare_json_tool_calls():
    # Shape Ollama + Qwen actually returns: several bare JSON calls, nested args.
    llm = LocalLLM(LLMConfig())
    content = (
        '{"name": "search", "arguments": {"pattern": "request[.]form", "globs": ["*.py"]}}\n'
        '{"name": "list_dir", "arguments": {"path": "src"}}'
    )
    data = {"choices": [{"message": {"role": "assistant", "content": content},
                         "finish_reason": "stop"}]}
    resp = llm._parse(data)
    assert [tc.name for tc in resp.tool_calls] == ["search", "list_dir"], resp.tool_calls
    assert resp.tool_calls[0].arguments["globs"] == ["*.py"]
    assert len({tc.id for tc in resp.tool_calls}) == 2
    print("ok: bare JSON tool calls parsed")


def test_native_tool_calls_parsed():
    llm = LocalLLM(LLMConfig())
    data = {
        "choices": [{
            "message": {"role": "assistant", "content": "",
                "tool_calls": [{"id": "c1", "type": "function",
                    "function": {"name": "search", "arguments": '{"pattern":"x"}'}}]},
            "finish_reason": "tool_calls",
        }]
    }
    resp = llm._parse(data)
    assert resp.tool_calls[0].name == "search"
    print("ok: native tool_calls parsed")


def test_compaction_drops_old_written_content():
    import json as _json
    from pyscan.agent import Agent
    llm = LocalLLM(LLMConfig())
    agent = Agent(llm, tool_ctx=None)
    big = "x" * 20000
    def write_turn(i):
        text = _json.dumps({"name": "write_hunt_file", "arguments": {"path": ".hunt/a.md", "content": big}})
        return {"role": "assistant", "content": text, "tool_calls": [{
            "id": f"c{i}", "type": "function", "function": {
                "name": "write_hunt_file",
                "arguments": _json.dumps({"path": ".hunt/a.md", "content": big})}}]}
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "t"}]
    for i in range(4):
        msgs += [write_turn(i), {"role": "tool", "tool_call_id": f"c{i}", "content": "wrote"}]
    agent._maybe_compact(msgs)
    args = [_json.loads(m["tool_calls"][0]["function"]["arguments"])
            for m in msgs if m.get("tool_calls")]
    assert all("were written to .hunt/a.md" in a["content"] for a in args[:-1]), args
    assert args[-1]["content"] == big  # the newest write is left alone
    assert llm.estimate_tokens(msgs) < 13000  # only the newest write keeps its payload
    print("ok: compaction drops content of older write_hunt_file calls")


def test_repeated_tool_call_is_redirected(tmp_path):
    from pyscan.agent import Agent, RoleSpec
    from pyscan.llm import LLMResponse, ToolCall
    replies = iter(
        [LLMResponse("", [ToolCall("c", "search", {"pattern": "x"})], "tool_calls", {})] * 3
        + [LLMResponse("done", [], "stop", {})]
    )
    class FakeLLM:
        config = LLMConfig()
        def chat(self, *a, **k): return next(replies)
        def estimate_tokens(self, *a, **k): return 0
    agent = Agent(FakeLLM(), _ctx(tmp_path))
    spec = RoleSpec(name="t", system_prompt="s", tools=["search"], required_outputs=[])
    res = agent.run_role(spec, "task")
    tool_results = [m["content"] for m in res.transcript if m.get("role") == "tool"]
    assert "NOTE: you already made this exact search call" not in tool_results[0]
    assert all("you already made this exact search call" in r for r in tool_results[1:]), tool_results
    print("ok: repeated identical tool calls are redirected")


def test_write_refuses_placeholder_and_truncation(tmp_path):
    from pyscan.agent import Agent
    ctx = _ctx(tmp_path)
    t_write_hunt_file(ctx, {"path": str(tmp_path / "a.md"), "content": "y" * 5000})
    placeholder = Agent._compact_written_content
    msg = {"role": "assistant", "content": "", "tool_calls": [{"function": {
        "name": "write_hunt_file",
        "arguments": '{"path": "a.md", "content": "' + "z" * 5000 + '"}'}}]}
    placeholder(msg)
    import json as _json
    stub = _json.loads(msg["tool_calls"][0]["function"]["arguments"])["content"]
    for bad in (stub, "short"):
        try:
            t_write_hunt_file(ctx, {"path": str(tmp_path / "a.md"), "content": bad})
            raise AssertionError(f"write not refused: {bad!r}")
        except ToolError:
            pass
    assert (tmp_path / "a.md").read_text() == "y" * 5000
    t_write_hunt_file(ctx, {"path": str(tmp_path / "a.md"), "content": "more", "mode": "append"})
    print("ok: write refuses history placeholders and truncating overwrites")


def test_evidence_gate_keeps_proven_and_demotes_unproven(tmp_path):
    import json as _json
    import types
    from pyscan.agent import RoleResult
    from pyscan.orchestrator import Orchestrator, _Logger
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    for name in ("routes.py", "service.py", "other.py"):
        (repo / "app" / name).write_text("x\n" * 50)
    cands = tmp_path / ".hunt" / "candidates"
    cands.mkdir(parents=True)
    (cands / "c.md").write_text(
        "### CAND-1-1\nEntry Point: app/routes.py:10 via POST /run\n"
        "Sink: app/service.py:20 -- subprocess.run(shell=True)\n"
        "Chain: app/routes.py:10 -> app/service.py:20\n\n"
        "### CAND-2-1\nEntry Point: app/routes.py:12\n"
        "Sink: app/other.py:5 -- eval\nChain: app/routes.py:12 -> app/other.py:5\n\n"
        "### CAND-3-1\nEntry Point: app/routes.py:14\n"
        "Sink: server.run (assumed, not provided in the code)\n"
    )
    (cands / "f.md").write_text(
        "### CAND-1-1 -- CONFIRMED\nEntry: app/routes.py:10\nSink: app/service.py:20\n\n"
        "### CAND-2-1 -- CONFIRMED\nEntry: app/routes.py:12\nSink: app/other.py:5\n\n"
        "### CAND-3-1 -- DOWNGRADED\nEntry: app/routes.py:14\n"
    )
    o = Orchestrator.__new__(Orchestrator)
    o.ctx = types.SimpleNamespace(source_repo=repo, hunt_dir=tmp_path / ".hunt")
    o.log = _Logger(tmp_path / "logs")
    def read(path):
        return {"role": "assistant", "content": "", "tool_calls": [{"function": {
            "name": "read_file", "arguments": _json.dumps({"path": path})}}]}
    bt = RoleResult("bt", True, "", 2, "", [read("app/routes.py"), read(str(repo / "app/service.py"))])
    o._gate_confirmations(".hunt/candidates/c.md", ".hunt/candidates/f.md", bt)
    assert o._confirmed_ids(".hunt/candidates/f.md") == ["CAND-1-1"]
    text = (cands / "f.md").read_text()
    assert "CAND-2-1: blue team never opened app/other.py" in text, text
    assert "CAND-3-1: chain relies on an assumed" in text, text
    print("ok: evidence gate keeps proven chains, demotes unread and assumed ones")


def test_roles_use_configured_sampling():
    import os
    from pyscan.agent import RoleSpec
    sent = {}
    os.environ["PYSCAN_LLM_TEMPERATURE"] = "0.7"
    os.environ["PYSCAN_LLM_TOP_P"] = "0.8"
    try:
        llm = LocalLLM(LLMConfig.from_env())
    finally:
        del os.environ["PYSCAN_LLM_TEMPERATURE"], os.environ["PYSCAN_LLM_TOP_P"]
    llm._post = lambda path, payload: sent.update(payload) or {
        "choices": [{"message": {"content": "x"}, "finish_reason": "stop"}]}
    spec = RoleSpec(name="r", system_prompt="s", tools=[], required_outputs=[])
    llm.chat([{"role": "user", "content": "hi"}], temperature=spec.temperature)
    assert (sent["temperature"], sent["top_p"]) == (0.7, 0.8), sent
    assert (LLMConfig().temperature, LLMConfig().top_p) == (1.0, 0.95)
    print("ok: roles use the configured sampling settings")


def test_qwen3_xml_tool_calls_parsed():
    llm = LocalLLM(LLMConfig())
    text = (
        "Writing it now.<tool_call>\n<function=write_hunt_file>\n"
        "<parameter=path>\n.hunt/a.md\n</parameter>\n"
        "<parameter=content>\n# Map\n[1, 2]\n</parameter>\n</function>\n</tool_call>"
        "<tool_call>\n<function=read_file>\n<parameter=path>\napp.py\n</parameter>\n"
        "<parameter=start_line>\n20\n</parameter>\n</function>\n</tool_call>"
    )
    resp = llm._parse({"choices": [{"message": {"content": text}, "finish_reason": "stop"}]})
    assert [tc.name for tc in resp.tool_calls] == ["write_hunt_file", "read_file"], resp.tool_calls
    assert resp.tool_calls[0].arguments == {"path": ".hunt/a.md", "content": "# Map\n[1, 2]"}
    assert resp.tool_calls[1].arguments == {"path": "app.py", "start_line": 20}
    cut = llm._parse({"choices": [{"message": {"content": text.split("</function>")[0]},
                                   "finish_reason": "length"}]})
    assert cut.tool_calls == [] and cut.finish_reason == "length"
    print("ok: Qwen3 XML tool calls parsed; cut-off calls ignored")


def test_cut_off_reply_asks_for_smaller_writes(tmp_path):
    from pyscan.agent import Agent, RoleSpec
    from pyscan.llm import LLMResponse
    replies = iter([LLMResponse("<function=write_hunt_file>...", [], "length", {}),
                    LLMResponse("done", [], "stop", {})])
    class FakeLLM:
        config = LLMConfig()
        def chat(self, *a, **k): return next(replies)
        def estimate_tokens(self, *a, **k): return 0
    res = Agent(FakeLLM(), _ctx(tmp_path)).run_role(
        RoleSpec(name="t", system_prompt="s", tools=[], required_outputs=[]), "task")
    notes = [m["content"] for m in res.transcript if m["role"] == "user"]
    assert any("mode 'append'" in n for n in notes), notes
    print("ok: cut-off replies ask the model to write in parts")


def test_same_content_rewrites_are_capped(tmp_path):
    import os
    from pyscan.agent import Agent, RoleSpec
    from pyscan.llm import LLMResponse, ToolCall
    base = "# Map\\n" + "row | data | more\\n" * 400
    def write(content, mode="overwrite"):
        return LLMResponse("", [ToolCall("c", "write_hunt_file",
            {"path": ".hunt/a.md", "content": content, "mode": mode})], "tool_calls", {})
    replies = iter([
        write(base), write(base + "x"),          # 2 similar writes: allowed
        write(base + "y"),                       # 3rd similar: refused
        write("## Extra\\n", mode="append"),     # appends always go through
        write(base + "z"),                       # refused again -> role stops
        write("never reached"),
    ])
    class FakeLLM:
        config = LLMConfig()
        def chat(self, *a, **k): return next(replies)
        def estimate_tokens(self, *a, **k): return 0
    os.environ["PYSCAN_MAX_SAME_WRITES"] = "2"
    try:
        res = Agent(FakeLLM(), _ctx(tmp_path)).run_role(
            RoleSpec(name="t", system_prompt="s", tools=["write_hunt_file"],
                     required_outputs=[".hunt/a.md"]), "task")
    finally:
        del os.environ["PYSCAN_MAX_SAME_WRITES"]
    results = [m["content"] for m in res.transcript if m["role"] == "tool"]
    assert len(results) == 5, results
    assert results[0].startswith("wrote") and results[1].startswith("wrote")
    assert results[2].startswith("NOTE") and results[4].startswith("NOTE")
    assert results[3].startswith("wrote")
    assert (tmp_path / "a.md").read_text().endswith("## Extra\\n")
    assert res.ok, res.reason
    print("ok: same-content rewrites are capped and the role moves on")


def test_bracketed_candidate_ids_are_found(tmp_path):
    import types
    from pyscan.orchestrator import Orchestrator, _section
    (tmp_path / "f.md").write_text(
        "### CAND-3-[4] -- CONFIRMED\nEntry: a.py:1\n\n### CAND-1-4 -- DISPROVED\n")
    o = Orchestrator.__new__(Orchestrator)
    o.ctx = types.SimpleNamespace(source_repo=tmp_path, hunt_dir=tmp_path)
    assert o._confirmed_ids(str(tmp_path / "f.md")) == ["CAND-3-[4]"]
    assert _section((tmp_path / "f.md").read_text(), "CAND-3-[4]").strip() == "Entry: a.py:1"
    print("ok: bracketed candidate IDs like CAND-3-[4] are found")


def test_capability_check_requires_confirmation(tmp_path):
    import io
    from pyscan import capabilities
    from pyscan.config import ProductConfig, RunContext
    product = ProductConfig(
        highest_value_asset="The most valuable compromise outcome for this product",
        known_entry_points=["POST /api/run"],
    )
    ctx = RunContext(product=product, llm=LLMConfig(), source_repo=tmp_path,
                     hunt_dir=tmp_path / ".hunt", agents_dir=tmp_path,
                     prompts_dir=tmp_path, export_root=tmp_path, semgrep_bin=None)
    plan = capabilities.CorpusPlan(location=tmp_path / "corpus", languages=["python"],
                                   existing={}, to_build=[])
    caps = {c.name: c for c in capabilities.assess(ctx, offline=False, corpus=plan)}
    assert not caps["semgrep"].available
    assert not caps["CVE corpus (python)"].available
    plan.to_build = ["python"]
    built = {c.name: c for c in capabilities.assess(ctx, offline=False, corpus=plan)}
    assert built["CVE corpus (python)"].available and built["CVE corpus (python)"].label == "build"
    plan.existing, plan.to_build = {"python": tmp_path}, []
    assert {c.name: c for c in capabilities.assess(ctx, offline=False, corpus=plan)}["CVE corpus (python)"].available
    assert "highest_value_asset" in caps["product context"].detail
    assert "known_entry_points" not in caps["product context"].detail
    assert "semgrep rules (offline cache)" not in caps  # only checked offline
    caps = list(caps.values())

    class Tty(io.StringIO):
        def isatty(self): return True
    out = io.StringIO()
    assert not capabilities.confirm(caps, assume_yes=False, stdin=io.StringIO(""), out=out)
    assert "--yes" in out.getvalue()
    assert capabilities.confirm(caps, assume_yes=True, stdin=io.StringIO(""), out=io.StringIO())
    assert capabilities.confirm(caps, assume_yes=False, stdin=Tty("y\n"), out=io.StringIO())
    assert not capabilities.confirm(caps, assume_yes=False, stdin=Tty("\n"), out=io.StringIO())
    ok = [capabilities.Capability("x", True, "", "", "")]
    assert capabilities.confirm(ok, assume_yes=False, stdin=io.StringIO(""), out=io.StringIO())
    print("ok: capability check lists gaps and needs confirmation to continue")


def _corpus_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "requirements.txt").write_text("fastapi==0.100.0\nrequests\n# comment\n")
    (repo / "app" / "main.py").write_text(
        "import os, json\nfrom fastapi import FastAPI\nimport yaml\nfrom app import util\n"
        "from . import local\nimport requests  # http\n")
    (repo / "app" / "util.py").write_text("x = 1\n")
    site = repo / ".venv" / "lib" / "site-packages" / "requests-2.31.0.dist-info"
    site.mkdir(parents=True)
    (site / "METADATA").write_text("Name: requests\nVersion: 2.31.0\n")
    return repo


def test_cve_corpus_discovers_manifests_envs_and_imports(tmp_path):
    from pyscan import cve_corpus
    found = cve_corpus.discover(_corpus_repo(tmp_path))
    assert set(found) == {"python"}, found
    py = found["python"]
    assert py.declared == {"fastapi": "0.100.0", "requests": "2.31.0"}, py.declared
    assert py.resolved["requests"] == "2.31.0"  # from the installed env
    assert py.imported == {"fastapi", "pyyaml", "requests"}, py.imported  # no stdlib/local
    print("ok: corpus discovery reads manifests, envs, and source imports")


def test_cve_corpus_build_writes_language_folders(tmp_path):
    from pyscan import cve_corpus

    class FakeOSV:
        def vuln_ids(self, ecosystem, packages):
            hits = {"fastapi": ["GHSA-1", "PYSEC-1"], "requests": ["GHSA-2"],
                    "pyyaml": ["GHSA-3"]}
            return {p: (hits.get(p, []) if v or p == "pyyaml" else hits.get(p, [])) for p, v in packages.items()}

        def details(self, ids):
            def adv(i, pkg, eco, sev):
                return {"id": i, "summary": f"issue {i}", "aliases": ["CVE-1"] if i in ("GHSA-1", "PYSEC-1") else [],
                        "database_specific": {"severity": sev, "cwe_ids": ["CWE-79"]},
                        "affected": [{"package": {"name": pkg, "ecosystem": eco},
                                      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.9"}]}]}]}
            table = {"GHSA-1": ("fastapi", "PyPI", "HIGH"), "PYSEC-1": ("fastapi", "PyPI", ""),
                     "GHSA-2": ("requests", "PyPI", "CRITICAL"),
                     "GHSA-3": ("pyyaml", "PyPI", "MODERATE")}
            return {i: adv(i, *table[i]) for i in ids}

    out = tmp_path / "corpus"
    built = cve_corpus.build(_corpus_repo(tmp_path), out, product="Demo", osv=FakeOSV(), log=lambda m: None)
    assert set(built) == {"python"}
    assert cve_corpus.language_dirs(out) == {"python": out / "python"}
    index = (out / "python" / "INDEX.md").read_text()
    assert "GHSA-1" in index and "PYSEC-1" not in index  # GHSA/PYSEC duplicate merged
    assert "packages/pyyaml.md" in index  # import-only library gets history
    pkg = (out / "python" / "packages" / "requests.md").read_text()
    assert "[AFFECTS VERSION IN USE]" in pkg and "fixed in 9.9" in pkg
    staged = tmp_path / "staged"
    staged.mkdir()
    (staged / "notes.md").write_text("x")
    assert cve_corpus.language_dirs(staged) == {"any": staged}
    print("ok: corpus build writes the python folder and merges duplicate advisories")


def test_semgrep_uses_cached_rules_offline(tmp_path):
    import os
    from pyscan import semgrep_rules
    cache = tmp_path / "rules"
    cache.mkdir()
    (cache / "p_security-audit.yml").write_text("rules: []\n")
    cwd = os.getcwd()
    os.chdir(tmp_path)  # cache given as a relative path must still resolve
    try:
        configs, missing = semgrep_rules.resolve(["p/security-audit", "p/python"], Path("rules"))
    finally:
        os.chdir(cwd)
    assert configs[0] == str((cache / "p_security-audit.yml").resolve())
    assert missing == ["p/python"]
    ctx = ToolContext(source_repo=FIX, hunt_dir=tmp_path / "hunt", semgrep_bin="/bin/false",
                      semgrep_rulesets=["p/python"], semgrep_rules_cache=cache, offline=True)
    from pyscan.tools import t_run_semgrep
    try:
        t_run_semgrep(ctx, {"roots": ["."], "shard_name": "x"})
        raise AssertionError("offline run with no cached rules should not call semgrep")
    except ToolError as e:
        assert "not cached for offline use" in str(e)
    print("ok: offline semgrep uses cached rule files and never registry names")


def test_git_history_summary_is_optional(tmp_path):
    import subprocess
    from pyscan import git_history
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "tests").mkdir()

    def git(*args):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(repo), *args],
                       check=True, capture_output=True)
    git("init", "-q")
    (repo / "app" / "upload.py").write_text("v1\n")
    (repo / "tests" / "test_upload.py").write_text("t\n")
    (repo / "README.md").write_text("docs\n")
    git("add", "-A")
    git("commit", "-q", "-m", "Add upload handler", "-m", "body mentions security and CVE")
    (repo / "app" / "upload.py").write_text("v2\n")
    git("commit", "-qam", "Fix path traversal in upload")
    out = tmp_path / "git-history.md"
    assert git_history.summarize(repo, out)
    text = out.read_text()
    assert "| app/upload.py | 2 |" in text
    assert "test_upload.py" not in text and "README.md" not in text  # tests/docs left out
    assert "Fix path traversal in upload" in text
    assert "Add upload handler" not in text.split("## Commits")[1]  # body words don't count
    plain = tmp_path / "plain"
    plain.mkdir()
    assert not git_history.summarize(plain, tmp_path / "none.md")
    assert not (tmp_path / "none.md").exists()
    print("ok: git history summary is written when history exists and skipped otherwise")


def _bare_orchestrator(tmp_path, repo):
    import types
    from pyscan.orchestrator import Orchestrator, _Logger
    o = Orchestrator.__new__(Orchestrator)
    o.ctx = types.SimpleNamespace(source_repo=repo, hunt_dir=tmp_path / ".hunt", cve_corpus={})
    o.log = _Logger(tmp_path / "logs")
    return o


def test_verifier_gate_files_only_backed_verified(tmp_path):
    import json as _json
    from pyscan.agent import RoleResult
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    for name in ("routes.py", "db.py"):
        (repo / "app" / name).write_text("x\n" * 30)
    cands = tmp_path / ".hunt" / "candidates"
    cands.mkdir(parents=True)
    (cands / "c.md").write_text("".join(
        f"### {cid}\nEntry Point: app/routes.py:3\nSink: app/db.py:9 -- execute\n\n"
        for cid in ("CAND-1-1", "CAND-2-1", "CAND-3-1")))
    launch = "Launch: uvicorn app (app/routes.py:1)\n"
    (cands / "v.md").write_text(
        "### CAND-1-1 -- VERIFIED\nTrace:\n  Entry: app/routes.py:3\n  Sink: app/db.py:9\n"
        + launch + "Input source: ATTACKER-CONTROLLED -- query param (app/routes.py:3)\n\n"
        "### CAND-2-1 -- REJECTED\nReason: escaped\n\n"
        "### CAND-3-1 -- VERIFIED\nTrace:\n  Entry: app/routes.py:3\n  Sink: app/db.py:9\n"
        + launch + "Input source: OPERATOR-CONTROLLED -- config file (app/routes.py:5)\n")
    o = _bare_orchestrator(tmp_path, repo)
    read = lambda p: {"role": "assistant", "tool_calls": [{"function": {
        "name": "read_file", "arguments": _json.dumps({"path": p})}}]}
    both = RoleResult("v", True, "", 2, "", [read("app/routes.py"), read("app/db.py")])
    ids = ["CAND-1-1", "CAND-2-1", "CAND-3-1"]
    # CAND-3-1 is VERIFIED but its input is operator-controlled, so it is not filed.
    assert o._verified_ids(".hunt/candidates/c.md", ".hunt/candidates/v.md", ids, both) == ["CAND-1-1"]
    entry_only = RoleResult("v", True, "", 1, "", [read("app/routes.py")])
    assert o._verified_ids(".hunt/candidates/c.md", ".hunt/candidates/v.md", ids, entry_only) == []
    assert "treated as UNCERTAIN" in (cands / "v.md").read_text()
    print("ok: only VERIFIED, attacker-reachable findings backed by opened files are filed")


def test_semgrep_triage_batches_and_dependency_targets(tmp_path):
    import os
    from pyscan import cve_corpus, sweep
    o = _bare_orchestrator(tmp_path, tmp_path)
    matches = [{"id": f"S-{i:03d}", "rule": "r", "severity": "ERROR", "path": "a.py", "line": i,
                "message": "m", "code": "", "cwe": []} for i in range(1, 6)]
    sweep.write(o.ctx.hunt_dir, matches, ["app"])
    assert [m["id"] for m in sweep.load(o.ctx.hunt_dir)] == [m["id"] for m in matches]
    assert "### S-005 [ERROR] r" in (o.ctx.hunt_dir / "semgrep-findings.md").read_text()

    tasks, piped = [], []

    class FakeAgent:
        def run_role(self, spec, task):
            tasks.append(task)
            from pyscan.agent import RoleResult
            return RoleResult(spec.name, True, "", 0, "", [])
    o._agent = lambda **kw: FakeAgent()
    o._invoke = lambda r: r
    o._falsify_and_file = lambda label, cand, fals, extra_reads=None: piped.append((label, cand)) or 0
    import pyscan.orchestrator as orch
    real_build_role = orch.build_role
    orch.build_role = lambda ctx, name, required_outputs=None: type("S", (), {"name": name})()
    os.environ["PYSCAN_SEMGREP_BATCH"] = "2"
    try:
        o._semgrep_triage_pass()
    finally:
        del os.environ["PYSCAN_SEMGREP_BATCH"]
    assert len(tasks) == 3 and "S-001, S-002" in tasks[0] and "S-005" in tasks[2]
    assert piped[0] == ("semgrep batch 1", ".hunt/candidates/semgrep-1-candidates.md")

    corpus = tmp_path / "corpus"
    (corpus / "packages").mkdir(parents=True)
    (corpus / "INDEX.md").write_text(
        "# x\n\n## Advisories affecting the versions in use (3)\n\n"
        "### libdev 1.0 -> packages/libdev.md\n- GHSA-1 [CRITICAL] -- dev tool\n\n"
        "### libapp 2.0 -> packages/libapp.md\n- GHSA-2 [MODERATE] -- app lib\n\n"
        "### libdecl 3.0 -> packages/libdecl.md\n- GHSA-3 [HIGH] -- declared\n\n"
        "## Libraries with advisory history (3)\n"
        "| Library | Version | Found in | Advisories | Affect version | Worst | File |\n"
        "|---|---|---|---|---|---|---|\n"
        "| libdev | 1.0 | lock/env | 1 | 1 | CRITICAL | packages/libdev.md |\n"
        "| libapp | 2.0 | manifest+imports | 1 | 1 | MODERATE | packages/libapp.md |\n"
        "| libdecl | 3.0 | manifest | 1 | 1 | HIGH | packages/libdecl.md |\n")
    picked = [lib["package"] for lib in cve_corpus.reachability_targets(corpus)]
    assert picked == ["libapp", "libdecl"], picked  # imported first; lock-only dev tool skipped
    tasks.clear()
    piped.clear()
    o.ctx.cve_corpus = {"python": corpus}
    try:
        o._dependency_pass()
    finally:
        orch.build_role = real_build_role
    assert "libapp 2.0" in tasks[0] and "GHSA-2 [MODERATE]" in tasks[0]
    assert piped == [("dependency libapp", ".hunt/candidates/deps-1-candidates.md"),
                     ("dependency libdecl", ".hunt/candidates/deps-2-candidates.md")]
    print("ok: semgrep triage runs in batches; dependency pass picks imported/declared libraries")


class _ScriptedLLM:
    """Fake model: answers each chat() with the next scripted reply, or a
    write of the output when only write_hunt_file is offered."""
    config = LLMConfig()

    def __init__(self, replies, final_write=None):
        self.replies = iter(replies)
        self.final_write = final_write
        self.tool_sets = []

    def chat(self, messages, tools, **kw):
        from pyscan.llm import LLMResponse, ToolCall
        names = [t["function"]["name"] for t in tools]
        self.tool_sets.append(names)
        if names == ["write_hunt_file"] and self.final_write:
            return LLMResponse("", [ToolCall("w", "write_hunt_file", self.final_write)], "tool_calls", {})
        return next(self.replies)

    def estimate_tokens(self, *a, **k):
        return 0


def _call(name, **args):
    from pyscan.llm import LLMResponse, ToolCall
    return LLMResponse("", [ToolCall("c", name, args)], "tool_calls", {})


def test_budget_warning_and_final_write(tmp_path):
    from pyscan.agent import Agent, RoleSpec
    spec = RoleSpec(name="t", system_prompt="s", tools=["list_dir", "write_hunt_file"],
                    required_outputs=[".hunt/out.md"], max_tool_calls=10)
    llm = _ScriptedLLM([_call("list_dir", path=f"src{i}") for i in range(20)],
                       final_write={"path": ".hunt/out.md", "content": "# Partial\\n" + "x" * 80})
    res = Agent(llm, _ctx(tmp_path)).run_role(spec, "task")
    notes = [m["content"] for m in res.transcript if m["role"] == "user"][1:]
    assert any("tool calls left" in n for n in notes), notes  # warned with 5 left
    assert llm.tool_sets[-1] == ["write_hunt_file"]  # last-chance write-only turn
    assert (tmp_path / "out.md").is_file()
    print("ok: low-budget warning, then a write-only turn saves the output")


def test_repeating_role_stops_once_output_exists(tmp_path):
    from pyscan.agent import Agent, RoleSpec
    (tmp_path / "out.md").write_text("# Done\\n" + "x" * 80)
    spec = RoleSpec(name="t", system_prompt="s", tools=["list_dir"],
                    required_outputs=[".hunt/out.md"], max_tool_calls=80)
    llm = _ScriptedLLM([_call("list_dir", path="src")] * 80)
    res = Agent(llm, _ctx(tmp_path)).run_role(spec, "task")
    assert res.tool_calls_used == 6, res.tool_calls_used  # 1 real call + 5 skipped repeats
    print("ok: a role that only repeats calls stops once its output exists")


def test_findings_ids_fields_duplicates_and_summary(tmp_path):
    from pyscan import findings
    hunt = tmp_path
    (hunt / "findings").mkdir()
    assert findings.next_id(hunt) == "SECSCAN-0001"
    pack = ("# SECSCAN-0001: SSRF\n\n## Severity\nCVSS Score: 9.8\n\n## Summary Fields\n"
            "title: SSRF via web fetch, follows redirects\ncwe_id: CWE-918\ncwe_name: SSRF\n"
            "cvss_score: 9.8\ncvss_severity: Critical\nsink_file: app/web.py\nsink_line: 40\n"
            "summary: Fetches any URL, including \"internal\" hosts\nunknown_field: x\n")
    row = findings.parse_summary_fields(pack)
    assert row["title"] == "SSRF via web fetch, follows redirects" and "unknown_field" not in row
    row.update(findings.parse_severity(
        "Severity: 7.7 High CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N -- needs an account"))
    assert (row["cvss_score"], row["cvss_severity"]) == ("7.7", "High")  # verifier wins
    row.update({"finding_id": "SECSCAN-0001"})
    findings.append_row(hunt, row)
    (hunt / "findings" / "SECSCAN-0001-ssrf.md").write_text(pack)
    rows = findings.read_rows(hunt)
    assert rows[0]["summary"] == 'Fetches any URL, including "internal" hosts'  # csv quoting
    assert len(rows[0]) == len(findings.HEADER)
    assert findings.next_id(hunt) == "SECSCAN-0002"
    assert findings.duplicate_of(rows, "./app/web.py", "40", "CWE-918") == "SECSCAN-0001"
    assert findings.duplicate_of(rows, "app/web.py", "40", "") == "SECSCAN-0001"  # CWE unknown
    assert findings.duplicate_of(rows, "app/web.py", "40", "CWE-79") == ""  # different CWE
    findings.write_executive_summary(hunt, "Demo", "FULL_48H")
    summary = (hunt / "executive-summary.md").read_text()
    assert "| SECSCAN-0001 | High | 7.7 | CWE-918 |" in summary
    moved = findings.set_aside([hunt / "findings" / "SECSCAN-0001-ssrf.md"], hunt, "test")
    assert moved[0].parent.name == "discarded-filings" and moved[0].is_file()
    print("ok: SECSCAN ids, summary fields, verifier severity, CSV, duplicates, executive summary")


if __name__ == "__main__":
    import tempfile
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                if "tmp_path" in fn.__code__.co_varnames[: fn.__code__.co_argcount]:
                    with tempfile.TemporaryDirectory() as d:
                        fn(Path(d))
                else:
                    fn()
            except Exception as e:
                failures += 1
                print(f"FAIL: {name}: {e}")
    print(f"\n{'ALL PASS' if not failures else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)
