"""Single-role agent loop.

Drives one worker role (recon mapper, red team, blue team, verifier, filer) to
completion against the local model: the orchestrator calls run_role() directly.

Design points, all driven by using a local model:

* Hard tool-call budget per role, so a confused model cannot loop forever.
* Context compaction: when the running transcript approaches the model's
  window, older tool results are summarised out, to fit a 32K-class context.
* Completion is decided by the required output artifact existing on disk, not
  by the model claiming success -- an evidence-of-execution rule enforced in
  code.
"""
from __future__ import annotations

import difflib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .llm import LocalLLM, LLMResponse, ToolCall
from .tools import COMPACTED_WRITE_MARKER, TOOL_IMPLS, ToolContext, ToolError, schemas_for

# Overwrites of the same file at least this similar count as the same write.
SAME_WRITE_SIMILARITY = 0.95
# Refused rewrites after which a role whose outputs exist is ended.
SAME_WRITE_STOP_AFTER = 2
# Skipped (repeated) calls in a row that count as a loop.
LOOP_STOP_AFTER = 5


def _budget_reserve(budget: int) -> int:
    """Calls left when a role without its output is told to write it now."""
    return max(5, budget * 15 // 100)


def max_same_writes() -> int:
    """How many times a role may overwrite a file with essentially the same
    content before further rewrites are refused (PYSCAN_MAX_SAME_WRITES)."""
    try:
        return max(1, int(os.environ.get("PYSCAN_MAX_SAME_WRITES", "2")))
    except ValueError:
        return 2


def _same_content(a: str, b: str) -> bool:
    if a == b:
        return True
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    return matcher.quick_ratio() >= SAME_WRITE_SIMILARITY and matcher.ratio() >= SAME_WRITE_SIMILARITY


@dataclass
class RoleSpec:
    name: str
    system_prompt: str
    tools: list[str]
    # Artifact(s) that must exist and be non-trivial for the role to count as
    # done. Relative to the source repo.
    required_outputs: list[str]
    max_tool_calls: int = 60
    # None uses the model config (PYSCAN_LLM_TEMPERATURE); sampling suits
    # the model, not the role.
    temperature: float | None = None


@dataclass
class RoleResult:
    name: str
    ok: bool
    reason: str
    tool_calls_used: int
    final_text: str
    transcript: list[dict] = field(default_factory=list)


class Agent:
    def __init__(
        self,
        llm: LocalLLM,
        tool_ctx: ToolContext,
        log_dir: Path | None = None,
        progress: Callable[[str], None] | None = None,
    ):
        self.llm = llm
        self.tool_ctx = tool_ctx
        self.log_dir = log_dir
        self.progress = progress or (lambda _msg: None)

    def run_role(self, spec: RoleSpec, task: str) -> RoleResult:
        messages: list[dict] = [
            {"role": "system", "content": spec.system_prompt},
            {"role": "user", "content": task},
        ]
        tool_schemas = schemas_for(spec.tools)
        calls_used = 0
        final_text = ""
        turn = 0
        seen_calls: dict[str, int] = {}
        cutoffs = 0
        write_limit = max_same_writes()
        last_written: dict[str, str] = {}
        same_writes: dict[str, int] = {}
        refused_rewrites = 0
        skipped_in_a_row = 0
        budget_warned = loop_warned = False
        self.progress(f"[{spec.name}] start (budget {spec.max_tool_calls} tool calls)")

        while calls_used <= spec.max_tool_calls:
            turn += 1
            self._maybe_compact(messages)
            self.progress(
                f"[{spec.name}] turn {turn}: waiting for model "
                f"(~{self.llm.estimate_tokens(messages)} tokens in context)"
            )
            started = time.monotonic()
            resp: LLMResponse = self.llm.chat(
                messages, tool_schemas, temperature=spec.temperature
            )
            self.progress(
                f"[{spec.name}] turn {turn}: model replied in "
                f"{time.monotonic() - started:.0f}s, {len(resp.tool_calls)} tool call(s)"
            )

            if resp.tool_calls:
                # Record the assistant turn that requested the tools.
                messages.append(self._assistant_tool_msg(resp))
                for tc in resp.tool_calls:
                    calls_used += 1
                    self.progress(
                        f"[{spec.name}]   #{calls_used} {tc.name} {_summarize_args(tc.arguments)}"
                    )
                    key = tc.name + json.dumps(tc.arguments, sort_keys=True)
                    seen_calls[key] = seen_calls.get(key, 0) + 1
                    if seen_calls[key] > 1 and tc.name != "write_hunt_file":
                        # Small local models can loop on the same call; the
                        # result would be identical, so redirect instead.
                        result = (
                            f"NOTE: you already made this exact {tc.name} call "
                            f"{seen_calls[key] - 1} time(s); the result has not "
                            "changed. Do not repeat it. read_file a specific hit, "
                            "try a different pattern or path, or write your output."
                        )
                    elif self._is_repeat_write(tc, last_written, same_writes) and (
                        same_writes[str(tc.arguments.get("path", ""))] > write_limit
                    ):
                        refused_rewrites += 1
                        result = (
                            f"NOTE: {tc.arguments.get('path')} is already saved with "
                            f"essentially this content ({write_limit} similar writes). "
                            "Nothing was written. Move on to the next step, or finish "
                            "with your completion signal."
                        )
                    else:
                        result = self._dispatch_tool(tc)
                    status = (
                        "ERROR" if result.startswith("ERROR")
                        else "skipped" if result.startswith("NOTE")
                        else "ok"
                    )
                    self.progress(f"[{spec.name}]   #{calls_used} -> {status}, {len(result)} chars")
                    skipped_in_a_row = skipped_in_a_row + 1 if status == "skipped" else 0
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "name": tc.name,
                            "content": result,
                        }
                    )
                    if calls_used > spec.max_tool_calls:
                        break
                # Save the transcript as we go so a long role can be inspected live.
                self._maybe_log(spec, messages)
                if refused_rewrites >= SAME_WRITE_STOP_AFTER and self._outputs_present(spec):
                    self.progress(
                        f"[{spec.name}] stopping: output saved and the model keeps "
                        "rewriting the same content"
                    )
                    break
                if skipped_in_a_row >= LOOP_STOP_AFTER:
                    if self._outputs_present(spec):
                        self.progress(f"[{spec.name}] stopping: output saved and the model "
                                      "keeps repeating calls")
                        break
                    if loop_warned:
                        self.progress(f"[{spec.name}] stopping: still repeating calls after a warning")
                        break
                    loop_warned = True
                    skipped_in_a_row = 0
                    self.progress(f"[{spec.name}] repeating calls without output; asking for it now")
                    messages.append({"role": "user", "content": self._write_now_message(
                        spec, "You are repeating calls you already made.")})
                remaining = spec.max_tool_calls - calls_used
                if (not budget_warned and spec.required_outputs
                        and remaining <= _budget_reserve(spec.max_tool_calls)
                        and not self._outputs_present(spec)):
                    budget_warned = True
                    self.progress(f"[{spec.name}] {remaining} tool calls left and no output yet; "
                                  "asking for it now")
                    messages.append({"role": "user", "content": self._write_now_message(
                        spec, f"You have {max(remaining, 0)} tool calls left.")})
                continue

            # Cut off at the output limit mid-call (typically a large file
            # write): keep a stub instead of the partial text, and ask for the
            # file in parts so each call fits.
            if resp.finish_reason == "length" and cutoffs < 3:
                cutoffs += 1
                self.progress(f"[{spec.name}] reply hit the output limit; asking for smaller writes")
                messages.append({
                    "role": "assistant",
                    "content": f"[reply cut off at the output limit after {len(resp.text or '')} chars]",
                })
                messages.append({
                    "role": "user",
                    "content": (
                        "Your last reply was cut off at the output-token limit before "
                        "the tool call finished, so nothing was written. Write the file "
                        "in parts: call write_hunt_file with the first few sections and "
                        "mode 'overwrite', then call it again with mode 'append' for "
                        "each remaining part. Keep each call under about 8000 characters."
                    ),
                })
                continue

            # No tool calls -> the model is done talking for this turn.
            final_text = resp.text or ""
            messages.append({"role": "assistant", "content": final_text})
            # If the model stopped but hasn't produced the artifact, nudge once.
            if not self._outputs_present(spec):
                if self._already_nudged(messages):
                    break
                self.progress(f"[{spec.name}] model stopped without writing its output; nudging")
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "You have not yet written the required output file(s): "
                            f"{', '.join(spec.required_outputs)}. "
                            "Use write_hunt_file to persist your result now, then "
                            "print your completion signal. Do not stop before the "
                            "file exists."
                        ),
                    }
                )
                continue
            break

        if spec.required_outputs and not self._outputs_present(spec):
            self._final_write(spec, messages)
        ok, reason = self._verify(spec, calls_used)
        self._maybe_log(spec, messages)
        return RoleResult(
            name=spec.name,
            ok=ok,
            reason=reason,
            tool_calls_used=calls_used,
            final_text=final_text,
            transcript=messages,
        )

    @staticmethod
    def _write_now_message(spec: RoleSpec, why: str) -> str:
        return (
            f"{why} You have not written {', '.join(spec.required_outputs)}. "
            "Write it now with write_hunt_file using what you have found so far, "
            "marked '## Status: PARTIAL' and listing what you did not get to. "
            "Unsaved work is lost when the budget runs out."
        )

    def _final_write(self, spec: RoleSpec, messages: list[dict]) -> None:
        """The budget is spent and the output is missing: give the model a
        last turn in which writing the output is the only thing it can do."""
        self.progress(f"[{spec.name}] budget spent without output; final write-only turn")
        messages.append({"role": "user", "content": (
            "Your tool-call budget is used up and "
            f"{', '.join(spec.required_outputs)} does not exist. The only tool left is "
            "write_hunt_file. Write the file now from everything above, marked "
            "'## Status: PARTIAL'. If it is long, write the first part now.")})
        for _ in range(2):
            resp = self.llm.chat(messages, schemas_for(["write_hunt_file"]),
                                 temperature=spec.temperature)
            writes = [tc for tc in resp.tool_calls if tc.name == "write_hunt_file"]
            if not writes:
                break
            messages.append(self._assistant_tool_msg(resp))
            for tc in writes:
                result = self._dispatch_tool(tc)
                self.progress(f"[{spec.name}]   final write {_summarize_args(tc.arguments)} -> "
                              f"{'ERROR' if result.startswith('ERROR') else 'ok'}")
                messages.append({"role": "tool", "tool_call_id": tc.id,
                                 "name": tc.name, "content": result})
            if self._outputs_present(spec):
                break

    # -- tool dispatch ------------------------------------------------------

    @staticmethod
    def _is_repeat_write(
        tc: ToolCall, last_written: dict[str, str], same_writes: dict[str, int]
    ) -> bool:
        """Track overwrites per path; True when this one repeats the last
        content written there. Appends and other tools never count."""
        if tc.name != "write_hunt_file" or tc.arguments.get("mode") == "append":
            return False
        path = str(tc.arguments.get("path", ""))
        content = str(tc.arguments.get("content", ""))
        previous = last_written.get(path)
        repeat = previous is not None and _same_content(previous, content)
        same_writes[path] = same_writes.get(path, 0) + 1 if repeat else 1
        last_written[path] = content
        return repeat

    def _dispatch_tool(self, tc: ToolCall) -> str:
        impl = TOOL_IMPLS.get(tc.name)
        if impl is None:
            return f"ERROR: unknown tool '{tc.name}'"
        try:
            return impl(self.tool_ctx, tc.arguments)
        except ToolError as e:
            return f"ERROR: {e}"
        except Exception as e:  # defensive: a tool bug must not kill the run
            return f"ERROR: tool '{tc.name}' failed unexpectedly: {e}"

    @staticmethod
    def _assistant_tool_msg(resp: LLMResponse) -> dict:
        return {
            "role": "assistant",
            "content": resp.text or "",
            "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": json.dumps(tc.arguments),
                    },
                }
                for tc in resp.tool_calls
            ],
        }

    # -- completion verification -------------------------------------------

    def _outputs_present(self, spec: RoleSpec) -> bool:
        return all(self._artifact_ok(rel) for rel in spec.required_outputs)

    def _artifact_ok(self, rel: str) -> bool:
        s = str(rel).replace("\\", "/")
        if s.startswith(".hunt/"):
            path = (self.tool_ctx.hunt_dir / s[len(".hunt/"):]).resolve()
        elif s.startswith("hunt/"):
            path = (self.tool_ctx.hunt_dir / s[len("hunt/"):]).resolve()
        else:
            path = (self.tool_ctx.source_repo / rel).resolve()
        return path.is_file() and path.stat().st_size > 40

    def _verify(self, spec: RoleSpec, calls_used: int) -> tuple[bool, str]:
        missing = [r for r in spec.required_outputs if not self._artifact_ok(r)]
        if missing:
            return False, f"required output(s) missing or empty: {missing}"
        if calls_used > spec.max_tool_calls:
            return False, (
                f"exceeded tool-call budget ({spec.max_tool_calls}); output may be partial"
            )
        return True, "ok"

    @staticmethod
    def _already_nudged(messages: list[dict]) -> bool:
        return any(
            m.get("role") == "user" and "required output file" in str(m.get("content", ""))
            for m in messages
        )

    # -- context management -------------------------------------------------

    def _maybe_compact(self, messages: list[dict]) -> None:
        """Keep the transcript under the model's window by summarising old tool
        output. A 32K-class window is limited, so long
        recon transcripts must be compacted or the request is rejected."""
        # File content the model already wrote is on disk, so drop it from
        # older write calls regardless of budget: repeated checkpoints of a
        # large artifact would otherwise fill the window on their own.
        for m in messages[2:-2]:
            if m.get("role") == "assistant" and m.get("tool_calls"):
                self._compact_written_content(m)
        budget = int(self.llm.config.context_tokens * 0.72)
        if self.llm.estimate_tokens(messages) <= budget:
            return
        # Never touch the system prompt (0), the first user task (1), or the two
        # most recent messages. Replace the content of older tool results with a
        # short stub so the model keeps the thread without the bulk.
        for i in range(2, len(messages) - 2):
            m = messages[i]
            if m.get("role") == "tool" and not m.get("_compacted"):
                original = str(m.get("content", ""))
                if len(original) > 600:
                    m["content"] = (
                        original[:400]
                        + f"\n... [older tool output compacted to save context; "
                        f"{len(original)} chars; re-run the tool if you need it again]"
                    )
                    m["_compacted"] = True
            if self.llm.estimate_tokens(messages) <= budget:
                return

    @staticmethod
    def _compact_written_content(message: dict) -> None:
        # Models without structured tool calls put the call JSON, file content
        # included, in the message text; tool_calls already records the call.
        text = str(message.get("content") or "")
        if len(text) > 600 and "write_hunt_file" in text:
            message["content"] = ""
        for call in message["tool_calls"]:
            fn = call.get("function", {})
            if fn.get("name") != "write_hunt_file":
                continue
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                continue
            content = args.get("content")
            if isinstance(content, str) and len(content) > 600:
                args["content"] = (
                    f"[{COMPACTED_WRITE_MARKER}: {len(content)} chars were "
                    f"written to {args.get('path')}; read_file it to see them]"
                )
                fn["arguments"] = json.dumps(args)

    def _maybe_log(self, spec: RoleSpec, messages: list[dict]) -> None:
        if not self.log_dir:
            return
        self.log_dir.mkdir(parents=True, exist_ok=True)
        path = self.log_dir / f"{spec.name}.transcript.json"
        try:
            path.write_text(json.dumps(messages, indent=2), encoding="utf-8")
        except OSError:
            pass


def _summarize_args(args: dict[str, Any], limit: int = 160) -> str:
    """One-line view of tool arguments for progress output; bulky file
    content is reduced to its size."""
    shown = {
        k: (f"<{len(v)} chars>" if k == "content" and isinstance(v, str) else v)
        for k, v in args.items()
    }
    text = json.dumps(shown, ensure_ascii=False)
    return text if len(text) <= limit else text[: limit - 3] + "..."
