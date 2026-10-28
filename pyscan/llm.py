"""Local OpenAI-compatible chat client for pyscan.

This is the ONLY module that performs network I/O, and it talks only to the
configured local endpoint (vLLM / Ollama / llama.cpp, all exposing the OpenAI
/v1/chat/completions contract). It uses the Python standard library only, so
the sandbox image needs no pip dependencies.

Two things make it robust against a local model:

1. Retries with backoff on transient server errors (model still loading, a
   slot queue full, a dropped socket).
2. A tool-call fallback: if the server cannot emit structured tool_calls, the
   model is instructed to print a ```tool_call``` fenced JSON block, and this
   module extracts it. Either way the agent loop sees the same shape.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .config import LLMConfig

# Qwen3-Coder's own tool-call format:
#   <function=name><parameter=key>value</parameter>...</function>
_XML_CALL = re.compile(r"<function=([\w.-]+)>(.*?)</function>", re.S)
_XML_PARAM = re.compile(r"<parameter=([\w.-]+)>\n?(.*?)\n?</parameter>", re.S)


class LLMError(RuntimeError):
    pass


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    text: str
    tool_calls: list[ToolCall]
    finish_reason: str
    raw: dict[str, Any]


def _approx_tokens(messages: list[dict], tools: list[dict] | None) -> int:
    """Cheap token estimate (~4 chars/token) for pre-flight context checks.

    Deliberately conservative; the orchestrator uses it to decide when to
    compact, not for billing.
    """
    blob = json.dumps(messages, ensure_ascii=False)
    if tools:
        blob += json.dumps(tools, ensure_ascii=False)
    return len(blob) // 4


class LocalLLM:
    def __init__(self, config: LLMConfig):
        self.config = config

    # -- public API ---------------------------------------------------------

    def estimate_tokens(self, messages: list[dict], tools: list[dict] | None = None) -> int:
        return _approx_tokens(messages, tools)

    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature
            if temperature is None
            else temperature,
            "top_p": self.config.top_p,
            "max_tokens": max_tokens or self.config.max_output_tokens,
            "stream": False,
        }
        if tools and self.config.native_tool_calls:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        data = self._post("/chat/completions", payload)
        return self._parse(data)

    def health(self) -> bool:
        """True if the model endpoint answers /models. Used by the egress and
        readiness self-tests; never raises."""
        try:
            self._get("/models")
            return True
        except Exception:
            return False

    # -- transport ----------------------------------------------------------

    def _url(self, path: str) -> str:
        return self.config.base_url.rstrip("/") + path

    def _get(self, path: str) -> dict[str, Any]:
        req = urllib.request.Request(
            self._url(path),
            headers={"Authorization": f"Bearer {self.config.api_key}"},
            method="GET",
        )
        # No proxies: the sandbox has no egress anyway, and we must not route
        # the local call through one if the host set HTTP_PROXY.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        last_err: Exception | None = None
        for attempt in range(self.config.max_retries):
            req = urllib.request.Request(
                self._url(path),
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.config.api_key}",
                },
                method="POST",
            )
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            try:
                with opener.open(req, timeout=self.config.request_timeout_s) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                detail = e.read().decode("utf-8", "replace")[:500]
                # 4xx other than 429 are our bug (bad request): do not retry.
                if e.code not in (429, 500, 502, 503, 504):
                    raise LLMError(f"LLM HTTP {e.code}: {detail}") from e
                last_err = LLMError(f"LLM HTTP {e.code}: {detail}")
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                last_err = LLMError(f"LLM connection error: {e}")
            sleep = min(2 ** attempt, 30)
            time.sleep(sleep)
        raise LLMError(
            f"LLM request failed after {self.config.max_retries} attempts: {last_err}"
        )

    # -- parsing ------------------------------------------------------------

    def _parse(self, data: dict[str, Any]) -> LLMResponse:
        try:
            choice = data["choices"][0]
        except (KeyError, IndexError) as e:
            raise LLMError(f"malformed LLM response: {data}") from e
        message = choice.get("message", {})
        text = message.get("content") or ""
        finish = choice.get("finish_reason", "stop")

        tool_calls: list[ToolCall] = []
        # Path 1: server emitted structured tool_calls.
        for i, tc in enumerate(message.get("tool_calls") or []):
            fn = tc.get("function", {})
            args = fn.get("arguments", "{}")
            parsed = self._safe_json(args)
            if parsed is not None:
                tool_calls.append(
                    ToolCall(
                        id=tc.get("id") or f"call_{i}",
                        name=fn.get("name", ""),
                        arguments=parsed,
                    )
                )
        # Path 2: fallback -- extract tool-call JSON from the text.
        if not tool_calls and text:
            tool_calls = self._extract_text_tool_calls(text)

        return LLMResponse(
            text=text, tool_calls=tool_calls, finish_reason=finish, raw=data
        )

    @staticmethod
    def _safe_json(blob: Any) -> dict[str, Any] | None:
        if isinstance(blob, dict):
            return blob
        if not isinstance(blob, str):
            return None
        try:
            val = json.loads(blob)
            return val if isinstance(val, dict) else {"_value": val}
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _extract_xml_tool_calls(text: str) -> list[ToolCall]:
        """Complete Qwen3-Coder XML tool calls; a call cut off before its
        closing tag is ignored rather than run with partial arguments."""
        calls: list[ToolCall] = []
        for name, body in _XML_CALL.findall(text):
            args: dict[str, Any] = {}
            for key, raw in _XML_PARAM.findall(body):
                try:
                    val = json.loads(raw)
                except json.JSONDecodeError:
                    val = raw
                # Numbers and booleans become typed; text (file content
                # included) stays exactly as written.
                args[key] = val if isinstance(val, (bool, int, float)) else raw
            calls.append(ToolCall(id=f"call_text_{len(calls)}", name=name, arguments=args))
        return calls

    def _extract_text_tool_calls(self, text: str) -> list[ToolCall]:
        """Pull {"tool"|"name": "...", "arguments": {...}} objects out of model text.

        Scans for every top-level JSON object, so it accepts fenced
        ```tool_call blocks, <tool_call> tags, and bare JSON (one or several
        per message, with nested arguments). Local Qwen builds served by
        Ollama often emit tool calls this way instead of structured
        tool_calls, so the loop must work without server tool support.
        """
        calls = self._extract_xml_tool_calls(text)
        if calls:
            return calls
        decoder = json.JSONDecoder()
        i = text.find("{")
        while i != -1:
            try:
                obj, end = decoder.raw_decode(text, i)
            except json.JSONDecodeError:
                i = text.find("{", i + 1)
                continue
            if isinstance(obj, dict):
                name = obj.get("tool") or obj.get("name") or obj.get("function")
                args = obj.get("arguments") or obj.get("args") or obj.get("parameters") or {}
                if isinstance(args, str):
                    args = self._safe_json(args)
                if isinstance(name, str) and name and isinstance(args, dict):
                    calls.append(
                        ToolCall(id=f"call_text_{len(calls)}", name=name, arguments=args)
                    )
            i = text.find("{", end)
        return calls
