"""pyscan -- offline, local-LLM security hunt framework.

Runs fully offline against a
local OpenAI-compatible model server (Qwen3-Coder-Next by default,
served by vLLM, Ollama, or llama.cpp).

No module in this package makes outbound network calls except pyscan.llm,
which talks only to the configured local model endpoint.
"""

__version__ = "0.1.0"
