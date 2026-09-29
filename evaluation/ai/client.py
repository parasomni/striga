"""
LLM backend client for the AI evaluation layer.

The rest of the layer (evaluator.py, __init__.build_evaluator) depends on exactly
this surface:

    LLMClient(provider, model, base_url, api_key, timeout, temperature, retries, options)
    client.health() -> bool
    client.complete_json(system: str, user: str, schema: dict) -> dict   # {"findings": [...]}

Two backends are supported with no extra dependency (uses `requests`, already a
Striga dependency):

  * ollama  -> POST {base_url}/api/chat with `format=<json schema>` (Ollama's
              structured-output mode), `stream=false`.
  * openai  -> POST {base_url}/v1/chat/completions with
              `response_format={"type":"json_object"}` and a Bearer key.
              Anything that isn't "ollama" is treated as OpenAI-compatible
              (vLLM, llama.cpp server, LM Studio, etc.).

complete_json never trusts the model to return clean JSON: the content is parsed
leniently (code-fence stripping + first balanced object) so a chatty local model
doesn't blow up the run. Network/5xx errors are retried; a genuinely unparseable
non-empty response raises so evaluator.py records it as a per-item notice rather
than silently dropping a module's output.
"""

from __future__ import annotations

import json
import re
from typing import Any

import requests


class LLMClient:
    def __init__(
        self,
        provider: str = "ollama",
        model: str = "qwen2.5:14b-instruct",
        base_url: str = "http://127.0.0.1:11434",
        api_key: str | None = None,
        timeout: int = 120,
        temperature: float = 0.0,
        retries: int = 2,
        options: dict[str, Any] | None = None,
    ):
        self.provider = (provider or "ollama").strip().lower()
        self.model = model
        self.base_url = (base_url or "").rstrip("/")
        self.api_key = api_key
        self.timeout = int(timeout)
        self.temperature = float(temperature)
        self.retries = max(0, int(retries))
        self.options = options or {}

    @property
    def _is_ollama(self) -> bool:
        return self.provider == "ollama"

    # -- reachability -------------------------------------------------------

    def health(self) -> bool:
        """Cheap liveness probe so run_ai_evaluation can skip (not crash) when the
        backend is down. Never raises."""
        try:
            if self._is_ollama:
                resp = requests.get(f"{self.base_url}/api/tags", timeout=min(self.timeout, 10))
            else:
                resp = requests.get(
                    f"{self.base_url}/v1/models",
                    headers=self._headers(),
                    timeout=min(self.timeout, 10),
                )
            return resp.status_code < 500
        except requests.RequestException:
            return False

    # -- completion ---------------------------------------------------------

    def complete_json(self, system: str, user: str, schema: dict[str, Any]) -> dict[str, Any]:
        """Run one chat completion and return the parsed JSON object. Retries on
        transient network/5xx failures; raises on a non-empty unparseable body."""
        content = self._chat(system, user, schema)
        if not content or not content.strip():
            return {"findings": []}
        parsed = _lenient_json(content)
        if parsed is None:
            raise ValueError(f"LLM returned unparseable JSON: {content[:200]!r}")
        if isinstance(parsed, list):
            return {"findings": parsed}
        if not isinstance(parsed, dict):
            return {"findings": []}
        return parsed

    # -- backends -----------------------------------------------------------

    def _chat(self, system: str, user: str, schema: dict[str, Any]) -> str:
        last_exc: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                if self._is_ollama:
                    return self._chat_ollama(system, user, schema)
                return self._chat_openai(system, user)
            except (requests.RequestException, ValueError) as exc:
                last_exc = exc
                if attempt >= self.retries:
                    break
        raise RuntimeError(f"LLM request failed after {self.retries + 1} attempt(s): {last_exc}")

    def _chat_ollama(self, system: str, user: str, schema: dict[str, Any]) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "format": schema,  # Ollama structured outputs (JSON schema)
            "options": {"temperature": self.temperature, **self.options},
        }
        resp = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        return (data.get("message") or {}).get("content", "")

    def _chat_openai(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
            "response_format": {"type": "json_object"},
            "stream": False,
            **self.options,
        }
        resp = requests.post(
            f"{self.base_url}/v1/chat/completions",
            json=payload,
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        choices = data.get("choices") or []
        if not choices:
            return ""
        return (choices[0].get("message") or {}).get("content", "")

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers


_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


def _lenient_json(text: str) -> Any:
    """Parse JSON from a model response that may be wrapped in code fences or
    surrounded by chatter. Returns the parsed value, or None if nothing parses."""
    stripped = _FENCE_RE.sub("", text.strip())
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        pass

    # Fall back to the first balanced {...} or [...] span.
    for opener, closer in (("{", "}"), ("[", "]")):
        start = stripped.find(opener)
        if start == -1:
            continue
        depth = 0
        for i in range(start, len(stripped)):
            ch = stripped[i]
            if ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    candidate = stripped[start:i + 1]
                    try:
                        return json.loads(candidate)
                    except (json.JSONDecodeError, ValueError):
                        break
    return None
