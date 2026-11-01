"""Generic client for an OpenAI-compatible chat-completions endpoint, used
for both LLM A and LLM B (different endpoint/model/key each, same shape).
Called only from worker-remediate, never from a sandbox.

Supports a cached-response mode so a demo can run offline:
  - "live": always call out, never read/write the cache.
  - "record": call out, then save the response to the cache for later replay.
  - "replay": never call out; read from the cache, erroring clearly on a miss.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

import httpx

log = logging.getLogger("routes.worker.llm")

CACHE_MODES = ("live", "record", "replay")


class LLMError(Exception):
    """Raised on a request failure, a cache miss in replay mode, or an
    unparseable response - never silently returns a fabricated answer."""


class LLMClient:
    def __init__(self, *, endpoint: str, api_key: str, model: str, cache_mode: str = "live",
                 cache_dir: str | None = None, timeout: float = 60.0, transport: httpx.BaseTransport | None = None,
                 proxy: str | None = None) -> None:
        if not endpoint or not model:
            raise LLMError("An LLM endpoint and model must be configured.")
        if cache_mode not in CACHE_MODES:
            raise LLMError(f"Unknown LLM cache mode {cache_mode!r}; expected one of {CACHE_MODES}.")
        self.endpoint = endpoint
        self.model = model
        self.cache_mode = cache_mode
        self.cache_dir = Path(cache_dir) if cache_dir else None
        # Usage reported by the provider for the most recent live call
        # (token counts, served model); None for cached replies.
        self.last_usage: dict | None = None
        self._client = httpx.Client(
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            timeout=httpx.Timeout(timeout, connect=10.0),
            transport=transport,
            # The worker's network only reaches the gateway; the route is the
            # model-egress session, never ambient proxy environment variables.
            proxy=proxy, trust_env=False,
        )

    def close(self) -> None:
        self._client.close()

    @property
    def provider(self) -> str:
        """The provider is identified by the endpoint's host, so a new
        provider never needs a code or schema change."""
        return httpx.URL(self.endpoint).host or "unknown"

    def complete(self, messages: list[dict], *, temperature: float = 0.0) -> str:
        self.last_usage = None
        key = self._cache_key(messages, temperature)
        if self.cache_mode == "replay":
            cached = self._read_cache(key)
            if cached is None:
                raise LLMError(f"No cached LLM response for this request (replay mode, cache key {key}).")
            return cached
        content = self._call(messages, temperature)
        if self.cache_mode == "record":
            self._write_cache(key, content)
        return content

    def _call(self, messages: list[dict], temperature: float) -> str:
        try:
            r = self._client.post(self.endpoint, json={"model": self.model, "messages": messages,
                                                        "temperature": temperature})
        except httpx.HTTPError as exc:
            raise LLMError(f"LLM request to {self.endpoint} failed: {exc}") from exc
        if r.status_code != 200:
            raise LLMError(f"LLM request returned {r.status_code}: {r.text[:300]}")
        try:
            body = r.json()
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise LLMError(f"LLM response had an unexpected shape: {exc}") from exc
        usage = body.get("usage") if isinstance(body.get("usage"), dict) else {}
        self.last_usage = {k: usage[k] for k in ("prompt_tokens", "completion_tokens", "total_tokens")
                           if isinstance(usage.get(k), int)}
        if isinstance(body.get("model"), str):
            self.last_usage["model_version"] = body["model"]
        return content

    def _cache_key(self, messages: list[dict], temperature: float) -> str:
        payload = json.dumps({"endpoint": self.endpoint, "model": self.model, "messages": messages,
                              "temperature": temperature}, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()[:40]

    def _cache_path(self, key: str) -> Path:
        if self.cache_dir is None:
            raise LLMError("No cache directory configured; cannot use record/replay cache mode.")
        return self.cache_dir / f"{key}.json"

    def _read_cache(self, key: str) -> str | None:
        path = self._cache_path(key)
        if not path.is_file():
            return None
        return json.loads(path.read_text())["content"]

    def _write_cache(self, key: str, content: str) -> None:
        path = self._cache_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"content": content}))
