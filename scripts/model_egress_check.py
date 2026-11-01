"""Live check of worker-remediate's model-provider route.

Run in a container attached ONLY to the internal `model-egress` network
(where worker-remediate lives), with MODEL_EGRESS_TOKEN set to the gateway's:
  - an allowed provider is reachable over HTTPS through the gateway;
  - any other host is refused by the gateway;
  - plain HTTP is refused;
  - a wrong token is refused;
  - there is no direct route to the internet at all.
Only TLS handshakes / unauthenticated requests are made; no API key is used.
"""

from __future__ import annotations

import os
import sys

import httpx

TOKEN = os.environ["MODEL_EGRESS_TOKEN"]
GW = "network-gateway:3128"
RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str) -> None:
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}  ({detail})", flush=True)


def get(url: str, *, proxy: str | None) -> tuple[int | None, str]:
    try:
        with httpx.Client(proxy=proxy, trust_env=False, timeout=15) as c:
            r = c.get(url)
            return r.status_code, r.text[:120].replace("\n", " ")
    except httpx.ProxyError as exc:
        return None, f"proxy refused: {exc}"
    except httpx.HTTPError as exc:
        return None, f"{type(exc).__name__}: {exc}"


ok_proxy = f"http://routes:{TOKEN}@{GW}"
status, detail = get("https://api.groq.com/openai/v1/models", proxy=ok_proxy)
check("allowed provider reachable through the gateway (HTTPS)", status is not None, f"HTTP {status}")
status, detail = get("https://example.com/", proxy=ok_proxy)
check("other hosts refused by the gateway", status is None and "403" in detail, detail[:120])
status, detail = get("http://api.groq.com/", proxy=ok_proxy)
check("plain HTTP refused", status in (403, None), f"HTTP {status} {detail[:80]}")
status, detail = get("https://api.groq.com/openai/v1/models", proxy=f"http://routes:{'x' * 32}@{GW}")
check("wrong token refused", status is None and "407" in detail, detail[:120])
status, detail = get("https://api.groq.com/openai/v1/models", proxy=None)
check("no direct route to the internet", status is None, detail[:120])
print(f"{sum(o for _, o, _ in RESULTS)}/{len(RESULTS)} checks passed")
sys.exit(0 if all(o for _, o, _ in RESULTS) else 1)
