"""Discovery sandbox entrypoint. Configuration comes from environment
variables set by the Sandbox Manager; output follows discovery.events."""

from __future__ import annotations

import asyncio
import os
import sys

from discovery.browser.render import Renderer
from discovery.crawler.engine import Config, Crawler
from discovery.events import emit_result


async def run() -> dict:
    target = os.environ.get("ROUTES_TARGET_URL", "")
    proxy = os.environ.get("ROUTES_PROXY_URL") or None
    if not target:
        return {"fatal": True, "error": "No target URL configured."}
    if proxy is None:
        # Fail closed: discovery never runs without the controlled gateway.
        return {"fatal": True, "error": "No network gateway configured for this sandbox."}
    max_pages = min(int(os.environ.get("ROUTES_MAX_PAGES", "25")), 25)
    config = Config(target_url=target, max_pages=max_pages, proxy_url=proxy)
    crawler = Crawler(config)
    crawler.renderer = Renderer(crawler.hostname, proxy)
    crawler.renderer._browser = None  # started lazily on the first JS-rendered page
    return await crawler.run()


def main() -> int:
    try:
        result = asyncio.run(run())
    except Exception as exc:  # noqa: BLE001
        result = {"fatal": True, "error": f"Discovery failed unexpectedly ({type(exc).__name__})."}
    emit_result(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
