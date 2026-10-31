"""Entry point: runs the egress proxy (:3128) and the control API (:8080)."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
import struct

import uvicorn

from gateway.control import build_control_app
from gateway.github_import import GithubFetcher
from gateway.proxy import MAX_HEAD, ProxyServer
from gateway.sessions import SessionStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("routes.gateway")


def startup_networks() -> list[ipaddress.IPv4Network]:
    """IPv4 networks directly attached at startup, read from /proc/net/route.

    The gateway starts attached only to the control and egress networks;
    sandbox networks are connected later and are thus never control peers.
    """
    nets: list[ipaddress.IPv4Network] = []
    try:
        with open("/proc/net/route") as fh:
            next(fh)
            for line in fh:
                fields = line.split()
                dest, mask = fields[1], fields[7]
                if dest == "00000000":
                    continue
                d = socket.inet_ntoa(struct.pack("<L", int(dest, 16)))
                m = socket.inet_ntoa(struct.pack("<L", int(mask, 16)))
                nets.append(ipaddress.ip_network(f"{d}/{m}", strict=False))
    except OSError:
        log.error("could not read routing table; control API will reject all peers")
    return nets


def control_peers() -> list[ipaddress.IPv4Network]:
    """Restrict control callers to the control network when its subnet is known."""
    nets = startup_networks()
    try:
        manager_ip = ipaddress.ip_address(socket.gethostbyname(os.environ.get("CONTROL_PEER_HOST", "sandbox-manager")))
        nets = [n for n in nets if manager_ip in n] or nets
    except (OSError, ValueError):
        log.warning("sandbox-manager not resolvable at startup; allowing all startup networks")
    return nets


async def main() -> None:
    token = os.environ.get("GATEWAY_CONTROL_TOKEN", "")
    if len(token) < 24:
        raise SystemExit("GATEWAY_CONTROL_TOKEN must be set (24+ characters)")
    dev_hosts = frozenset(h.strip().lower() for h in os.environ.get("GATEWAY_DEV_ALLOW_HOSTS", "").split(",") if h.strip())
    if dev_hosts:
        log.warning("DEVELOPMENT ALLOWLIST ACTIVE: private addresses permitted for %s", ", ".join(sorted(dev_hosts)))
    store = SessionStore()
    peers = control_peers()
    log.info("control API peers: %s", ", ".join(map(str, peers)) or "none")
    proxy = ProxyServer(store, dev_hosts=dev_hosts, github_fetch=GithubFetcher())
    server = await asyncio.start_server(proxy.handle, host="0.0.0.0", port=3128, limit=MAX_HEAD)
    control = uvicorn.Server(uvicorn.Config(build_control_app(store, token=token, allowed_peers=peers),
                                            host="0.0.0.0", port=8080, log_level="warning", access_log=False))

    async def sweeper():
        while True:
            await asyncio.sleep(30)
            store.sweep()

    log.info("gateway listening: proxy :3128, control :8080")
    async with server:
        await asyncio.gather(server.serve_forever(), control.serve(), sweeper())


if __name__ == "__main__":
    asyncio.run(main())
