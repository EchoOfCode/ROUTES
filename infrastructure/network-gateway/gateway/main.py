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
    """Restrict control callers to the control network.

    CONTROL_SUBNET (set by docker-compose) is authoritative; otherwise fall
    back to the networks attached at startup, narrowed to the one containing
    the Sandbox Manager if it is resolvable."""
    configured = os.environ.get("CONTROL_SUBNET", "").strip()
    if configured:
        return [ipaddress.ip_network(configured, strict=False)]
    nets = startup_networks()
    try:
        manager_ip = ipaddress.ip_address(socket.gethostbyname(os.environ.get("CONTROL_PEER_HOST", "sandbox-manager")))
        nets = [n for n in nets if manager_ip in n] or nets
    except (OSError, ValueError):
        log.warning("sandbox-manager not resolvable at startup; allowing all startup networks")
    return nets


MODEL_SESSION_BYTES = 50 * 1024 ** 3   # generous: prompts and replies only


def model_session(store: SessionStore, env=os.environ):
    """The remediation worker's only route to the internet: a fixed session
    bound to the internal model-egress network, HTTPS CONNECT on 443 to the
    configured provider hosts only. Not configured -> no route (fail closed)."""
    from routes_shared.netpolicy import normalise_hostname

    token = env.get("MODEL_EGRESS_TOKEN", "").strip()
    subnet = env.get("MODEL_EGRESS_SUBNET", "").strip()
    hosts = [h.strip() for h in env.get("MODEL_EGRESS_HOSTS", "").split(",") if h.strip()]
    if not (token and subnet and hosts):
        log.info("model egress not configured: the remediation worker has no outbound route")
        return None
    if len(token) < 24:
        raise SystemExit("MODEL_EGRESS_TOKEN must be 24+ characters")
    allowed = frozenset(normalise_hostname(h) for h in hosts)
    session = store.create(token=token, mode="models", allowed_hosts=allowed, allowed_ports=frozenset({443}),
                           subnet=ipaddress.ip_network(subnet, strict=False), expires_at=float("inf"),
                           max_bytes=MODEL_SESSION_BYTES)
    log.info("model egress: %s -> %s (HTTPS only)", subnet, ", ".join(sorted(allowed)))
    return session


async def main() -> None:
    token = os.environ.get("GATEWAY_CONTROL_TOKEN", "")
    if len(token) < 24:
        raise SystemExit("GATEWAY_CONTROL_TOKEN must be set (24+ characters)")
    dev_hosts = frozenset(h.strip().lower() for h in os.environ.get("GATEWAY_DEV_ALLOW_HOSTS", "").split(",") if h.strip())
    if dev_hosts:
        log.warning("DEVELOPMENT ALLOWLIST ACTIVE: private addresses permitted for %s", ", ".join(sorted(dev_hosts)))
    store = SessionStore()
    model_session(store)
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
