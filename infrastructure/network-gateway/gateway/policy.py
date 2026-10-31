"""Destination policy: DNS resolution + address validation performed by the
gateway itself. Connections are made to the validated address, never to a
second resolution, which closes the DNS-rebinding window."""

from __future__ import annotations

import asyncio
import ipaddress
import socket

from routes_shared.netpolicy import is_blocked_ip, normalise_hostname


class PolicyDenied(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _dev_address_ok(addr: str) -> bool:
    """Dev-allowlisted hosts may be private (Docker networks) but never
    loopback, link-local/metadata, multicast or unspecified."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


Resolver = "callable(host, port) -> awaitable[list[str]]"


async def system_resolve(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP), timeout=5
        )
    except (socket.gaierror, TimeoutError, UnicodeError) as exc:
        raise PolicyDenied("dns_resolution_failed") from exc
    return list(dict.fromkeys(i[4][0] for i in infos))


async def resolve_validated(host: str, port: int, *, dev_hosts: frozenset[str], resolver=system_resolve) -> list[str]:
    host = normalise_hostname(host.strip("[]"))
    addresses = await resolver(host, port)
    if not addresses:
        raise PolicyDenied("dns_no_addresses")
    if host in dev_hosts:
        if not all(_dev_address_ok(a) for a in addresses):
            raise PolicyDenied("blocked_address")
        return addresses
    # Strict: if any resolved address is internal the whole destination is refused.
    if any(is_blocked_ip(a) for a in addresses):
        raise PolicyDenied("blocked_address")
    return addresses


def check_scope(host: str, port: int, allowed_hosts: frozenset[str], allowed_ports: frozenset[int]) -> str:
    try:
        normalised = normalise_hostname(host.strip("[]"))
    except Exception as exc:  # noqa: BLE001
        raise PolicyDenied("invalid_host") from exc
    if normalised not in allowed_hosts:
        raise PolicyDenied("host_out_of_scope")
    if port not in allowed_ports:
        raise PolicyDenied("port_not_allowed")
    return normalised
