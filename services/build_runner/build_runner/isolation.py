"""Network isolation handshake and self-check for the build runner.

After dependencies are installed the runner announces ``awaiting_isolation``.
The Sandbox Manager then closes the gateway session, detaches the gateway and
this container from the package network and attaches the container to the
run's private database and test networks only. The runner waits until it can
observe that change itself, then probes a set of destinations that must be
unreachable. Results are reported as evidence; any destination that accepts a
connection makes the run fail closed.
"""

from __future__ import annotations

import errno
import ipaddress
import os
import socket
import struct
import time
from dataclasses import dataclass

CONNECT_TIMEOUT = 1.5
# Ports probed on each attached network's bridge (host-side) address: SSH, web,
# Docker engine, and ports local development stacks commonly publish.
BRIDGE_PORTS = (22, 80, 443, 2375, 2376, 3000, 3100, 5432, 6379, 8000, 8080, 8100, 8190)


@dataclass
class Probe:
    label: str
    host: str
    port: int
    expected: str = "blocked"     # "blocked" | "allowed"


def tcp_state(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> str:
    """connected | refused | timeout | unreachable | dns_failed"""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return "dns_failed"
    state = "unreachable"
    for family, kind, proto, _, addr in infos[:3]:
        s = socket.socket(family, kind, proto)
        s.settimeout(timeout)
        try:
            s.connect(addr)
            return "connected"
        except socket.timeout:
            state = "timeout"
        except ConnectionRefusedError:
            state = "refused"
        except OSError as exc:
            state = "unreachable" if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL) else "unreachable"
        finally:
            s.close()
    return state


def interfaces(root: str = "/sys/class/net") -> list[str]:
    try:
        return sorted(n for n in os.listdir(root) if n != "lo")
    except OSError:
        return []


def local_subnets(route_file: str = "/proc/net/route") -> list[ipaddress.IPv4Network]:
    """Directly connected IPv4 subnets (one per attached Docker network)."""
    nets: list[ipaddress.IPv4Network] = []
    try:
        lines = open(route_file, encoding="ascii").read().splitlines()[1:]
    except OSError:
        return nets
    for line in lines:
        cols = line.split()
        if len(cols) < 8:
            continue
        dest, gateway, mask = (struct.pack("<L", int(c, 16)) for c in (cols[1], cols[2], cols[7]))
        if gateway != b"\0\0\0\0" or dest == b"\0\0\0\0":
            continue
        try:
            nets.append(ipaddress.IPv4Network(f"{socket.inet_ntoa(dest)}/{socket.inet_ntoa(mask)}"))
        except ValueError:
            continue
    return nets


def has_default_route(route_file: str = "/proc/net/route") -> bool:
    try:
        lines = open(route_file, encoding="ascii").read().splitlines()[1:]
    except OSError:
        return False
    return any(len(c := line.split()) > 1 and c[1] == "00000000" for line in lines)


def wait_for_cut(gateway: tuple[str, int] | None, expected_interfaces: int, timeout: float) -> bool:
    """True once the gateway is unreachable and exactly the expected private networks are attached."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if len(interfaces()) == expected_interfaces and (gateway is None or tcp_state(*gateway, timeout=1.0) != "connected"):
            return True
        time.sleep(1.0)
    return False


def forbidden_probes(gateway_ip: str | None, extra: list[Probe] | None = None) -> list[Probe]:
    probes = [
        Probe("cloud metadata service", "169.254.169.254", 80),
        Probe("public internet (HTTPS)", "1.1.1.1", 443),
        Probe("public internet (DNS)", "8.8.8.8", 53),
        Probe("package registry", "registry.npmjs.org", 443),
        Probe("GitHub", "github.com", 443),
        Probe("Docker host alias", "host.docker.internal", 80),
        Probe("Docker host alias (engine API)", "host.docker.internal", 2375),
    ]
    if gateway_ip:
        probes.append(Probe("ROUTES network gateway", gateway_ip, 3128))
    for net in local_subnets():
        bridge = str(next(net.hosts()))      # Docker assigns the first address to the bridge
        for port in BRIDGE_PORTS:
            probes.append(Probe(f"Docker bridge address {bridge}", bridge, port))
    return probes + (extra or [])


def run_probes(probes: list[Probe]) -> dict:
    results = []
    violations = []
    for p in probes:
        state = tcp_state(p.host, p.port)
        ok = (state == "connected") if p.expected == "allowed" else (state != "connected")
        results.append({"target": p.label, "host": p.host, "port": p.port, "expected": p.expected, "observed": state,
                        "ok": ok})
        if not ok:
            violations.append(f"{p.label} ({p.host}:{p.port}) was {state}, expected {p.expected}")
    return {"default_route": has_default_route(), "interfaces": len(interfaces()), "probes": results,
            "violations": violations, "verdict": "isolated" if not violations else "violated"}
