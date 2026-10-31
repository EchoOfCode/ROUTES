"""Network safety policy shared by the API (early validation), the network
gateway (authoritative enforcement) and the crawler (scope checks).

The gateway is the enforcement point; the API check only exists to give the
developer fast feedback. Neither trusts the other.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})
DEFAULT_PORTS = {"http": 80, "https": 443}

# Addresses that are never acceptable destinations, in addition to anything
# Python already classifies as private / loopback / link-local / reserved.
_EXTRA_BLOCKED_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "100.64.0.0/10",  # carrier-grade NAT
        "169.254.0.0/16",  # link-local, includes 169.254.169.254 metadata
        "192.0.0.0/24",
        "192.0.2.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::/128",
        "::1/128",
        "64:ff9b::/96",  # NAT64 can map to internal IPv4
        "64:ff9b:1::/48",
        "100::/64",
        "2001:db8::/32",
        "fc00::/7",  # unique local, includes fd00:ec2::254 metadata
        "fe80::/10",
        "ff00::/8",
    )
]

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$"
)


class UrlPolicyError(ValueError):
    """Raised when a URL is not an acceptable assessment target."""


def is_blocked_ip(value: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if the address must never be contacted."""
    try:
        ip = ipaddress.ip_address(value) if isinstance(value, str) else value
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped or ip.sixtofour
        if mapped is not None:
            return is_blocked_ip(mapped)
        if ip.teredo is not None:
            return True
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    ):
        return True
    return any(ip in net for net in _EXTRA_BLOCKED_NETWORKS if net.version == ip.version)


def all_addresses_allowed(addresses: list[str]) -> bool:
    """Strict check: every resolved address must be public. An empty list fails."""
    return bool(addresses) and not any(is_blocked_ip(a) for a in addresses)


@dataclass(frozen=True)
class TargetUrl:
    url: str
    scheme: str
    hostname: str
    port: int

    @property
    def origin(self) -> str:
        default = DEFAULT_PORTS[self.scheme]
        netloc = self.hostname if self.port == default else f"{self.hostname}:{self.port}"
        return f"{self.scheme}://{netloc}"


def normalise_hostname(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UrlPolicyError("The hostname is not valid.") from exc
    return host


def parse_target_url(raw: str, *, dev_allow_hosts: frozenset[str] = frozenset()) -> TargetUrl:
    """Validate a developer-submitted website URL (syntax and static policy only).

    DNS resolution is checked separately because it is environment dependent.
    """
    raw = (raw or "").strip()
    if not raw:
        raise UrlPolicyError("Enter a website URL.")
    if len(raw) > 2048:
        raise UrlPolicyError("The URL is too long.")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError as exc:
        raise UrlPolicyError("The URL is not valid.") from exc
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UrlPolicyError("Only http:// and https:// websites can be assessed.")
    if parts.username or parts.password:
        raise UrlPolicyError("URLs containing credentials are not accepted.")
    if not parts.hostname:
        raise UrlPolicyError("The URL must include a hostname.")
    host = normalise_hostname(parts.hostname)
    port = port or DEFAULT_PORTS[scheme]
    if port not in ALLOWED_PORTS:
        raise UrlPolicyError(
            "Only ports 80, 443, 8080 and 8443 are supported for assessments."
        )

    if host in dev_allow_hosts:
        return TargetUrl(url=_rebuild(scheme, host, port, parts.path), scheme=scheme, hostname=host, port=port)

    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        ip = None
    if ip is not None:
        if is_blocked_ip(ip):
            raise UrlPolicyError("Private, loopback and internal addresses cannot be assessed.")
    else:
        if not _HOSTNAME_RE.match(host) or "." not in host:
            raise UrlPolicyError("Enter a public hostname, for example https://example.com.")
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan", ".home.arpa")):
            raise UrlPolicyError("Local and internal hostnames cannot be assessed.")
    return TargetUrl(url=_rebuild(scheme, host, port, parts.path), scheme=scheme, hostname=host, port=port)


def _rebuild(scheme: str, host: str, port: int, path: str) -> str:
    netloc = host if port == DEFAULT_PORTS[scheme] else f"{host}:{port}"
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]" if port == DEFAULT_PORTS[scheme] else f"[{host}]:{port}"
    return urlunsplit((scheme, netloc, path or "/", "", ""))


def same_host(url: str, hostname: str) -> bool:
    """Exact-hostname scope check (subdomains are out of scope)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme.lower() not in ALLOWED_SCHEMES or not parts.hostname:
        return False
    try:
        return normalise_hostname(parts.hostname) == hostname
    except UrlPolicyError:
        return False
