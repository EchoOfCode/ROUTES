"""Forward proxy enforcing ROUTES egress policy for sandbox containers.

Sandbox containers live on Docker networks created with ``internal: true``;
their only reachable peer is this gateway, so the policy below is not
bypassable by ignoring proxy environment variables.

Supported:
  * ``CONNECT host:port`` (HTTPS tunnelling) for web-discovery sessions.
  * Absolute-form ``GET``/``HEAD`` for plain HTTP in web-discovery sessions.
  * ``GET /import`` for GitHub import sessions (see github_import.py).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import ipaddress
import logging
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from gateway.policy import PolicyDenied, check_scope, resolve_validated, system_resolve
from gateway.sessions import Session, SessionStore

log = logging.getLogger("routes.gateway.proxy")

MAX_HEAD = 16 * 1024
HEAD_TIMEOUT = 15
CONNECT_TIMEOUT = 10
IDLE_TIMEOUT = 30
MAX_CONNECTION_SECONDS = 180
CHUNK = 64 * 1024
_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authorization", "proxy-authenticate", "proxy-connection",
    "te", "trailer", "transfer-encoding", "upgrade", "host",
}


class ProxyError(Exception):
    def __init__(self, status: int, reason: str, message: str = ""):
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.message = message or reason


@dataclass
class Request:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]

    def header(self, name: str) -> str | None:
        name = name.lower()
        for k, v in self.headers:
            if k == name:
                return v
        return None


def parse_head(raw: bytes) -> Request:
    try:
        text = raw.decode("latin-1")
    except UnicodeDecodeError as exc:  # pragma: no cover - latin-1 never fails
        raise ProxyError(400, "bad_request") from exc
    lines = text.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[2] not in ("HTTP/1.1", "HTTP/1.0") or not _TOKEN_RE.match(parts[0]):
        raise ProxyError(400, "bad_request_line")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if line == "":
            continue
        if line[0] in " \t" or ":" not in line:
            raise ProxyError(400, "bad_header")
        name, value = line.split(":", 1)
        if not _TOKEN_RE.match(name):
            raise ProxyError(400, "bad_header")
        if "\r" in value or "\n" in value or "\x00" in value:
            raise ProxyError(400, "bad_header")
        headers.append((name.lower(), value.strip()))
    return Request(method=parts[0], target=parts[1], version=parts[2], headers=headers)


def _extract_token(req: Request) -> str | None:
    value = req.header("proxy-authorization")
    if not value:
        return None
    scheme, _, credentials = value.partition(" ")
    if scheme.lower() == "bearer":
        return credentials.strip()
    if scheme.lower() == "basic":
        try:
            decoded = base64.b64decode(credentials.strip(), validate=True).decode()
        except (binascii.Error, UnicodeDecodeError):
            return None
        _, _, password = decoded.partition(":")
        return password
    return None


def _split_authority(authority: str, default_port: int) -> tuple[str, int]:
    if authority.startswith("["):
        host, _, rest = authority[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    elif authority.count(":") == 1:
        host, port = authority.split(":")
    else:
        host, port = authority, ""
    if not host:
        raise ProxyError(400, "bad_target")
    if port:
        if not port.isdigit() or not (0 < int(port) < 65536):
            raise ProxyError(400, "bad_target")
        return host, int(port)
    return host, default_port


async def _write_error(writer: asyncio.StreamWriter, status: int, reason: str, message: str, extra: str = "") -> None:
    phrase = {400: "Bad Request", 403: "Forbidden", 405: "Method Not Allowed", 407: "Proxy Authentication Required",
              409: "Conflict", 413: "Payload Too Large", 502: "Bad Gateway", 504: "Gateway Timeout",
              404: "Not Found"}.get(status, "Error")
    body = (message + "\n").encode()
    head = (
        f"HTTP/1.1 {status} {phrase}\r\nContent-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\nX-Routes-Gateway-Reason: {reason}\r\nConnection: close\r\n{extra}\r\n"
    )
    try:
        writer.write(head.encode() + body)
        await writer.drain()
    except (ConnectionError, RuntimeError):
        pass


async def default_open(addresses: list[str], port: int, *, tls_host: str | None = None):
    """Connect to the first reachable *validated* address."""
    last: Exception | None = None
    for addr in addresses:
        try:
            if tls_host:
                import ssl

                ctx = ssl.create_default_context()
                return await asyncio.wait_for(
                    asyncio.open_connection(addr, port, ssl=ctx, server_hostname=tls_host), CONNECT_TIMEOUT
                )
            return await asyncio.wait_for(asyncio.open_connection(addr, port), CONNECT_TIMEOUT)
        except (OSError, TimeoutError) as exc:
            last = exc
    raise ProxyError(502, "upstream_unreachable", f"Could not connect: {type(last).__name__ if last else 'none'}")


class ProxyServer:
    def __init__(self, store: SessionStore, *, dev_hosts: frozenset[str] = frozenset(),
                 resolver=system_resolve, opener=default_open, github_fetch=None):
        self.store = store
        self.dev_hosts = dev_hosts
        self.resolver = resolver
        self.opener = opener
        self.github_fetch = github_fetch

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = (writer.get_extra_info("peername") or ("0.0.0.0", 0))[0]
        session: Session | None = None
        req: Request | None = None
        try:
            try:
                raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT)
            except (asyncio.LimitOverrunError, asyncio.IncompleteReadError, TimeoutError, ValueError) as exc:
                raise ProxyError(400, "bad_request") from exc
            req = parse_head(raw[:-4])
            session = self._authenticate(req, peer)
            session.connections += 1
            if req.method == "CONNECT":
                await self._connect(session, req, reader, writer)
            elif req.method == "GET" and urlsplit(req.target).path == "/import":
                await self._import(session, req, writer)
            elif req.method in ("GET", "HEAD"):
                await self._forward(session, req, writer)
            else:
                raise ProxyError(405, "method_not_allowed", "Only GET and HEAD requests are permitted.")
        except ProxyError as exc:
            if session is not None:
                session.record(decision="deny", reason=exc.reason, method=req.method if req else None,
                               target=(req.target[:300] if req else None))
            extra = 'Proxy-Authenticate: Basic realm="routes"\r\n' if exc.status == 407 else ""
            await _write_error(writer, exc.status, exc.reason, exc.message, extra)
        except Exception:  # noqa: BLE001
            log.exception("unexpected proxy error")
            await _write_error(writer, 502, "gateway_error", "Gateway error.")
        finally:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), 5)
            except (ConnectionError, TimeoutError, RuntimeError):
                pass

    def _authenticate(self, req: Request, peer: str) -> Session:
        session = self.store.by_token(_extract_token(req))
        if session is None:
            raise ProxyError(407, "proxy_auth_required", "Proxy authentication required.")
        try:
            peer_ip = ipaddress.ip_address(peer)
        except ValueError as exc:
            raise ProxyError(403, "peer_not_allowed") from exc
        if isinstance(peer_ip, ipaddress.IPv6Address) and peer_ip.ipv4_mapped:
            peer_ip = peer_ip.ipv4_mapped
        if peer_ip not in session.subnet:
            raise ProxyError(403, "peer_not_allowed", "This session is not valid from this network.")
        if session.bytes_in + session.bytes_out > session.max_bytes:
            raise ProxyError(403, "session_byte_limit", "The session's transfer limit has been reached.")
        return session

    async def _validated(self, session: Session, host: str, port: int) -> tuple[str, list[str]]:
        if session.mode != "web":
            raise ProxyError(403, "mode_forbids_egress", "This session cannot make outbound connections.")
        try:
            host = check_scope(host, port, session.allowed_hosts, session.allowed_ports)
            addresses = await resolve_validated(host, port, dev_hosts=self.dev_hosts, resolver=self.resolver)
        except PolicyDenied as exc:
            session.record(decision="deny", reason=exc.reason, host=host, port=port)
            raise ProxyError(403, exc.reason, f"Destination refused by ROUTES policy ({exc.reason}).") from exc
        return host, addresses

    async def _connect(self, session: Session, req: Request, reader, writer) -> None:
        host, port = _split_authority(req.target, 443)
        host, addresses = await self._validated(session, host, port)
        up_reader, up_writer = await self.opener(addresses, port)
        peer_ip = (up_writer.get_extra_info("peername") or (addresses[0],))[0]
        session.record(decision="allow", method="CONNECT", host=host, port=port, ip=peer_ip)
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await self._pipe_both(session, reader, writer, up_reader, up_writer)

    async def _forward(self, session: Session, req: Request, writer) -> None:
        parts = urlsplit(req.target)
        if parts.scheme != "http" or not parts.netloc:
            raise ProxyError(400, "absolute_http_url_required", "Use CONNECT for HTTPS destinations.")
        if (req.header("content-length") or "0") != "0" or req.header("transfer-encoding"):
            raise ProxyError(400, "request_body_not_allowed", "Requests with bodies are not permitted.")
        if "@" in parts.netloc:
            raise ProxyError(400, "bad_target")
        host, port = _split_authority(parts.netloc, 80)
        host, addresses = await self._validated(session, host, port)
        up_reader, up_writer = await self.opener(addresses, port)
        peer_ip = (up_writer.get_extra_info("peername") or (addresses[0],))[0]
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        lines = [f"{req.method} {path} HTTP/1.1", f"Host: {parts.netloc}"]
        lines += [f"{k}: {v}" for k, v in req.headers if k not in HOP_BY_HOP]
        lines += ["Connection: close", "", ""]
        up_writer.write("\r\n".join(lines).encode("latin-1"))
        await up_writer.drain()
        session.record(decision="allow", method=req.method, host=host, port=port, ip=peer_ip, path=path[:300])
        try:
            await self._pipe(session, up_reader, writer, inbound=True)
        finally:
            up_writer.close()

    async def _import(self, session: Session, req: Request, writer) -> None:
        if session.mode != "github_import" or session.github is None or self.github_fetch is None:
            raise ProxyError(403, "import_not_permitted", "This session cannot import repositories.")
        await self.github_fetch(session, writer)

    async def _pipe(self, session: Session, src: asyncio.StreamReader, dst: asyncio.StreamWriter, *, inbound: bool) -> None:
        while True:
            try:
                data = await asyncio.wait_for(src.read(CHUNK), IDLE_TIMEOUT)
            except (TimeoutError, ConnectionError):
                return
            if not data:
                return
            if inbound:
                session.bytes_in += len(data)
            else:
                session.bytes_out += len(data)
            if session.bytes_in + session.bytes_out > session.max_bytes:
                session.record(decision="deny", reason="session_byte_limit")
                return
            try:
                dst.write(data)
                await dst.drain()
            except (ConnectionError, RuntimeError):
                return

    async def _pipe_both(self, session, c_reader, c_writer, u_reader, u_writer) -> None:
        tasks = [
            asyncio.create_task(self._pipe(session, c_reader, u_writer, inbound=False)),
            asyncio.create_task(self._pipe(session, u_reader, c_writer, inbound=True)),
        ]
        try:
            await asyncio.wait(tasks, timeout=MAX_CONNECTION_SECONDS, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in tasks:
                t.cancel()
            u_writer.close()
