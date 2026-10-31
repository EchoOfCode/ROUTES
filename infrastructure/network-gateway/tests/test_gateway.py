"""Gateway enforcement tests. A local upstream stands in for the internet; a
fake resolver decides what each hostname "resolves" to so SSRF, scope and
rebinding cases are deterministic."""

import asyncio
import base64
import ipaddress
import time

import pytest
from gateway.github_import import GithubFetcher
from gateway.proxy import ProxyServer
from gateway.sessions import GithubImport, SessionStore

PUBLIC = "93.184.215.14"


class Upstream:
    """Tiny HTTP server recording requests; responds per path."""

    def __init__(self, routes=None):
        self.requests: list[bytes] = []
        self.routes = routes or {}

    async def handle(self, reader, writer):
        data = await reader.readuntil(b"\r\n\r\n")
        self.requests.append(data)
        path = data.split(b" ")[1].decode()
        status, headers, body = self.routes.get(path, (200, {}, b"hello"))
        head = f"HTTP/1.1 {status} X\r\nContent-Length: {len(body)}\r\nConnection: close\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        writer.write(head.encode() + b"\r\n" + body)
        await writer.drain()
        writer.close()


async def _start(handler):
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def make_resolver(table, calls=None):
    async def resolve(host, port):
        if calls is not None:
            calls.append(host)
        value = table.get(host)
        if callable(value):
            return value()
        if value is None:
            from gateway.policy import PolicyDenied
            raise PolicyDenied("dns_resolution_failed")
        return value
    return resolve


def make_opener(upstream_port, seen):
    async def opener(addresses, port, *, tls_host=None):
        seen.append((tuple(addresses), port, tls_host))
        return await asyncio.open_connection("127.0.0.1", upstream_port)
    return opener


def web_session(store, host="example.com", subnet="127.0.0.0/8", **kw):
    return store.create(mode="web", allowed_hosts=frozenset({host}), allowed_ports=frozenset({80, 443}),
                        subnet=ipaddress.ip_network(subnet), expires_at=time.time() + 60,
                        max_bytes=kw.pop("max_bytes", 10_000_000), **kw)


def auth(token):
    return "Proxy-Authorization: Basic " + base64.b64encode(f"routes:{token}".encode()).decode() + "\r\n"


async def _request(port, raw: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(raw)
    await writer.drain()
    data = await asyncio.wait_for(reader.read(-1), 10)
    writer.close()
    return data


def run(coro):
    return asyncio.run(coro)


async def _harness(resolver_table, routes=None, session_kw=None, github=None):
    upstream = Upstream(routes)
    up_server, up_port = await _start(upstream.handle)
    store = SessionStore()
    seen = []
    calls = []
    proxy = ProxyServer(store, resolver=make_resolver(resolver_table, calls), opener=make_opener(up_port, seen),
                        github_fetch=github)
    px_server, px_port = await _start(proxy.handle)
    return upstream, store, seen, calls, px_port, (up_server, px_server)


def test_requires_proxy_auth():
    async def go():
        _, _, _, _, port, servers = await _harness({"example.com": [PUBLIC]})
        out = await _request(port, b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        assert out.startswith(b"HTTP/1.1 407") and b"Proxy-Authenticate: Basic" in out
    run(go())


def test_forwards_in_scope_get_and_strips_credentials():
    async def go():
        upstream, store, seen, _, port, _ = await _harness({"example.com": [PUBLIC]})
        s = web_session(store)
        out = await _request(port, (f"GET http://example.com/a?b=1 HTTP/1.1\r\nHost: example.com\r\n{auth(s.token)}\r\n").encode())
        assert out.startswith(b"HTTP/1.1 200") and out.endswith(b"hello")
        sent = upstream.requests[0]
        assert sent.startswith(b"GET /a?b=1 HTTP/1.1") and b"Proxy-Authorization" not in sent
        assert seen[0][0] == (PUBLIC,)
        assert s.events[-1]["decision"] == "allow"
    run(go())


@pytest.mark.parametrize(
    "target,table,reason",
    [
        ("http://www.example.com/", {"www.example.com": [PUBLIC]}, b"host_out_of_scope"),
        ("http://example.com.evil.net/", {"example.com.evil.net": [PUBLIC]}, b"host_out_of_scope"),
        ("http://example.com:22/", {"example.com": [PUBLIC]}, b"port_not_allowed"),
        ("http://example.com/", {"example.com": ["127.0.0.1"]}, b"blocked_address"),
        ("http://example.com/", {"example.com": ["169.254.169.254"]}, b"blocked_address"),
        ("http://example.com/", {"example.com": ["10.0.0.7"]}, b"blocked_address"),
        ("http://example.com/", {"example.com": [PUBLIC, "192.168.0.1"]}, b"blocked_address"),
        ("http://example.com/", {"example.com": ["::ffff:127.0.0.1"]}, b"blocked_address"),
        ("http://example.com/", {"example.com": ["fd00:ec2::254"]}, b"blocked_address"),
        ("http://example.com/", {}, b"dns_resolution_failed"),
    ],
)
def test_denied_destinations(target, table, reason):
    async def go():
        _, store, seen, _, port, _ = await _harness(table)
        s = web_session(store)
        host = target.split("/")[2]
        out = await _request(port, f"GET {target} HTTP/1.1\r\nHost: {host}\r\n{auth(s.token)}\r\n".encode())
        assert out.startswith(b"HTTP/1.1 403") and reason in out
        assert seen == []  # never connected anywhere
        assert s.events[-1]["decision"] == "deny"
    run(go())


def test_ip_literal_targets_blocked_even_if_in_scope():
    async def go():
        _, store, seen, _, port, _ = await _harness({"127.0.0.1": ["127.0.0.1"]})
        s = web_session(store, host="127.0.0.1")
        out = await _request(port, f"CONNECT 127.0.0.1:443 HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        assert b"403" in out.split(b"\r\n")[0] and seen == []
    run(go())


def test_dns_rebinding_connects_only_to_validated_address():
    answers = iter([[PUBLIC], ["127.0.0.1"]])

    async def go():
        _, store, seen, calls, port, _ = await _harness({"example.com": lambda: next(answers)})
        s = web_session(store)
        first = await _request(port, f"GET http://example.com/ HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        second = await _request(port, f"GET http://example.com/ HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        assert first.startswith(b"HTTP/1.1 200")
        assert second.startswith(b"HTTP/1.1 403")  # rebinding to loopback refused
        assert seen == [((PUBLIC,), 80, None)]  # the only connection used the validated address
        assert calls == ["example.com", "example.com"]  # resolved by the gateway per request
    run(go())


def test_wrong_source_subnet_rejected():
    async def go():
        _, store, seen, _, port, _ = await _harness({"example.com": [PUBLIC]})
        s = web_session(store, subnet="10.99.0.0/24")
        out = await _request(port, f"GET http://example.com/ HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        assert out.startswith(b"HTTP/1.1 403") and b"peer_not_allowed" in out
    run(go())


def test_only_get_and_head_without_body():
    async def go():
        _, store, _, _, port, _ = await _harness({"example.com": [PUBLIC]})
        s = web_session(store)
        post = await _request(port, f"POST http://example.com/login HTTP/1.1\r\n{auth(s.token)}Content-Length: 3\r\n\r\nabc".encode())
        assert post.startswith(b"HTTP/1.1 405")
        body = await _request(port, f"GET http://example.com/ HTTP/1.1\r\n{auth(s.token)}Content-Length: 3\r\n\r\nabc".encode())
        assert body.startswith(b"HTTP/1.1 400")
    run(go())


def test_connect_tunnel_and_expired_session():
    async def go():
        upstream, store, seen, _, port, _ = await _harness({"example.com": [PUBLIC]})
        s = web_session(store)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(f"CONNECT example.com:443 HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        await writer.drain()
        assert (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200")
        writer.write(b"GET /tunnelled HTTP/1.1\r\n\r\n")
        await writer.drain()
        assert (await asyncio.wait_for(reader.read(-1), 5)).endswith(b"hello")
        assert seen[0][1] == 443
        s.expires_at = time.time() - 1
        out = await _request(port, f"CONNECT example.com:443 HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        assert out.startswith(b"HTTP/1.1 407")
    run(go())


def test_session_byte_limit():
    async def go():
        _, store, _, _, port, _ = await _harness({"example.com": [PUBLIC]}, routes={"/big": (200, {}, b"x" * 5000)})
        s = web_session(store, max_bytes=2000)
        await _request(port, f"GET http://example.com/big HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        again = await _request(port, f"GET http://example.com/big HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        assert b"session_byte_limit" in again
    run(go())


# ---------------------------------------------------------------- GitHub import


def _import_session(store, token="ghp_secret_token_value_1234567890", ref="main"):
    return store.create(mode="github_import", allowed_hosts=frozenset(), allowed_ports=frozenset({443}),
                        subnet=ipaddress.ip_network("127.0.0.0/8"), expires_at=time.time() + 60,
                        max_bytes=10_000_000, github=GithubImport(owner="acme", repo="app", ref=ref, token=token))


def _github_harness(routes):
    async def go():
        upstream = Upstream(routes)
        up_server, up_port = await _start(upstream.handle)
        seen = []
        fetcher = GithubFetcher(
            resolver=make_resolver({"api.github.com": [PUBLIC], "codeload.github.com": ["140.82.112.10"]}),
            opener=make_opener(up_port, seen), scheme_port=("http", 80),
        )
        store = SessionStore()
        proxy = ProxyServer(store, resolver=make_resolver({}), opener=make_opener(up_port, []), github_fetch=fetcher)
        px_server, px_port = await _start(proxy.handle)
        return upstream, store, seen, px_port
    return go


def test_github_import_redirect_token_scoping_and_single_use():
    routes = {
        "/repos/acme/app/tarball/main": (302, {"Location": "http://codeload.github.com/acme/app/tar.gz/main?token=x"}, b""),
        "/acme/app/tar.gz/main?token=x": (200, {}, b"TARBALL-BYTES"),
    }

    async def go():
        upstream, store, seen, port = await _github_harness(routes)()
        s = _import_session(store)
        out = await _request(port, f"GET /import HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        assert out.startswith(b"HTTP/1.1 200") and b"TARBALL-BYTES" in out and out.endswith(b"0\r\n\r\n")
        api_req, codeload_req = upstream.requests
        assert b"Authorization: Bearer ghp_secret_token_value_1234567890" in api_req
        assert b"Authorization" not in codeload_req  # token never follows redirects
        assert s.github.token is None  # wiped after use
        again = await _request(port, f"GET /import HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        assert again.startswith(b"HTTP/1.1 409")
        # Import sessions cannot be used for general egress.
        connect = await _request(port, f"CONNECT example.com:443 HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        assert connect.startswith(b"HTTP/1.1 403")
    run(go())


def test_github_import_rejects_unexpected_redirect_host():
    routes = {"/repos/acme/app/tarball/main": (302, {"Location": "http://evil.example/steal"}, b"")}

    async def go():
        _, store, _, port = await _github_harness(routes)()
        s = _import_session(store)
        out = await _request(port, f"GET /import HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        assert out.startswith(b"HTTP/1.1 502") and b"import_host_not_allowed" in out
    run(go())


def test_github_import_not_found_message():
    routes = {"/repos/acme/app/tarball/main": (404, {}, b"{}")}

    async def go():
        _, store, _, port = await _github_harness(routes)()
        s = _import_session(store)
        out = await _request(port, f"GET /import HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        assert out.startswith(b"HTTP/1.1 404") and b"not found" in out
    run(go())


def test_public_import_uses_archive_host_without_api_call():
    routes = {"/acme/app/tar.gz/HEAD": (200, {}, b"PUBLIC-TARBALL")}

    async def go():
        upstream, store, seen, port = await _github_harness(routes)()
        s = _import_session(store, token=None, ref=None)
        out = await _request(port, f"GET /import HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        assert out.startswith(b"HTTP/1.1 200") and b"PUBLIC-TARBALL" in out
        (req,) = upstream.requests  # exactly one request, to the archive host
        assert req.startswith(b"GET /acme/app/tar.gz/HEAD ") and b"Host: codeload.github.com" in req
        assert b"Authorization" not in req
        assert seen[0][0] == ("140.82.112.10",)
    run(go())


def test_public_import_not_found_suggests_private_connection():
    routes = {"/acme/app/tar.gz/main": (404, {}, b"")}

    async def go():
        _, store, _, port = await _github_harness(routes)()
        s = _import_session(store, token=None)
        out = await _request(port, f"GET /import HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        assert out.startswith(b"HTTP/1.1 404") and b"private repository with a token" in out
    run(go())


@pytest.mark.parametrize("status,headers", [
    (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1793450612"}),
    (429, {"Retry-After": "120"}),
])
def test_rate_limit_reported_separately_from_permission_errors(status, headers):
    routes = {"/repos/acme/app/tarball/main": (status, headers, b"{}")}

    async def go():
        _, store, _, port = await _github_harness(routes)()
        s = _import_session(store)
        out = await _request(port, f"GET /import HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        assert out.startswith(b"HTTP/1.1 429") and b"rate limit" in out and b"permission" not in out
        assert s.events[-1]["reason"] == "import_rate_limited"
    run(go())


def test_permission_error_without_rate_limit_headers():
    routes = {"/repos/acme/app/tarball/main": (403, {"X-RateLimit-Remaining": "4999"}, b"{}")}

    async def go():
        _, store, _, port = await _github_harness(routes)()
        s = _import_session(store)
        out = await _request(port, f"GET /import HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        assert out.startswith(b"HTTP/1.1 403") and b"Contents: Read-only" in out
    run(go())


def test_web_session_cannot_import():
    async def go():
        _, store, _, _, port, _ = await _harness({}, github=GithubFetcher())
        s = web_session(store)
        out = await _request(port, f"GET /import HTTP/1.1\r\n{auth(s.token)}\r\n".encode())
        assert out.startswith(b"HTTP/1.1 403")
    run(go())
