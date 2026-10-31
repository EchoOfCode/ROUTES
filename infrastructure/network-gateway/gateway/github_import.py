"""Narrow GitHub import path.

The analyzer sandbox never receives the developer's access token and has no
general egress. It asks the gateway for ``GET /import``; the gateway fetches
the repository archive, applies the same address validation as web traffic,
streams the archive back with a hard size cap, and wipes the token.

* Private repositories (token present): ``api.github.com/repos/{o}/{r}/tarball``
  with the token, following a redirect only to codeload.github.com (without
  the token).
* Public repositories (no token): ``codeload.github.com/{o}/{r}/tar.gz/{ref}``
  directly. This avoids GitHub's unauthenticated REST API limit (60 requests
  per hour per IP), which the archive host does not count against.
"""

from __future__ import annotations

import asyncio
import re
import time
from urllib.parse import quote, urljoin, urlsplit

import h11

from gateway.policy import PolicyDenied, resolve_validated, system_resolve
from gateway.proxy import ProxyError, default_open
from gateway.sessions import Session

ALLOWED_HOSTS = frozenset({"api.github.com", "codeload.github.com"})
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_REDIRECTS = 3
READ_TIMEOUT = 60
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_REF_RE = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")


def build_url(owner: str, repo: str, ref: str | None, *, authenticated: bool, scheme: str = "https") -> str:
    if not _NAME_RE.match(owner) or not _NAME_RE.match(repo) or (ref and (not _REF_RE.match(ref) or ".." in ref)):
        raise ProxyError(400, "invalid_repository", "Invalid repository reference.")
    if not authenticated:
        return f"{scheme}://codeload.github.com/{owner}/{repo}/tar.gz/{quote(ref, safe='/') if ref else 'HEAD'}"
    url = f"{scheme}://api.github.com/repos/{owner}/{repo}/tarball"
    if ref:
        url += "/" + quote(ref, safe="")
    return url


def _rate_limit_message(headers: dict[str, str]) -> str:
    when = ""
    reset = headers.get("x-ratelimit-reset", "")
    if reset.isdigit():
        when = " It resets at " + time.strftime("%H:%M UTC", time.gmtime(int(reset))) + "."
    elif headers.get("retry-after", "").isdigit():
        when = f" Try again in about {max(1, int(headers['retry-after']) // 60)} minute(s)."
    return ("GitHub's rate limit for this network has been reached." + when +
            " Try again later, connect the repository with a token, or upload a ZIP.")


class GithubFetcher:
    def __init__(self, *, resolver=system_resolve, opener=default_open, scheme_port: tuple[str, int] = ("https", 443),
                 allowed_hosts: frozenset[str] = ALLOWED_HOSTS):
        self.resolver = resolver
        self.opener = opener
        self.scheme, self.port = scheme_port  # http/80 only in tests
        self.allowed_hosts = allowed_hosts

    async def __call__(self, session: Session, writer: asyncio.StreamWriter) -> None:
        gh = session.github
        assert gh is not None
        if gh.used:
            raise ProxyError(409, "import_already_used", "This import session has already been used.")
        gh.used = True
        token, gh.token = gh.token, None  # single use: removed from session state immediately
        url = build_url(gh.owner, gh.repo, gh.ref, authenticated=bool(token), scheme=self.scheme)
        try:
            await self._fetch(session, writer, url, token)
        finally:
            token = None  # noqa: F841 - drop the last reference promptly

    async def _fetch(self, session: Session, client: asyncio.StreamWriter, url: str, token: str | None) -> None:
        for _ in range(MAX_REDIRECTS + 1):
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
            if parts.scheme != self.scheme or host not in self.allowed_hosts:
                session.record(decision="deny", reason="import_host_not_allowed", host=host)
                raise ProxyError(502, "import_host_not_allowed", "GitHub redirected to an unexpected host.")
            try:
                addresses = await resolve_validated(host, self.port, dev_hosts=frozenset(), resolver=self.resolver)
            except PolicyDenied as exc:
                session.record(decision="deny", reason=exc.reason, host=host, port=self.port)
                raise ProxyError(502, exc.reason, "GitHub could not be reached safely.") from exc
            reader, up = await self.opener(addresses, self.port, tls_host=host if self.scheme == "https" else None)
            session.record(decision="allow", method="GET", host=host, port=self.port, ip=addresses[0], purpose="github_import")
            try:
                path = parts.path + (f"?{parts.query}" if parts.query else "")
                headers = [
                    ("Host", host),
                    ("User-Agent", "ROUTES-Importer/0.1"),
                    ("Accept", "application/vnd.github+json"),
                    ("X-GitHub-Api-Version", "2022-11-28"),
                    ("Connection", "close"),
                ]
                # The token is only ever sent to the API host, never to redirect targets.
                if token and host == "api.github.com":
                    headers.append(("Authorization", f"Bearer {token}"))
                conn = h11.Connection(h11.CLIENT)
                up.write(conn.send(h11.Request(method="GET", target=path, headers=headers)))
                up.write(conn.send(h11.EndOfMessage()))
                await up.drain()
                response = await self._next_event(conn, reader)
                if not isinstance(response, h11.Response):
                    raise ProxyError(502, "import_bad_response", "Unexpected response from GitHub.")
                status = response.status_code
                rh = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in response.headers}
                if status in (301, 302, 303, 307, 308):
                    location = rh.get("location")
                    if not location:
                        raise ProxyError(502, "import_bad_redirect", "GitHub returned an invalid redirect.")
                    url = urljoin(url, location)
                    continue
                if status == 200:
                    await self._stream(session, conn, reader, client)
                    return
                if status == 429 or (status == 403 and rh.get("x-ratelimit-remaining") == "0"):
                    session.record(decision="deny", reason="import_rate_limited", host=host, status=status)
                    raise ProxyError(429, "import_rate_limited", _rate_limit_message(rh))
                if status in (401, 403):
                    raise ProxyError(403, "import_forbidden",
                                     "GitHub refused access. Check that the token is valid and has "
                                     "Contents: Read-only permission for this repository.")
                if status == 404:
                    if token:
                        raise ProxyError(404, "import_not_found",
                                         "The repository or reference was not found, or the token cannot access it.")
                    raise ProxyError(404, "import_not_found",
                                     "The repository or reference was not found. If the repository is private, "
                                     "connect it as a private repository with a token.")
                raise ProxyError(502, "import_upstream_error", f"GitHub responded with status {status}.")
            finally:
                up.close()
        raise ProxyError(502, "import_too_many_redirects", "Too many redirects from GitHub.")

    async def _next_event(self, conn: h11.Connection, reader: asyncio.StreamReader):
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                try:
                    data = await asyncio.wait_for(reader.read(65536), READ_TIMEOUT)
                except TimeoutError as exc:
                    raise ProxyError(504, "import_timeout", "GitHub did not respond in time.") from exc
                conn.receive_data(data)
                continue
            return event

    async def _stream(self, session: Session, conn: h11.Connection, reader, client: asyncio.StreamWriter) -> None:
        # Chunked encoding lets the sandbox detect truncation: the terminating
        # zero-length chunk is only sent after a complete, in-limit transfer.
        client.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/gzip\r\nTransfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
        )
        total = 0
        while True:
            event = await self._next_event(conn, reader)
            if isinstance(event, h11.Data):
                if not event.data:
                    continue
                total += len(event.data)
                session.bytes_in += len(event.data)
                if total > MAX_ARCHIVE_BYTES:
                    session.record(decision="deny", reason="import_size_limit")
                    return  # no terminating chunk: the sandbox sees a truncated transfer
                client.write(f"{len(event.data):x}\r\n".encode() + event.data + b"\r\n")
                await client.drain()
            elif isinstance(event, h11.EndOfMessage):
                client.write(b"0\r\n\r\n")
                await client.drain()
                return
            else:
                return  # upstream closed early: leave the transfer unterminated
