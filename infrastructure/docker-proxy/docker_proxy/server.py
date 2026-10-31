"""Restricted Docker Engine API proxy.

Listens on TCP (internal docker-control network only) and forwards requests
that pass ``policy.route`` to the Docker socket. Container/network-specific
operations are only forwarded after confirming the target carries the
ROUTES sandbox label (or, for network connect, is the gateway container).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os

import h11

from docker_proxy.policy import Denied, Limits, check_attachment, is_gateway, is_sandbox, route

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("routes.docker-proxy")

MAX_HEAD = 16 * 1024
MAX_BODY = 1024 * 1024
SOCKET = os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock")


def load_limits() -> Limits:
    return Limits(
        images=frozenset(i.strip() for i in os.environ.get("ALLOWED_IMAGES", "").split(",") if i.strip()),
        upload_volume=os.environ.get("UPLOAD_VOLUME", "routes_uploads"),
        gateway_container=os.environ.get("GATEWAY_CONTAINER", "routes-p1-gateway"),
        max_memory=int(os.environ.get("MAX_MEMORY_BYTES", str(2 * 1024**3))),
        max_nano_cpus=int(os.environ.get("MAX_NANO_CPUS", "2000000000")),
        max_pids=int(os.environ.get("MAX_PIDS", "512")),
        build_images=frozenset(i.strip() for i in os.environ.get("BUILD_IMAGES", "").split(",") if i.strip()),
        max_build_memory=int(os.environ.get("MAX_BUILD_MEMORY_BYTES", str(4 * 1024**3))),
        max_build_tmpfs_bytes=int(os.environ.get("MAX_BUILD_TMPFS_BYTES", str(3 * 1024**3))),
    )


async def docker_get_json(path: str) -> tuple[int, dict]:
    reader, writer = await asyncio.open_unix_connection(SOCKET)
    try:
        conn = h11.Connection(h11.CLIENT)
        writer.write(conn.send(h11.Request(method="GET", target=path, headers=[("Host", "docker"), ("Connection", "close")])))
        writer.write(conn.send(h11.EndOfMessage()))
        await writer.drain()
        status, body = 0, b""
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                conn.receive_data(await reader.read(65536))
            elif isinstance(event, h11.Response):
                status = event.status_code
            elif isinstance(event, h11.Data):
                body += event.data
                if len(body) > 4 * MAX_BODY:
                    raise Denied("inspect_too_large")
            elif isinstance(event, (h11.EndOfMessage, h11.ConnectionClosed)):
                break
        try:
            return status, json.loads(body or b"{}")
        except ValueError:
            return status, {}
    finally:
        writer.close()


class DockerProxy:
    def __init__(self, limits: Limits, inspector=docker_get_json):
        self.limits = limits
        self.inspect = inspector

    async def authorise(self, method: str, path: str, query: str, body: bytes) -> str:
        decision = route(method, path, query, body, self.limits)
        if decision.kind == "container":
            status, info = await self.inspect(f"/containers/{decision.target}/json")
            if status != 200 or not is_sandbox(info):
                raise Denied("container_not_sandbox")
        elif decision.kind == "network":
            status, info = await self.inspect(f"/networks/{decision.target}")
            if status != 200 or not is_sandbox(info) or not (info.get("Name") or "").startswith("routes-sbx-"):
                raise Denied("network_not_sandbox")
        elif decision.kind == "connect":
            status, info = await self.inspect(f"/networks/{decision.target}")
            if status != 200 or not is_sandbox(info) or not (info.get("Name") or "").startswith("routes-sbx-"):
                raise Denied("network_not_sandbox")
            status, cinfo = await self.inspect(f"/containers/{decision.container}/json")
            gateway = status == 200 and is_gateway(cinfo, self.limits.gateway_container)
            if status != 200 or not (is_sandbox(cinfo) or gateway):
                raise Denied("container_not_permitted")
            check_attachment(decision.extra.get("op", "connect"), info, cinfo, gateway=gateway)
        return decision.path + (f"?{decision.query}" if decision.query else "")

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
            except (asyncio.LimitOverrunError, asyncio.IncompleteReadError, TimeoutError, ValueError):
                return await self._error(writer, 400, "bad_request")
            lines = head[:-4].decode("latin-1").split("\r\n")
            parts = lines[0].split(" ")
            if len(parts) != 3:
                return await self._error(writer, 400, "bad_request")
            method, target, _ = parts
            headers = [(k.strip().lower(), v.strip()) for k, v in (ln.split(":", 1) for ln in lines[1:] if ":" in ln)]
            hdr = dict(headers)
            if "transfer-encoding" in hdr:
                return await self._error(writer, 400, "chunked_body_not_supported")
            length = int(hdr.get("content-length", "0") or 0)
            if length > MAX_BODY:
                return await self._error(writer, 413, "body_too_large")
            body = await asyncio.wait_for(reader.readexactly(length), 15) if length else b""
            path, _, query = target.partition("?")
            try:
                forward_target = await self.authorise(method, path, query, body)
            except Denied as exc:
                log.warning("denied %s %s: %s", method, path, exc.reason)
                return await self._error(writer, 403, exc.reason)
            await self._forward(method, forward_target, headers, body, writer)
        except Exception:  # noqa: BLE001
            log.exception("proxy failure")
            await self._error(writer, 502, "proxy_error")
        finally:
            try:
                writer.close()
            except RuntimeError:
                pass

    async def _forward(self, method, target, headers, body, writer) -> None:
        up_reader, up_writer = await asyncio.open_unix_connection(SOCKET)
        keep = [(k, v) for k, v in headers if k in ("content-type", "accept", "user-agent")]
        lines = [f"{method} {target} HTTP/1.1", "Host: docker", f"Content-Length: {len(body)}", "Connection: close"]
        lines += [f"{k}: {v}" for k, v in keep]
        up_writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)
        await up_writer.drain()
        try:
            while data := await up_reader.read(65536):
                writer.write(data)
                await writer.drain()
        finally:
            up_writer.close()

    async def _error(self, writer, status: int, reason: str) -> None:
        body = json.dumps({"message": f"ROUTES docker-proxy denied request: {reason}"}).encode()
        writer.write(
            f"HTTP/1.1 {status} Denied\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n".encode() + body
        )
        try:
            await writer.drain()
        except ConnectionError:
            pass


async def main() -> None:
    limits = load_limits()
    if not limits.images:
        raise SystemExit("ALLOWED_IMAGES must list the sandbox images")
    proxy = DockerProxy(limits)
    server = await asyncio.start_server(proxy.handle, host="0.0.0.0", port=2375, limit=MAX_HEAD)
    log.info("docker-proxy listening on :2375; images=%s", ",".join(sorted(limits.images)))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
