"""Minimal Docker Engine API client. All calls go through the restricted
docker-proxy; this service never touches the Docker socket."""

from __future__ import annotations

import json
import struct

import httpx

API_VERSION = "v1.47"


class DockerError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"{status}: {message}")
        self.status = status
        self.message = message


class DockerAPI:
    def __init__(self, base_url: str, *, transport: httpx.AsyncBaseTransport | None = None):
        self._client = httpx.AsyncClient(base_url=f"{base_url.rstrip('/')}/{API_VERSION}", timeout=30.0,
                                         transport=transport)

    async def close(self) -> None:
        await self._client.aclose()

    async def _call(self, method: str, path: str, *, ok=(200, 201, 204), **kwargs) -> httpx.Response:
        r = await self._client.request(method, path, **kwargs)
        if r.status_code not in ok:
            try:
                message = r.json().get("message", r.text)
            except ValueError:
                message = r.text
            raise DockerError(r.status_code, message[:500])
        return r

    async def ping(self) -> bool:
        r = await self._client.get("/_ping")
        return r.status_code == 200

    # networks
    async def create_network(self, name: str, run_id: str, *, egress: bool = True) -> str:
        """Internal network for one run. Only ``egress`` networks may be joined by the gateway."""
        labels = {"routes.sandbox": "true", "routes.run": run_id}
        if egress:
            labels["routes.gateway"] = "allowed"
        body = {"Name": name, "Driver": "bridge", "Internal": True, "EnableIPv6": False, "CheckDuplicate": True,
                "Labels": labels,
                "Options": {"com.docker.network.bridge.enable_icc": "true"}}
        r = await self._call("POST", "/networks/create", json=body)
        return r.json()["Id"]

    async def inspect_network(self, name: str) -> dict:
        return (await self._call("GET", f"/networks/{name}")).json()

    async def connect(self, network: str, container: str) -> None:
        await self._call("POST", f"/networks/{network}/connect", json={"Container": container})

    async def disconnect(self, network: str, container: str) -> None:
        await self._call("POST", f"/networks/{network}/disconnect", json={"Container": container, "Force": True},
                         ok=(200, 204, 404))

    async def remove_network(self, name: str) -> None:
        await self._call("DELETE", f"/networks/{name}", ok=(200, 204, 404))

    async def list_networks(self) -> list[dict]:
        return (await self._call("GET", "/networks")).json()

    # containers
    async def create_container(self, name: str, spec: dict) -> str:
        r = await self._call("POST", "/containers/create", params={"name": name}, json=spec)
        return r.json()["Id"]

    async def start(self, cid: str) -> None:
        await self._call("POST", f"/containers/{cid}/start", ok=(204, 304))

    async def inspect(self, cid: str) -> dict:
        return (await self._call("GET", f"/containers/{cid}/json")).json()

    async def stop(self, cid: str, timeout: int = 15) -> None:
        await self._call("POST", f"/containers/{cid}/stop", params={"t": str(timeout)}, ok=(204, 304, 404))

    async def kill(self, cid: str) -> None:
        await self._call("POST", f"/containers/{cid}/kill", ok=(204, 404, 409))

    async def remove(self, cid: str) -> None:
        await self._call("DELETE", f"/containers/{cid}", params={"force": "true", "v": "true"}, ok=(204, 404))

    async def list_containers(self) -> list[dict]:
        return (await self._call("GET", "/containers/json", params={"all": "1"})).json()

    async def logs(self, cid: str, *, stdout: bool, stderr: bool, max_bytes: int) -> bytes:
        params = {"stdout": "1" if stdout else "0", "stderr": "1" if stderr else "0", "follow": "0"}
        out = bytearray()
        async with self._client.stream("GET", f"/containers/{cid}/logs", params=params) as r:
            if r.status_code != 200:
                raise DockerError(r.status_code, "logs unavailable")
            async for chunk in r.aiter_bytes():
                out += chunk
                if len(out) > max_bytes + 8 * 1024:
                    raise DockerError(413, "sandbox output exceeded the size limit")
        return demux(bytes(out))


def demux(raw: bytes) -> bytes:
    """Strip Docker's 8-byte stream multiplexing headers (non-TTY containers)."""
    out = bytearray()
    i = 0
    while i + 8 <= len(raw):
        stream, size = raw[i], struct.unpack(">I", raw[i + 4:i + 8])[0]
        if stream not in (0, 1, 2) or raw[i + 1:i + 4] != b"\x00\x00\x00":
            return raw  # not multiplexed
        out += raw[i + 8:i + 8 + size]
        i += 8 + size
    return bytes(out)


def parse_json(text: str):
    return json.loads(text)
