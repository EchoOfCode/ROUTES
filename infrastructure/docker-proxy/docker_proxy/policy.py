"""Default-deny policy for Docker Engine API requests from the Sandbox Manager.

Pure functions only (no I/O) so every rule is unit-testable. Anything not
explicitly allowed here is refused.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs

SANDBOX_LABEL = "routes.sandbox"
NAME_PREFIX = "routes-sbx-"
_VERSION_PREFIX = re.compile(r"^/v\d+\.\d+(?=/)")
_ID = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class Denied(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Limits:
    images: frozenset[str]
    upload_volume: str
    gateway_container: str
    max_memory: int = 2 * 1024**3
    max_nano_cpus: int = 2_000_000_000
    max_pids: int = 512
    max_tmpfs_bytes: int = 1024**3


@dataclass
class Decision:
    """What the server must do: forward as-is, or check a label first."""

    kind: str  # "forward" | "container" | "network" | "connect"
    path: str
    query: str = ""
    target: str | None = None  # container / network id to label-check
    container: str | None = None  # for network connect/disconnect
    extra: dict = field(default_factory=dict)


def strip_version(path: str) -> str:
    return _VERSION_PREFIX.sub("", path)


def _require(cond: bool, reason: str) -> None:
    if not cond:
        raise Denied(reason)


def _empty(value) -> bool:
    return value in (None, "", [], {}, False, 0)


# ---------------------------------------------------------------- containers

_ALLOWED_CONTAINER_KEYS = {
    "Image", "Cmd", "Env", "User", "Labels", "WorkingDir", "HostConfig", "NetworkingConfig", "AttachStdin",
    "AttachStdout", "AttachStderr", "Tty", "OpenStdin", "StdinOnce", "StopTimeout", "StopSignal", "Hostname",
    "Domainname", "Entrypoint", "NetworkDisabled", "Volumes", "ExposedPorts", "Healthcheck", "MacAddress",
    "OnBuild", "Shell", "ArgsEscaped",
}

# HostConfig keys that may be present; everything else must be empty.
_ALLOWED_HOST_KEYS = {
    "Memory", "MemorySwap", "MemoryReservation", "NanoCpus", "CpuShares", "PidsLimit", "ReadonlyRootfs",
    "CapDrop", "CapAdd", "SecurityOpt", "Mounts", "Tmpfs", "NetworkMode", "Init", "AutoRemove", "RestartPolicy",
    "LogConfig", "Ulimits", "Privileged", "Binds", "PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode",
    "Devices", "DeviceRequests", "DeviceCgroupRules", "Sysctls", "PortBindings", "PublishAllPorts", "VolumesFrom",
    "Links", "ExtraHosts", "Runtime", "CgroupParent", "OomKillDisable", "Dns", "DnsOptions", "DnsSearch",
    "ShmSize", "GroupAdd", "OomScoreAdj", "MaskedPaths", "ReadonlyPaths", "Isolation", "ConsoleSize",
    "VolumeDriver", "ContainerIDFile", "Annotations",
}
_MUST_BE_EMPTY = {
    "Privileged", "Binds", "CapAdd", "Devices", "DeviceRequests", "DeviceCgroupRules", "Sysctls", "PortBindings",
    "PublishAllPorts", "VolumesFrom", "Links", "ExtraHosts", "CgroupParent", "OomKillDisable", "GroupAdd",
    "VolumeDriver", "ContainerIDFile", "Annotations", "Dns", "DnsOptions", "DnsSearch",
}
_NAMESPACE_KEYS = {"PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode"}


def _parse_size(value: str) -> int:
    m = re.fullmatch(r"(\d+)([kmg]?)", value.strip().lower())
    _require(m is not None, "tmpfs_size_invalid")
    n = int(m.group(1))
    return n * {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[m.group(2)]


def _check_tmpfs_options(opts: str, limits: Limits) -> None:
    sizes = [o.split("=", 1)[1] for o in opts.split(",") if o.startswith("size=")]
    _require(len(sizes) == 1, "tmpfs_size_required")
    _require(_parse_size(sizes[0]) <= limits.max_tmpfs_bytes, "tmpfs_too_large")
    _require("exec" not in [o.strip() for o in opts.split(",")], "tmpfs_exec_forbidden")


def _check_mounts(mounts: list, limits: Limits) -> None:
    for m in mounts or []:
        _require(isinstance(m, dict), "mount_invalid")
        kind = m.get("Type")
        if kind == "tmpfs":
            size = (m.get("TmpfsOptions") or {}).get("SizeBytes") or 0
            _require(0 < size <= limits.max_tmpfs_bytes, "tmpfs_size_required")
            _require(not m.get("Source"), "tmpfs_source_forbidden")
        elif kind == "volume":
            _require(m.get("Source") == limits.upload_volume, "volume_not_allowed")
            _require(m.get("ReadOnly") is True, "volume_must_be_readonly")
            _require(m.get("Target") == "/input", "volume_target_invalid")
            sub = ((m.get("VolumeOptions") or {}).get("Subpath")) or ""
            _require(bool(_UUID.match(sub)), "volume_subpath_required")
            _require(_empty((m.get("VolumeOptions") or {}).get("DriverConfig")), "volume_options_forbidden")
        else:
            raise Denied("mount_type_forbidden")


def check_container_create(query: str, body: bytes, limits: Limits) -> None:
    params = parse_qs(query)
    name = (params.get("name") or [""])[0]
    _require(name.startswith(NAME_PREFIX) and re.fullmatch(_ID, name) is not None, "name_prefix_required")
    try:
        spec = json.loads(body or b"{}")
    except ValueError as exc:
        raise Denied("invalid_json") from exc
    _require(isinstance(spec, dict), "invalid_json")
    unknown = [k for k, v in spec.items() if k not in _ALLOWED_CONTAINER_KEYS and not _empty(v)]
    _require(not unknown, "container_key_forbidden")
    _require(spec.get("Image") in limits.images, "image_not_allowed")
    labels = spec.get("Labels") or {}
    _require(labels.get(SANDBOX_LABEL) == "true", "sandbox_label_required")
    _require(_empty(spec.get("ExposedPorts")) and _empty(spec.get("Volumes")), "ports_or_volumes_forbidden")
    _require(not spec.get("Tty") and not spec.get("OpenStdin"), "interactive_forbidden")

    user = str(spec.get("User") or "")
    uid = user.split(":", 1)[0]
    _require(uid.isdigit() and int(uid) >= 1000, "non_root_user_required")
    if ":" in user:
        gid = user.split(":", 1)[1]
        _require(gid.isdigit() and int(gid) >= 1000, "non_root_group_required")

    host = spec.get("HostConfig") or {}
    _require(isinstance(host, dict), "hostconfig_invalid")
    unknown = [k for k, v in host.items() if k not in _ALLOWED_HOST_KEYS and not _empty(v)]
    _require(not unknown, "hostconfig_key_forbidden")
    for key in _MUST_BE_EMPTY:
        _require(_empty(host.get(key)), f"{key.lower()}_forbidden")
    for key in _NAMESPACE_KEYS:
        _require(host.get(key) in (None, "", "private"), "host_namespace_forbidden")
    _require(host.get("Runtime") in (None, "", "runc"), "runtime_forbidden")
    _require(host.get("Isolation") in (None, "", "default"), "isolation_forbidden")
    _require(host.get("ReadonlyRootfs") is True, "readonly_rootfs_required")
    _require("ALL" in (host.get("CapDrop") or []), "capdrop_all_required")

    secopts = host.get("SecurityOpt") or []
    _require(any(o in ("no-new-privileges", "no-new-privileges:true", "no-new-privileges=true") for o in secopts),
             "no_new_privileges_required")
    for opt in secopts:
        lowered = opt.lower()
        _require("unconfined" not in lowered and "label=disable" not in lowered and "label:disable" not in lowered,
                 "security_profile_forbidden")
    # Overriding masked/read-only /proc paths (even with []) unmasks them.
    _require(host.get("MaskedPaths") is None and host.get("ReadonlyPaths") is None, "unmasking_forbidden")

    memory = host.get("Memory") or 0
    _require(0 < memory <= limits.max_memory, "memory_limit_required")
    _require(host.get("MemorySwap") in (None, 0, memory), "swap_forbidden")
    _require(0 < (host.get("NanoCpus") or 0) <= limits.max_nano_cpus, "cpu_limit_required")
    _require(0 < (host.get("PidsLimit") or 0) <= limits.max_pids, "pids_limit_required")
    _require((host.get("ShmSize") or 0) <= 256 * 1024**2, "shm_too_large")
    restart = (host.get("RestartPolicy") or {}).get("Name", "")
    _require(restart in ("", "no"), "restart_policy_forbidden")

    net = host.get("NetworkMode") or ""
    _require(net == "none" or (net.startswith(NAME_PREFIX) and re.fullmatch(_ID, net) is not None), "network_forbidden")
    endpoints = ((spec.get("NetworkingConfig") or {}).get("EndpointsConfig")) or {}
    _require(all(k == net for k in endpoints), "network_forbidden")
    for ep in endpoints.values():
        _require(_empty((ep or {}).get("IPAMConfig")) and _empty((ep or {}).get("Links")), "endpoint_config_forbidden")

    for path, opts in (host.get("Tmpfs") or {}).items():
        _require(isinstance(path, str) and path.startswith("/"), "tmpfs_invalid")
        _check_tmpfs_options(opts or "", limits)
    _check_mounts(host.get("Mounts") or [], limits)


# ------------------------------------------------------------------ networks


def check_network_create(body: bytes) -> None:
    try:
        spec = json.loads(body or b"{}")
    except ValueError as exc:
        raise Denied("invalid_json") from exc
    _require(isinstance(spec, dict), "invalid_json")
    allowed = {"Name", "Driver", "Internal", "Labels", "EnableIPv6", "CheckDuplicate", "Options", "IPAM", "Attachable",
               "Ingress", "Scope", "ConfigOnly", "ConfigFrom", "EnableIPv4"}
    _require(all(k in allowed for k in spec), "network_key_forbidden")
    name = spec.get("Name") or ""
    _require(name.startswith(NAME_PREFIX) and re.fullmatch(_ID, name) is not None, "name_prefix_required")
    _require(spec.get("Internal") is True, "network_must_be_internal")
    _require(spec.get("Driver") in (None, "", "bridge"), "driver_forbidden")
    _require(not spec.get("EnableIPv6"), "ipv6_forbidden")
    _require(not spec.get("Attachable") and not spec.get("Ingress") and not spec.get("ConfigOnly"), "network_mode_forbidden")
    _require(_empty(spec.get("ConfigFrom")) and spec.get("Scope") in (None, "", "local"), "network_mode_forbidden")
    _require((spec.get("Labels") or {}).get(SANDBOX_LABEL) == "true", "sandbox_label_required")
    opts = spec.get("Options") or {}
    allowed_opts = {"com.docker.network.bridge.enable_icc", "com.docker.network.bridge.enable_ip_masquerade"}
    _require(all(k in allowed_opts for k in opts), "network_option_forbidden")
    ipam = spec.get("IPAM") or {}
    _require(ipam.get("Driver") in (None, "", "default") and _empty(ipam.get("Options")), "ipam_forbidden")


def check_connect_body(body: bytes) -> str:
    try:
        spec = json.loads(body or b"{}")
    except ValueError as exc:
        raise Denied("invalid_json") from exc
    _require(isinstance(spec, dict) and set(spec) <= {"Container", "EndpointConfig", "Force"}, "connect_body_invalid")
    container = spec.get("Container") or ""
    _require(re.fullmatch(_ID, container) is not None, "connect_body_invalid")
    ep = spec.get("EndpointConfig") or {}
    _require(_empty(ep.get("IPAMConfig")) and _empty(ep.get("Links")), "endpoint_config_forbidden")
    return container


def force_label_filter(query: str) -> str:
    """Rewrite list queries so only sandbox objects are ever returned."""
    from urllib.parse import urlencode

    params = parse_qs(query)
    try:
        filters = json.loads((params.get("filters") or ["{}"])[0])
    except ValueError:
        filters = {}
    if not isinstance(filters, dict):
        filters = {}
    filters["label"] = [f"{SANDBOX_LABEL}=true"]
    params["filters"] = [json.dumps(filters)]
    return urlencode({k: v[0] for k, v in params.items()})


# ------------------------------------------------------------------- routing

_CONTAINER_OPS = {
    ("GET", "json"), ("POST", "start"), ("POST", "wait"), ("POST", "kill"), ("POST", "stop"), ("GET", "logs"),
}


def route(method: str, raw_path: str, query: str, body: bytes, limits: Limits) -> Decision:
    path = strip_version(raw_path)
    if ".." in path or "//" in path or "%" in path:
        raise Denied("path_invalid")
    if method in ("GET", "HEAD") and path in ("/_ping", "/version"):
        return Decision("forward", raw_path, query)
    if method == "GET" and (m := re.fullmatch(r"/images/(.+)/json", path)):
        _require(m.group(1) in limits.images, "image_not_allowed")
        return Decision("forward", raw_path, query)
    if method == "POST" and path == "/containers/create":
        check_container_create(query, body, limits)
        return Decision("forward", raw_path, query)
    if method == "GET" and path == "/containers/json":
        return Decision("forward", raw_path, force_label_filter(query))
    if m := re.fullmatch(rf"/containers/({_ID})/(\w+)", path):
        _require((method, m.group(2)) in _CONTAINER_OPS, "container_operation_forbidden")
        if m.group(2) == "logs":
            params = parse_qs(query)
            _require((params.get("follow") or ["0"])[0] in ("0", "false"), "log_follow_forbidden")
        return Decision("container", raw_path, query, target=m.group(1))
    if method == "DELETE" and (m := re.fullmatch(rf"/containers/({_ID})", path)):
        return Decision("container", raw_path, query, target=m.group(1))
    if method == "POST" and path == "/networks/create":
        check_network_create(body)
        return Decision("forward", raw_path, query)
    if method == "GET" and path == "/networks":
        return Decision("forward", raw_path, force_label_filter(query))
    if method in ("GET", "DELETE") and (m := re.fullmatch(rf"/networks/({_ID})", path)):
        return Decision("network", raw_path, query, target=m.group(1))
    if method == "POST" and (m := re.fullmatch(rf"/networks/({_ID})/(connect|disconnect)", path)):
        container = check_connect_body(body)
        return Decision("connect", raw_path, query, target=m.group(1), container=container)
    raise Denied("endpoint_forbidden")


def is_sandbox(inspect: dict) -> bool:
    labels = (inspect.get("Config") or {}).get("Labels") or inspect.get("Labels") or {}
    return labels.get(SANDBOX_LABEL) == "true"


def is_gateway(inspect: dict, gateway_name: str) -> bool:
    return (inspect.get("Name") or "").lstrip("/") == gateway_name
