import asyncio
import copy
import json

import pytest

from docker_proxy.policy import Denied, Limits, check_container_create, route
from docker_proxy.server import DockerProxy

LIMITS = Limits(images=frozenset({"routes/discovery:local", "routes/analyzer:local"}), upload_volume="routes_uploads",
                gateway_container="routes-network-gateway")
QUERY = "name=routes-sbx-abc123"
UUID = "0f8fad5b-d9cb-469f-a165-70867728950e"


def valid_spec() -> dict:
    return {
        "Image": "routes/discovery:local",
        "Cmd": ["python", "-m", "discovery.main"],
        "Env": ["ROUTES_TARGET=https://example.com"],
        "User": "10001:10001",
        "Labels": {"routes.sandbox": "true", "routes.run": "abc123"},
        "HostConfig": {
            "Memory": 1024**3, "MemorySwap": 1024**3, "NanoCpus": 1_000_000_000, "PidsLimit": 256,
            "ReadonlyRootfs": True, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"],
            "NetworkMode": "routes-sbx-abc123", "Init": True,
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=256m"},
            "Mounts": [{"Type": "volume", "Source": "routes_uploads", "Target": "/input", "ReadOnly": True,
                        "VolumeOptions": {"Subpath": UUID}}],
            "RestartPolicy": {"Name": "no"},
        },
    }


def check(spec, query=QUERY):
    check_container_create(query, json.dumps(spec).encode(), LIMITS)


def test_valid_spec_allowed():
    check(valid_spec())
    spec = valid_spec()
    spec["HostConfig"]["NetworkMode"] = "none"
    check(spec)


def _mut(path, value):
    spec = valid_spec()
    target = spec
    for key in path[:-1]:
        target = target[key]
    if value is KeyError:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return spec


@pytest.mark.parametrize(
    "spec,reason",
    [
        (_mut(["HostConfig", "Privileged"], True), "privileged_forbidden"),
        (_mut(["HostConfig", "Binds"], ["/:/host"]), "binds_forbidden"),
        (_mut(["HostConfig", "Binds"], ["/var/run/docker.sock:/var/run/docker.sock"]), "binds_forbidden"),
        (_mut(["HostConfig", "CapAdd"], ["NET_ADMIN"]), "capadd_forbidden"),
        (_mut(["HostConfig", "CapDrop"], []), "capdrop_all_required"),
        (_mut(["HostConfig", "ReadonlyRootfs"], False), "readonly_rootfs_required"),
        (_mut(["HostConfig", "SecurityOpt"], []), "no_new_privileges_required"),
        (_mut(["HostConfig", "SecurityOpt"], ["no-new-privileges", "seccomp=unconfined"]), "security_profile_forbidden"),
        (_mut(["HostConfig", "NetworkMode"], "host"), "network_forbidden"),
        (_mut(["HostConfig", "NetworkMode"], "bridge"), "network_forbidden"),
        (_mut(["HostConfig", "NetworkMode"], "routes_backend"), "network_forbidden"),
        (_mut(["HostConfig", "PidMode"], "host"), "host_namespace_forbidden"),
        (_mut(["HostConfig", "IpcMode"], "host"), "host_namespace_forbidden"),
        (_mut(["HostConfig", "Devices"], [{"PathOnHost": "/dev/kvm"}]), "devices_forbidden"),
        (_mut(["HostConfig", "Memory"], 0), "memory_limit_required"),
        (_mut(["HostConfig", "Memory"], 64 * 1024**3), "memory_limit_required"),
        (_mut(["HostConfig", "NanoCpus"], KeyError), "cpu_limit_required"),
        (_mut(["HostConfig", "PidsLimit"], -1), "pids_limit_required"),
        (_mut(["HostConfig", "MemorySwap"], -1), "swap_forbidden"),
        (_mut(["HostConfig", "Sysctls"], {"net.ipv4.ip_forward": "1"}), "sysctls_forbidden"),
        (_mut(["HostConfig", "MaskedPaths"], []), "unmasking_forbidden"),
        (_mut(["HostConfig", "Runtime"], "nvidia"), "runtime_forbidden"),
        (_mut(["HostConfig", "Mounts"], [{"Type": "bind", "Source": "/", "Target": "/host"}]), "mount_type_forbidden"),
        (_mut(["HostConfig", "Mounts"], [{"Type": "volume", "Source": "postgres_data", "Target": "/input",
                                          "ReadOnly": True, "VolumeOptions": {"Subpath": UUID}}]), "volume_not_allowed"),
        (_mut(["HostConfig", "Mounts"], [{"Type": "volume", "Source": "routes_uploads", "Target": "/input",
                                          "ReadOnly": False, "VolumeOptions": {"Subpath": UUID}}]), "volume_must_be_readonly"),
        (_mut(["HostConfig", "Mounts"], [{"Type": "volume", "Source": "routes_uploads", "Target": "/input",
                                          "ReadOnly": True}]), "volume_subpath_required"),
        (_mut(["HostConfig", "Mounts"], [{"Type": "volume", "Source": "routes_uploads", "Target": "/input",
                                          "ReadOnly": True, "VolumeOptions": {"Subpath": "../"}}]), "volume_subpath_required"),
        (_mut(["HostConfig", "Tmpfs"], {"/tmp": "rw"}), "tmpfs_size_required"),
        (_mut(["HostConfig", "Tmpfs"], {"/tmp": "rw,exec,size=10m"}), "tmpfs_exec_forbidden"),
        (_mut(["HostConfig", "PortBindings"], {"80/tcp": [{"HostPort": "80"}]}), "portbindings_forbidden"),
        (_mut(["HostConfig", "SomethingNew"], True), "hostconfig_key_forbidden"),
        (_mut(["User"], ""), "non_root_user_required"),
        (_mut(["User"], "root"), "non_root_user_required"),
        (_mut(["User"], "0:0"), "non_root_user_required"),
        (_mut(["User"], "10001:0"), "non_root_group_required"),
        (_mut(["Image"], "alpine:latest"), "image_not_allowed"),
        (_mut(["Labels"], {}), "sandbox_label_required"),
        (_mut(["Tty"], True), "interactive_forbidden"),
        (_mut(["ExposedPorts"], {"80/tcp": {}}), "ports_or_volumes_forbidden"),
    ],
)
def test_dangerous_specs_denied(spec, reason):
    with pytest.raises(Denied) as exc:
        check(spec)
    assert exc.value.reason == reason


def test_name_prefix_required():
    with pytest.raises(Denied):
        check(valid_spec(), query="name=evil")
    with pytest.raises(Denied):
        check(valid_spec(), query="")


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/v1.43/containers/abc/exec"),
        ("POST", "/containers/abc/attach"),
        ("GET", "/containers/abc/archive"),
        ("PUT", "/containers/abc/archive"),
        ("POST", "/build"),
        ("POST", "/images/create"),
        ("GET", "/volumes"),
        ("POST", "/volumes/create"),
        ("GET", "/info"),
        ("POST", "/swarm/init"),
        ("POST", "/plugins/pull"),
        ("GET", "/images/alpine/json"),
        ("GET", "/containers/../../info"),
        ("GET", "/containers/abc/logs?follow=1"),
    ],
)
def test_forbidden_endpoints(method, path):
    p, _, q = path.partition("?")
    with pytest.raises(Denied):
        route(method, p, q, b"", LIMITS)


def test_list_queries_forced_to_sandbox_label():
    d = route("GET", "/v1.43/containers/json", 'all=1&filters={"label":["anything"]}', b"", LIMITS)
    assert "routes.sandbox%3Dtrue" in d.query and "anything" not in d.query


def test_network_create_rules():
    ok = {"Name": "routes-sbx-abc", "Internal": True, "Driver": "bridge", "Labels": {"routes.sandbox": "true"}}
    route("POST", "/networks/create", "", json.dumps(ok).encode(), LIMITS)
    for bad in [
        {**ok, "Internal": False},
        {**ok, "Name": "mynet"},
        {**ok, "Driver": "host"},
        {**ok, "EnableIPv6": True},
        {**ok, "Labels": {}},
        {**ok, "Options": {"com.docker.network.bridge.name": "docker0"}},
    ]:
        with pytest.raises(Denied):
            route("POST", "/networks/create", "", json.dumps(bad).encode(), LIMITS)


# ----------------------------------------------------------- label checks


class FakeInspector:
    def __init__(self, objects):
        self.objects = objects

    async def __call__(self, path):
        return (200, self.objects[path]) if path in self.objects else (404, {})


def _authorise(proxy, method, path, body=b""):
    p, _, q = path.partition("?")
    return asyncio.run(proxy.authorise(method, p, q, body))


def test_operations_only_on_labelled_containers():
    proxy = DockerProxy(LIMITS, inspector=FakeInspector({
        "/containers/sbx/json": {"Config": {"Labels": {"routes.sandbox": "true"}}},
        "/containers/postgres/json": {"Config": {"Labels": {}}},
    }))
    assert _authorise(proxy, "POST", "/containers/sbx/start")
    assert _authorise(proxy, "DELETE", "/containers/sbx?force=1")
    for path in ["/containers/postgres/start", "/containers/postgres/json", "/containers/missing/kill"]:
        with pytest.raises(Denied):
            _authorise(proxy, "POST" if not path.endswith("json") else "GET", path)
    with pytest.raises(Denied):
        _authorise(proxy, "DELETE", "/containers/postgres")


def test_network_connect_only_sandbox_or_gateway():
    proxy = DockerProxy(LIMITS, inspector=FakeInspector({
        "/networks/routes-sbx-1": {"Name": "routes-sbx-1", "Labels": {"routes.sandbox": "true"}},
        "/networks/routes_backend": {"Name": "routes_backend", "Labels": {}},
        "/containers/routes-network-gateway/json": {"Name": "/routes-network-gateway", "Config": {"Labels": {}}},
        "/containers/routes-api-1/json": {"Name": "/routes-api-1", "Config": {"Labels": {}}},
    }))
    body = lambda c: json.dumps({"Container": c}).encode()  # noqa: E731
    assert _authorise(proxy, "POST", "/networks/routes-sbx-1/connect", body("routes-network-gateway"))
    with pytest.raises(Denied):
        _authorise(proxy, "POST", "/networks/routes-sbx-1/connect", body("routes-api-1"))
    with pytest.raises(Denied):
        _authorise(proxy, "POST", "/networks/routes_backend/connect", body("routes-network-gateway"))
    with pytest.raises(Denied):
        _authorise(proxy, "DELETE", "/networks/routes_backend")


def test_valid_spec_is_not_mutated():
    spec = valid_spec()
    before = copy.deepcopy(spec)
    check(spec)
    assert spec == before
