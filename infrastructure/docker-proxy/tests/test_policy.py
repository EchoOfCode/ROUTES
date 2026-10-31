import asyncio
import copy
import json

import pytest

from docker_proxy.policy import Denied, Limits, check_container_create, route
from docker_proxy.server import DockerProxy

LIMITS = Limits(images=frozenset({"routes/discovery:local", "routes/analyzer:local"}), upload_volume="routes_uploads",
                gateway_container="routes-p1-gateway")
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
        "/containers/routes-p1-gateway/json": {"Name": "/routes-p1-gateway", "Config": {"Labels": {}}},
        "/containers/routes-api-1/json": {"Name": "/routes-api-1", "Config": {"Labels": {}}},
    }))
    body = lambda c: json.dumps({"Container": c}).encode()  # noqa: E731
    with pytest.raises(Denied):  # the network was not created for egress
        _authorise(proxy, "POST", "/networks/routes-sbx-1/connect", body("routes-p1-gateway"))
    assert _authorise(proxy, "POST", "/networks/routes-sbx-1/disconnect", body("routes-p1-gateway"))
    with pytest.raises(Denied):
        _authorise(proxy, "POST", "/networks/routes-sbx-1/connect", body("routes-api-1"))
    with pytest.raises(Denied):
        _authorise(proxy, "POST", "/networks/routes_backend/connect", body("routes-p1-gateway"))
    with pytest.raises(Denied):
        _authorise(proxy, "DELETE", "/networks/routes_backend")


def test_valid_spec_is_not_mutated():
    spec = valid_spec()
    before = copy.deepcopy(spec)
    check(spec)
    assert spec == before


# ------------------------------------------------------------ build-run images
BUILD_LIMITS = Limits(images=frozenset({"routes/discovery:local", "routes/build-runner:local", "routes/build-db:local"}),
                      upload_volume="routes_uploads", gateway_container="routes-p1-gateway",
                      build_images=frozenset({"routes/build-runner:local"}))


def build_spec(image="routes/build-runner:local") -> dict:
    spec = valid_spec()
    spec["Image"] = image
    spec["HostConfig"]["Memory"] = spec["HostConfig"]["MemorySwap"] = 3 * 1024**3
    spec["HostConfig"]["Tmpfs"] = {"/work": "rw,exec,nosuid,nodev,size=2g", "/tmp": "rw,noexec,nosuid,size=256m"}
    return spec


def test_build_image_gets_executable_work_and_larger_limits():
    check_container_create(QUERY, json.dumps(build_spec()).encode(), BUILD_LIMITS)


@pytest.mark.parametrize("mutate, reason", [
    (lambda s: s.update(Image="routes/discovery:local"), "memory_limit_required"),     # larger caps are build-only
    (lambda s: s["HostConfig"].update(Memory=8 * 1024**3, MemorySwap=8 * 1024**3), "memory_limit_required"),
    (lambda s: s["HostConfig"]["Tmpfs"].update({"/tmp": "rw,exec,size=64m"}), "tmpfs_exec_forbidden"),
    (lambda s: s["HostConfig"]["Tmpfs"].update({"/work": "rw,exec,suid,size=1g"}), "tmpfs_suid_or_dev_forbidden"),
    (lambda s: s["HostConfig"]["Tmpfs"].update({"/work": "rw,exec,size=8g"}), "tmpfs_too_large"),
    (lambda s: s["HostConfig"].update(Privileged=True), "privileged_forbidden"),
    (lambda s: s["HostConfig"].update(Binds=["/var/run/docker.sock:/var/run/docker.sock"]), "binds_forbidden"),
    (lambda s: s["HostConfig"].update(NetworkMode="host"), "network_forbidden"),
    (lambda s: s["HostConfig"].update(ReadonlyRootfs=False), "readonly_rootfs_required"),
    (lambda s: s.update(User="0:0"), "non_root_user_required"),
])
def test_build_image_keeps_every_other_control(mutate, reason):
    spec = build_spec()
    mutate(spec)
    with pytest.raises(Denied) as exc:
        check_container_create(QUERY, json.dumps(spec).encode(), BUILD_LIMITS)
    assert exc.value.reason == reason


def test_non_build_image_cannot_have_executable_work():
    spec = build_spec(image="routes/build-db:local")
    spec["HostConfig"]["Memory"] = spec["HostConfig"]["MemorySwap"] = 1024**3
    spec["HostConfig"]["Tmpfs"] = {"/work": "rw,exec,size=512m"}
    with pytest.raises(Denied) as exc:
        check_container_create(QUERY, json.dumps(spec).encode(), BUILD_LIMITS)
    assert exc.value.reason == "tmpfs_exec_forbidden"


def test_tmpfs_mount_options_cannot_smuggle_exec():
    spec = valid_spec()
    spec["HostConfig"]["Mounts"] = [{"Type": "tmpfs", "Target": "/x",
                                     "TmpfsOptions": {"SizeBytes": 1024**2, "Options": [["exec"]]}}]
    with pytest.raises(Denied) as exc:
        check(spec)
    assert exc.value.reason == "tmpfs_options_forbidden"


def test_attachments_are_limited_to_the_same_run_and_egress_networks():
    proxy = DockerProxy(BUILD_LIMITS, inspector=FakeInspector({
        "/networks/routes-sbx-r1-pkg": {"Name": "routes-sbx-r1-pkg",
                                        "Labels": {"routes.sandbox": "true", "routes.run": "r1", "routes.gateway": "allowed"}},
        "/networks/routes-sbx-r1-db": {"Name": "routes-sbx-r1-db", "Labels": {"routes.sandbox": "true", "routes.run": "r1"}},
        "/networks/routes-sbx-r2-db": {"Name": "routes-sbx-r2-db", "Labels": {"routes.sandbox": "true", "routes.run": "r2"}},
        "/containers/routes-sbx-r1-app/json": {"Name": "/routes-sbx-r1-app",
                                               "Config": {"Labels": {"routes.sandbox": "true", "routes.run": "r1"}}},
        "/containers/routes-p1-gateway/json": {"Name": "/routes-p1-gateway", "Config": {"Labels": {}}},
    }))
    body = lambda c: json.dumps({"Container": c}).encode()  # noqa: E731
    assert _authorise(proxy, "POST", "/networks/routes-sbx-r1-db/connect", body("routes-sbx-r1-app"))
    assert _authorise(proxy, "POST", "/networks/routes-sbx-r1-pkg/connect", body("routes-p1-gateway"))
    for net, container, reason in [("routes-sbx-r2-db", "routes-sbx-r1-app", "cross_run_attachment_forbidden"),
                                   ("routes-sbx-r1-db", "routes-p1-gateway", "gateway_network_forbidden")]:
        with pytest.raises(Denied) as exc:
            _authorise(proxy, "POST", f"/networks/{net}/connect", body(container))
        assert exc.value.reason == reason
    # Leaving a network is always permitted (cleanup must never be blocked).
    assert _authorise(proxy, "POST", "/networks/routes-sbx-r2-db/disconnect", body("routes-sbx-r1-app"))
