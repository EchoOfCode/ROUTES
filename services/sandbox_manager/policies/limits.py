"""Resource and isolation profiles for disposable sandbox containers."""

from __future__ import annotations

import os
from dataclasses import dataclass

MiB = 1024 * 1024
# tmpfs mounts are owned by the sandbox user and private to it.
OWNED = "uid=10001,gid=10001,mode=0700"


@dataclass(frozen=True)
class Profile:
    image: str
    command: list[str]
    memory: int
    nano_cpus: int
    pids: int
    timeout_seconds: int
    tmpfs: dict[str, str]
    shm_size: int = 0


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def discovery_profile() -> Profile:
    return Profile(
        image=os.environ.get("DISCOVERY_IMAGE", "routes/discovery:local"),
        command=["python", "-m", "discovery.main"],
        memory=1024 * MiB,
        nano_cpus=1_000_000_000,
        pids=256,
        timeout_seconds=_int("DISCOVERY_TIMEOUT_SECONDS", 600),
        # Chromium needs a writable HOME and /tmp; nothing is executable there.
        tmpfs={"/tmp": f"rw,noexec,nosuid,nodev,size=256m,{OWNED}", "/home/sandbox": f"rw,noexec,nosuid,nodev,size=64m,{OWNED}"},
        shm_size=128 * MiB,
    )


def analyzer_profile() -> Profile:
    return Profile(
        image=os.environ.get("ANALYZER_IMAGE", "routes/analyzer:local"),
        command=["python", "-m", "source_analyzer.main"],
        memory=1536 * MiB,
        nano_cpus=1_000_000_000,
        pids=128,
        timeout_seconds=_int("SOURCE_TIMEOUT_SECONDS", 900),
        # /work holds the extracted, untrusted source and is never executable.
        tmpfs={"/work": f"rw,noexec,nosuid,nodev,size=768m,{OWNED}", "/tmp": f"rw,noexec,nosuid,nodev,size=256m,{OWNED}",
               "/home/sandbox": f"rw,noexec,nosuid,nodev,size=32m,{OWNED}"},
    )


SANDBOX_USER = "10001:10001"


def container_spec(profile: Profile, *, run_id: str, kind: str, env: dict[str, str], network: str,
                   upload_volume: str | None = None, upload_id: str | None = None) -> dict:
    mounts = []
    if upload_volume and upload_id:
        mounts.append({"Type": "volume", "Source": upload_volume, "Target": "/input", "ReadOnly": True,
                       "VolumeOptions": {"Subpath": upload_id}})
    host = {
        "Memory": profile.memory,
        "MemorySwap": profile.memory,
        "NanoCpus": profile.nano_cpus,
        "PidsLimit": profile.pids,
        "ReadonlyRootfs": True,
        "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges:true"],
        "NetworkMode": network,
        "Init": True,
        "Tmpfs": profile.tmpfs,
        "Mounts": mounts,
        "RestartPolicy": {"Name": "no"},
        "LogConfig": {"Type": "json-file", "Config": {"max-size": "32m", "max-file": "1"}},
        "Ulimits": [{"Name": "nofile", "Soft": 1024, "Hard": 2048}],
    }
    if profile.shm_size:
        host["ShmSize"] = profile.shm_size
    return {
        "Image": profile.image,
        "Cmd": profile.command,
        "Env": [f"{k}={v}" for k, v in env.items()],
        "User": SANDBOX_USER,
        "WorkingDir": "/srv",
        "Labels": {"routes.sandbox": "true", "routes.run": run_id, "routes.kind": kind},
        "AttachStdout": False,
        "AttachStderr": False,
        "Tty": False,
        "OpenStdin": False,
        "StopTimeout": 5,
        "HostConfig": host,
    }
