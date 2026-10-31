"""Start, stop and inspect the local ROUTES engine with Docker Compose.

Commands are built from fixed argument lists (never a shell, never user text)
and always use the engine's env file and the default (engine) profile.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

ENGINE_SERVICES = ("network-gateway", "docker-proxy", "sandbox-manager")
SANDBOX_IMAGES = ("routes/discovery:local", "routes/analyzer:local")


class EngineControlError(RuntimeError):
    pass


@dataclass(frozen=True)
class ComposeTarget:
    compose_file: Path
    env_file: Path


def docker_available() -> bool:
    return shutil.which("docker") is not None


def _base(t: ComposeTarget) -> list[str]:
    if not t.compose_file or not Path(t.compose_file).is_file():
        raise EngineControlError("docker-compose.yml was not found. Run `routes init` from the ROUTES folder, "
                                 "or set ROUTES_COMPOSE_FILE.")
    if not t.env_file or not Path(t.env_file).is_file():
        raise EngineControlError("The engine env file is missing. Run `routes init`.")
    return ["docker", "compose", "-f", str(t.compose_file), "--env-file", str(t.env_file)]


def up_command(t: ComposeTarget, *, build: bool = True, sample_site: bool = False) -> list[str]:
    cmd = _base(t)
    if sample_site:
        cmd += ["--profile", "testing"]
    cmd += ["up", "-d", "--wait"]
    if build:
        cmd.append("--build")
    cmd += ["discovery-image", "analyzer-image", *ENGINE_SERVICES]
    if sample_site:
        cmd.append("sample-site")
    return cmd


def stop_command(t: ComposeTarget) -> list[str]:
    return _base(t) + ["stop", *ENGINE_SERVICES]


def stream(cmd: list[str], on_line: Callable[[str], None] | None = None, *, timeout: int = 3600) -> int:
    """Run a fixed command, passing each output line to ``on_line``."""
    if not docker_available():
        raise EngineControlError("Docker is not installed or not on PATH.")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                            errors="replace", stdin=subprocess.DEVNULL)
    try:
        for line in _lines(proc):
            if on_line:
                on_line(line.rstrip())
        return proc.wait(timeout=timeout)
    except BaseException:
        proc.kill()
        raise


def _lines(proc: subprocess.Popen) -> Iterator[str]:
    assert proc.stdout is not None
    yield from proc.stdout


def run_quiet(cmd: list[str], *, timeout: int = 20) -> tuple[int, str]:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                             timeout=timeout, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        return 127, "docker not found"
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    return out.returncode, (out.stdout or out.stderr).strip()
