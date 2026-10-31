"""Bounded subprocess execution for the build runner.

Every command runs in its own process group with a hard timeout; the whole
group is killed when the time is up, so stray child processes (dev servers,
watchers) cannot outlive their stage. Output is kept as a bounded tail only.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field

TAIL_BYTES = 12 * 1024


class Tail:
    """Thread-safe ring buffer over a process's combined stdout/stderr."""

    def __init__(self, limit: int = TAIL_BYTES):
        self.limit = limit
        self._chunks: deque[bytes] = deque()
        self._size = 0
        self.total = 0
        self._lock = threading.Lock()

    def add(self, data: bytes) -> None:
        with self._lock:
            self.total += len(data)
            self._chunks.append(data)
            self._size += len(data)
            while self._size > self.limit and len(self._chunks) > 1:
                self._size -= len(self._chunks.popleft())

    def text(self) -> str:
        with self._lock:
            data = b"".join(self._chunks)[-self.limit:]
        text = data.decode("utf-8", "replace")
        return ("[...earlier output omitted...]\n" + text) if self.total > len(data) else text


@dataclass
class ProcResult:
    exit_code: int | None
    timed_out: bool
    duration: float
    tail: str
    command: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


@dataclass
class Background:
    proc: subprocess.Popen
    tail: Tail
    started: float = field(default_factory=time.monotonic)
    _reader: threading.Thread | None = None

    def alive(self) -> bool:
        return self.proc.poll() is None

    def stop(self, grace: float = 5.0) -> int | None:
        _kill_group(self.proc, signal.SIGTERM)
        try:
            self.proc.wait(grace)
        except subprocess.TimeoutExpired:
            _kill_group(self.proc, signal.SIGKILL)
            self.proc.wait(5)
        if self._reader is not None:
            self._reader.join(2)
        return self.proc.returncode


def _kill_group(proc: subprocess.Popen, sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)
    except (ProcessLookupError, PermissionError, AttributeError):
        try:
            proc.send_signal(sig)
        except ProcessLookupError:
            pass


def _pump(stream, tail: Tail) -> None:
    for chunk in iter(lambda: stream.read1(8192) if hasattr(stream, "read1") else stream.read(8192), b""):
        tail.add(chunk)
    stream.close()


def _popen(cmd: list[str], cwd: str, env: dict[str, str]) -> subprocess.Popen:
    return subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, start_new_session=True)


def run(cmd: list[str], *, cwd: str, env: dict[str, str], timeout: float, tail_bytes: int = TAIL_BYTES) -> ProcResult:
    tail = Tail(tail_bytes)
    started = time.monotonic()
    try:
        proc = _popen(cmd, cwd, env)
    except OSError as exc:
        return ProcResult(None, False, 0.0, f"Could not start {cmd[0]}: {exc.strerror or exc}", " ".join(cmd))
    reader = threading.Thread(target=_pump, args=(proc.stdout, tail), daemon=True)
    reader.start()
    timed_out = False
    try:
        proc.wait(timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(proc, signal.SIGKILL)
        proc.wait(10)
    else:
        _kill_group(proc, signal.SIGKILL)   # leftover children of a finished command
    reader.join(5)
    return ProcResult(proc.returncode, timed_out, round(time.monotonic() - started, 1), tail.text(), " ".join(cmd))


def start(cmd: list[str], *, cwd: str, env: dict[str, str], tail_bytes: int = TAIL_BYTES) -> Background:
    tail = Tail(tail_bytes)
    proc = _popen(cmd, cwd, env)
    bg = Background(proc, tail)
    bg._reader = threading.Thread(target=_pump, args=(proc.stdout, tail), daemon=True)
    bg._reader.start()
    return bg
