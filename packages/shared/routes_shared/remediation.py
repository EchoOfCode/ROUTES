"""Shared data shapes for the remediation loop.

Plain dataclasses with no heavy dependency (no tree-sitter, no httpx), so
they can cross the source_analyzer <-> worker boundary: source_analyzer
builds a Snapshot (via tree-sitter, sandbox-only) and worker-remediate
consumes it (via an external LLM, worker-only) - both sides need the same
shape, and routes_shared is the only package both already install.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Snapshot:
    """The data-flow slice sent to LLM A/B: plain code, no LLM involved in
    producing it."""

    file: str
    start_line: int
    end_line: int
    code: str


@dataclass
class Testbench:
    """A finding's frozen exploit/benign test file. Shape only - built out in S7."""

    path: str
    content: str


@dataclass
class Assertion:
    """One testbench assertion. Shape only - built out in S7."""

    name: str
    category: str  # "exploit" | "benign"


@dataclass
class FixConstraints:
    """What a candidate fix for this finding must satisfy."""

    file: str
    start_line: int
    end_line: int
    forbid_new_dependencies: bool = True
    forbid_network_calls: bool = True
