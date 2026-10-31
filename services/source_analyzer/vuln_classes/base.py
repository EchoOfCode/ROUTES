"""The VulnClass plugin interface.

Each vulnerability class (SQLi, XSS, and whatever is added later) implements
this once instead of main.py growing a bespoke branch per class. As of S3
only detect() has a real implementation - it is SqliAnalyzer/XssAnalyzer
moved behind the interface with no behavior change. The rest of the
remediation pipeline (snapshot, testbench, fix validation) raises
NotImplementedError until S4/S6/S7 build real logic for it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from source_analyzer.data_flow.sqli import SqliAnalyzer


@dataclass
class AnalysisContext:
    """Shared, parsed state for one source tree, built once per analyse()
    call and threaded through every registered VulnClass's detect().

    SqliVulnClass.detect() populates `sqli_analyzer` as a side effect of
    running; XssVulnClass.detect() requires it to already be populated,
    since it reuses SqliAnalyzer's parsed module ASTs and discovered routes
    instead of re-parsing the tree itself. This mirrors the coupling that
    existed in main.py before S3 exactly - it is not a new dependency
    introduced here, and VULN_CLASSES' registration order (sqli before xss)
    exists specifically to satisfy it.
    """

    files: dict[str, bytes]
    tsconfig_paths: dict[str, list[str]]
    tsconfig_base: str
    pg_declared: bool
    warnings: list[str] = field(default_factory=list)
    sqli_analyzer: "SqliAnalyzer | None" = None


@dataclass
class Snapshot:
    """The data-flow slice sent to LLM A/B. Shape only - built out in S4."""

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
    """What a candidate fix for this finding must satisfy. Shape only - built
    out in S6 (fix-response validation)."""

    file: str
    start_line: int
    end_line: int
    forbid_new_dependencies: bool = True
    forbid_network_calls: bool = True


class VulnClass(ABC):
    rule_prefix: str  # e.g. "routes.sqli", "routes.xss"

    @abstractmethod
    def detect(self, ctx: AnalysisContext) -> list[dict]:
        """Return findings in the same dict shape main.py has always built
        (the shape persisted to SecurityFinding)."""

    def build_snapshot(self, finding: dict, ctx: AnalysisContext) -> Snapshot:
        raise NotImplementedError("Snapshot extraction lands in S4.")

    def build_testbench(self, finding: dict, snapshot: Snapshot) -> Testbench:
        raise NotImplementedError("Testbench generation lands in S7.")

    def exploit_assertions(self, finding: dict) -> list[Assertion]:
        raise NotImplementedError("Testbench generation lands in S7.")

    def benign_assertions(self, finding: dict) -> list[Assertion]:
        raise NotImplementedError("Testbench generation lands in S7.")

    def fix_constraints(self, finding: dict, snapshot: Snapshot) -> FixConstraints:
        raise NotImplementedError("Fix-response validation lands in S6.")
