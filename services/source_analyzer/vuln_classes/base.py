"""The VulnClass plugin interface.

Each vulnerability class (SQLi, XSS, and whatever is added later) implements
this once instead of main.py growing a bespoke branch per class. detect() is
SqliAnalyzer/XssAnalyzer moved behind the interface with no behavior change
(S3). build_snapshot() (S4) is a real, shared implementation: find the
smallest tree-sitter function enclosing the finding's line, widened to
include its export wrapper if any, so the slice stays a valid re-insertable
unit. The rest of the pipeline (testbench) still raises NotImplementedError
until S7 builds real logic for it.

Snapshot/Testbench/Assertion/FixConstraints live in routes_shared, not here
(see routes_shared.remediation) - worker-remediate needs to consume a
Snapshot/FixConstraints too (S6), and routes_shared is the only package both
source_analyzer and worker already install.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from tree_sitter import Node

from routes_shared.remediation import Assertion, FixConstraints, Snapshot, Testbench

from source_analyzer.structure.parser import FUNCTION_TYPES, walk

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


# Climb at most this many parent levels above a matched function node looking
# for an export wrapper (covers `export function f(){}` - 1 level - and
# `export const f = () => {}` - arrow_function -> variable_declarator ->
# lexical_declaration -> export_statement - 3 levels).
_MAX_EXPORT_CLIMB = 3
_EXPORT_CLIMB_THROUGH = ("variable_declarator", "lexical_declaration", "variable_declaration")


def _enclosing_function(root: Node, line_no: int) -> Node | None:
    """The smallest *standalone* function node (tree-sitter FUNCTION_TYPES)
    containing `line_no` (1-indexed), widened to its export_statement
    wrapper if any. "Standalone" excludes a bare callback passed directly as
    a call argument (e.g. `useEffect(() => {...})`) unless there is no other
    candidate - such a function has no name and isn't independently
    reinsertable, so it would make a useless snapshot."""
    target_row = line_no - 1
    candidates = [n for n in walk(root) if n.type in FUNCTION_TYPES and n.start_point[0] <= target_row <= n.end_point[0]]
    if not candidates:
        return None
    standalone = [n for n in candidates if n.parent is None or n.parent.type != "arguments"]
    pool = standalone or candidates
    fn = min(pool, key=lambda n: n.end_point[0] - n.start_point[0])
    node = fn
    for _ in range(_MAX_EXPORT_CLIMB):
        parent = node.parent
        if parent is None:
            break
        if parent.type == "export_statement":
            return parent
        if parent.type not in _EXPORT_CLIMB_THROUGH:
            break
        node = parent
    return fn


class VulnClass(ABC):
    rule_prefix: str  # e.g. "routes.sqli", "routes.xss"

    @abstractmethod
    def detect(self, ctx: AnalysisContext) -> list[dict]:
        """Return findings in the same dict shape main.py has always built
        (the shape persisted to SecurityFinding)."""

    def build_snapshot(self, finding: dict, ctx: AnalysisContext) -> Snapshot:
        """Cut the finding's enclosing function out of its file via
        tree-sitter. Falls back to just the finding's own line range if no
        enclosing function is found (e.g. a module-level constant)."""
        file = finding["file"]
        if ctx.sqli_analyzer is None or file not in ctx.sqli_analyzer.modules:
            raise ValueError(f"No parsed module available for {file!r}; cannot build a snapshot.")
        root = ctx.sqli_analyzer.modules[file].root
        source = ctx.files[file]

        fn = _enclosing_function(root, finding["line"])
        if fn is not None:
            return Snapshot(
                file=file, start_line=fn.start_point[0] + 1, end_line=fn.end_point[0] + 1,
                code=source[fn.start_byte:fn.end_byte].decode("utf-8", "replace"),
            )

        start_line = finding["line"]
        end_line = finding.get("end_line") or start_line
        lines = source.decode("utf-8", "replace").splitlines()
        return Snapshot(file=file, start_line=start_line, end_line=end_line,
                        code="\n".join(lines[start_line - 1:end_line]))

    def build_testbench(self, finding: dict, snapshot: Snapshot) -> Testbench:
        raise NotImplementedError("Testbench generation lands in S7.")

    def exploit_assertions(self, finding: dict) -> list[Assertion]:
        raise NotImplementedError("Testbench generation lands in S7.")

    def benign_assertions(self, finding: dict) -> list[Assertion]:
        raise NotImplementedError("Testbench generation lands in S7.")

    def fix_constraints(self, finding: dict, snapshot: Snapshot) -> FixConstraints:
        """Same for every vulnerability class: a candidate fix may only touch
        the snapshot's own file/line-range, add no new dependencies, and add
        no new network calls. See worker.llm.validation.validate_fix for
        where this is actually checked."""
        return FixConstraints(file=snapshot.file, start_line=snapshot.start_line, end_line=snapshot.end_line)
