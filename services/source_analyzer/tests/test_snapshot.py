"""Unit tests for VulnClass.build_snapshot() (S4): the snapshot cuts the
finding's enclosing function via tree-sitter, not just the flagged line.

Self-contained (hand-built source + AnalysisContext), not routed through the
acquire/profile/zip pipeline, so it does not touch test_analysis.py's fixture
suite.
"""

import pytest

from source_analyzer.data_flow.sqli import Module, SqliAnalyzer
from source_analyzer.structure.parser import parse
from source_analyzer.vuln_classes import AnalysisContext, SqliVulnClass

SOURCE = b"""
export async function GET(request) {
  const q = request.nextUrl.searchParams.get("q") ?? "";
  const result = await pool.query(`SELECT * FROM products WHERE name ILIKE '%${q}%'`);
  return NextResponse.json(result.rows);
}

export async function POST(request) {
  return NextResponse.json({ ok: true });
}
"""

CONST_ARROW_SOURCE = b"""
export const Preview = () => {
  const el = document.getElementById("preview");
  el.innerHTML = location.search;
};
"""


def _ctx_with_parsed_module(rel: str, source: bytes) -> AnalysisContext:
    analyzer = SqliAnalyzer({rel: source})
    tree = parse(rel, source)
    analyzer.modules[rel] = Module(rel=rel, root=tree.root_node)
    ctx = AnalysisContext(files={rel: source}, tsconfig_paths={}, tsconfig_base="", pg_declared=False)
    ctx.sqli_analyzer = analyzer
    return ctx


def test_build_snapshot_cuts_the_enclosing_function_not_just_the_line():
    rel = "app/api/search/route.ts"
    ctx = _ctx_with_parsed_module(rel, SOURCE)
    finding = {"file": rel, "line": 4, "end_line": 4}  # the pool.query(...) line

    snapshot = SqliVulnClass().build_snapshot(finding, ctx)

    assert snapshot.file == rel
    assert snapshot.start_line < finding["line"] < snapshot.end_line
    assert "export async function GET" in snapshot.code
    assert "pool.query" in snapshot.code
    assert "POST" not in snapshot.code  # the sibling function is excluded


def test_build_snapshot_includes_export_wrapper_for_const_arrow_functions():
    rel = "components/Preview.tsx"
    ctx = _ctx_with_parsed_module(rel, CONST_ARROW_SOURCE)
    finding = {"file": rel, "line": 4, "end_line": 4}  # the el.innerHTML = ... line

    snapshot = SqliVulnClass().build_snapshot(finding, ctx)

    assert snapshot.code.strip().startswith("export const Preview")
    assert "innerHTML" in snapshot.code


def test_build_snapshot_falls_back_to_the_line_range_with_no_enclosing_function():
    rel = "config/constants.ts"
    source = b"export const MAX_RETRIES = 3;\nexport const TIMEOUT_MS = 5000;\n"
    ctx = _ctx_with_parsed_module(rel, source)
    finding = {"file": rel, "line": 1, "end_line": 1}

    snapshot = SqliVulnClass().build_snapshot(finding, ctx)

    assert snapshot.start_line == 1 and snapshot.end_line == 1
    assert snapshot.code.strip() == "export const MAX_RETRIES = 3;"


def test_build_snapshot_unknown_file_raises_instead_of_fabricating_a_snapshot():
    ctx = _ctx_with_parsed_module("a.ts", b"export const x = 1;\n")
    finding = {"file": "b.ts", "line": 1, "end_line": 1}

    with pytest.raises(ValueError):
        SqliVulnClass().build_snapshot(finding, ctx)
