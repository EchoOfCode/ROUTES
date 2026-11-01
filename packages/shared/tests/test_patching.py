import pytest

from routes_shared.buildrun import PatchRejected
from routes_shared.patching import apply_unified_diff, unified_diff

FILE = "app/api/products/route.js"
BEFORE = [
    'import { NextResponse } from "next/server";',
    "",
    "export async function GET(request) {",
    '  const q = request.nextUrl.searchParams.get("q") ?? "";',
    "  const result = await pool.query(`SELECT * FROM products WHERE name ILIKE '%${q}%'`);",
    "  return NextResponse.json(result.rows);",
    "}",
    "",
    "export const tail = 1;",
]
REGION = "\n".join(BEFORE[2:7])
FIXED = REGION.replace("pool.query(`SELECT * FROM products WHERE name ILIKE '%${q}%'`)",
                       "pool.query(\"SELECT * FROM products WHERE name ILIKE '%' || $1 || '%'\", [q])")


def tree(tmp_path, text: str):
    (tmp_path / "app/api/products").mkdir(parents=True)
    (tmp_path / FILE).write_bytes(text.encode())
    return tmp_path


def test_region_diff_applies_at_its_real_position(tmp_path):
    root = tree(tmp_path, "\n".join(BEFORE) + "\n")
    diff = unified_diff(FILE, 3, REGION, FIXED)
    assert "@@ -3," in diff
    assert apply_unified_diff(root, diff) == [FILE]
    out = (root / FILE).read_text()
    assert "$1" in out and out.startswith('import { NextResponse }') and out.endswith("export const tail = 1;\n")


def test_crlf_files_keep_their_line_endings(tmp_path):
    root = tree(tmp_path, "\r\n".join(BEFORE) + "\r\n")
    apply_unified_diff(root, unified_diff(FILE, 3, REGION, FIXED))
    raw = (root / FILE).read_bytes()
    assert b"$1" in raw and b"\r\n" in raw and b"\n" not in raw.replace(b"\r\n", b"")


def test_a_patch_that_does_not_match_exactly_is_refused_and_nothing_changes(tmp_path):
    root = tree(tmp_path, "\n".join(BEFORE) + "\n")
    wrong_position = unified_diff(FILE, 1, REGION, FIXED)
    with pytest.raises(PatchRejected, match="does not apply"):
        apply_unified_diff(root, wrong_position)
    assert (root / FILE).read_text() == "\n".join(BEFORE) + "\n"


def test_unsafe_or_missing_targets_are_refused(tmp_path):
    root = tree(tmp_path, "\n".join(BEFORE) + "\n")
    with pytest.raises(PatchRejected):
        apply_unified_diff(root, unified_diff("../escape.js", 3, REGION, FIXED))
    with pytest.raises(PatchRejected, match="does not exist"):
        apply_unified_diff(root, unified_diff("app/missing.js", 3, REGION, FIXED))
    with pytest.raises(PatchRejected):
        apply_unified_diff(root, "not a diff")
