"""Fixed, in-code library of plausible-but-wrong fixes per vulnerability
class. A correct testbench must still catch every one of these as
vulnerable - if it doesn't, the testbench itself is untrustworthy, not the
finding fixed (S7's gate). SQLi first.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class KnownBadFix:
    name: str
    code: str


SQLI_KNOWN_BAD_FIXES: list[KnownBadFix] = [
    KnownBadFix(
        name="keyword-blacklist",
        code="""export async function GET(request) {
  const q = request.nextUrl.searchParams.get("q") ?? "";
  if (/drop|delete|insert|update/i.test(q)) {
    throw new Error("blocked");
  }
  const result = await pool.query(`SELECT * FROM products WHERE name ILIKE '%${q}%'`);
  return NextResponse.json(result.rows);
}""",
    ),
    KnownBadFix(
        name="comment-only-noop",
        code="""export async function GET(request) {
  // sanitized input before use
  const q = request.nextUrl.searchParams.get("q") ?? "";
  const result = await pool.query(`SELECT * FROM products WHERE name ILIKE '%${q}%'`);
  return NextResponse.json(result.rows);
}""",
    ),
    KnownBadFix(
        name="length-limit-only",
        code="""export async function GET(request) {
  const q = (request.nextUrl.searchParams.get("q") ?? "").slice(0, 50);
  const result = await pool.query(`SELECT * FROM products WHERE name ILIKE '%${q}%'`);
  return NextResponse.json(result.rows);
}""",
    ),
]

KNOWN_BAD_FIXES: dict[str, list[KnownBadFix]] = {
    "routes.sqli": SQLI_KNOWN_BAD_FIXES,
}


def known_bad_fixes_for(rule_id: str) -> list[KnownBadFix]:
    for prefix, fixes in KNOWN_BAD_FIXES.items():
        if rule_id.startswith(prefix):
            return fixes
    return []
