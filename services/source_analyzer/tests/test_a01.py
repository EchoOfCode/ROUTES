"""A01 (broken access control) detection tests.

The spec's three behaviours - no session rejected, another user's record
rejected, the owner still allowed - are properties of a *fixed* application,
so at detection time they appear as: the unprotected handler is flagged, the
handler that queries by request id without the session is flagged, and the
handler that scopes its query to the session user is not.
"""

import pytest

from .test_analysis import run_fixture

# NextAuth v5's documented shape: auth() re-exported from a local module.
AUTH_MODULE = """\
import NextAuth from "next-auth";

export const { handlers, auth } = NextAuth({ providers: [] });
"""

# Flagged: queries the database, never reads a session.
UNPROTECTED_GET = """\
import { pool } from "../../../lib/db";

export async function GET() {
  const { rows } = await pool.query("SELECT id, email, user_id FROM invoices");
  return Response.json(rows);
}
"""

# Flagged, and more seriously: an unauthenticated write.
UNPROTECTED_DELETE = """\
import { pool } from "../../../lib/db";

export async function DELETE(request: Request) {
  const id = new URL(request.url).searchParams.get("id");
  await pool.query("DELETE FROM invoices WHERE id = $1", [id]);
  return new Response(null, { status: 204 });
}
"""

# Flagged: authenticated, but the query trusts the request's id alone.
IDOR_GET = """\
import { auth } from "../../../../auth";
import { pool } from "../../../../lib/db";

export async function GET(request: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  const id = params.id;
  const { rows } = await pool.query("SELECT * FROM invoices WHERE id = $1", [id]);
  return Response.json(rows[0]);
}
"""

# Not flagged: the signed-in user is part of the query.
SCOPED_GET = """\
import { auth } from "../../../../auth";
import { pool } from "../../../../lib/db";

export async function GET(request: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });
  const id = params.id;
  const { rows } = await pool.query(
    "SELECT * FROM invoices WHERE id = $1 AND user_id = $2",
    [id, session.user.id],
  );
  if (!rows.length) return new Response("Not found", { status: 404 });
  return Response.json(rows[0]);
}
"""

# Not flagged: no database access at all.
NO_DB_ROUTE = """\
export async function GET() {
  return Response.json({ status: "ok" });
}
"""

FILES = {
    "auth.ts": AUTH_MODULE,
    "app/api/invoices/route.ts": UNPROTECTED_GET,
    "app/api/invoices/purge/route.ts": UNPROTECTED_DELETE,
    "app/api/invoices/[id]/route.ts": IDOR_GET,
    "app/api/invoices/[id]/scoped/route.ts": SCOPED_GET,
    "app/api/health/route.ts": NO_DB_ROUTE,
}


@pytest.fixture(scope="module")
def a01(tmp_path_factory):
    return run_fixture("nextjs-pg", tmp_path_factory.mktemp("a01"), extra=FILES)


def a01_findings(result, rule_id=None):
    return [f for f in result["findings"]
            if f["type"] == "Broken Access Control" and (rule_id is None or f["rule_id"] == rule_id)]


def for_file(result, path, rule_id=None):
    return [f for f in a01_findings(result, rule_id) if f["file"] == path]


# --------------------------------------------------- unprotected db routes

def test_unprotected_read_is_reported(a01):
    found = for_file(a01, "app/api/invoices/route.ts", "routes.a01.unprotected-db-route")
    assert len(found) == 1
    assert found[0]["endpoint"] == "/api/invoices" and found[0]["method"] == "GET"


def test_unprotected_write_is_more_severe_than_an_unprotected_read(a01):
    read = for_file(a01, "app/api/invoices/route.ts", "routes.a01.unprotected-db-route")[0]
    write = for_file(a01, "app/api/invoices/purge/route.ts", "routes.a01.unprotected-db-route")[0]
    assert (write["severity"], write["confidence"]) == ("high", "medium")
    assert (read["severity"], read["confidence"]) == ("medium", "low")


def test_route_that_never_touches_the_database_is_not_reported(a01):
    assert not for_file(a01, "app/api/health/route.ts")


def test_authenticated_route_is_not_reported_as_unprotected(a01):
    assert not for_file(a01, "app/api/invoices/[id]/route.ts", "routes.a01.unprotected-db-route")
    assert not for_file(a01, "app/api/invoices/[id]/scoped/route.ts", "routes.a01.unprotected-db-route")


# ------------------------------------------------------- ownership checks

def test_query_by_request_id_without_the_session_is_reported(a01):
    found = for_file(a01, "app/api/invoices/[id]/route.ts", "routes.a01.missing-ownership-check")
    assert len(found) == 1
    details = found[0]["technical_details"]
    assert details["request_id_variable"] == "id"
    assert details["session_variables"] == ["session"]


def test_query_scoped_to_the_session_user_is_not_reported(a01):
    assert not for_file(a01, "app/api/invoices/[id]/scoped/route.ts", "routes.a01.missing-ownership-check")


def test_confidence_reflects_whether_an_owner_column_was_visible(a01):
    """No owner column in the query means the schema may not support ownership
    at all, which is a weaker claim than one that could simply be filtered."""
    found = for_file(a01, "app/api/invoices/[id]/route.ts", "routes.a01.missing-ownership-check")[0]
    assert found["technical_details"]["owner_columns_seen"] == []
    assert found["confidence"] == "low"


def test_ownership_finding_explains_the_fix_concretely(a01):
    found = for_file(a01, "app/api/invoices/[id]/route.ts", "routes.a01.missing-ownership-check")[0]
    assert "user_id = $2" in found["recommendation"]
    assert "404" in found["recommendation"]


# ------------------------------------------------- shared finding plumbing

def test_a01_findings_carry_a_protected_sibling_as_a_worked_example(a01):
    """So a fix follows the project's own auth pattern rather than an invented one."""
    found = for_file(a01, "app/api/invoices/route.ts", "routes.a01.unprotected-db-route")[0]
    example = found["technical_details"]["protected_example"]
    assert example is not None
    assert example["session_variable"] == "session"
    assert "await auth()" in example["code"]
    assert example["file"].startswith("app/api/invoices/[id]/")


def test_a01_findings_carry_a_snapshot_of_their_handler(a01):
    for f in a01_findings(a01):
        assert f["snapshot"] is not None, f["file"]
        # Handlers are declared three ways across the fixture (named export,
        # default export, exported arrow const); all snapshot to the whole
        # exported unit rather than the signature line.
        assert f["snapshot"]["code"].startswith("export")
        assert f["snapshot"]["end_line"] > f["snapshot"]["start_line"]
        assert f["snapshot"]["code"].rstrip().endswith(("}", "};"))


def test_a01_findings_are_potential_not_confirmed(a01):
    assert a01_findings(a01)
    assert all(f["status"] == "potential" for f in a01_findings(a01))
    assert all("Not dynamically verified" in f["technical_details"]["verification"]
               for f in a01_findings(a01))


def test_a01_states_that_only_nextauth_is_recognised(a01):
    found = for_file(a01, "app/api/invoices/route.ts", "routes.a01.unprotected-db-route")[0]
    assert "NextAuth only" in found["technical_details"]["auth_support"]


def test_existing_fixture_routes_do_not_become_ownership_findings(a01):
    """The pre-existing fixture has no auth at all, so nothing in it can be an
    ownership finding - that rule requires a recognised session first."""
    ownership = a01_findings(a01, "routes.a01.missing-ownership-check")
    assert {f["file"] for f in ownership} == {"app/api/invoices/[id]/route.ts"}
