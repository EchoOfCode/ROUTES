"""End-to-end analyzer tests on fixture repositories (ZIP path, no network)."""

import json
import zipfile
from pathlib import Path
from shutil import copytree

import pytest

from source_analyzer import main as analyzer_main
from source_analyzer.acquisition.archive import extract_zip
from source_analyzer.main import analyse

FIXTURES = Path(__file__).parent / "fixtures"


def zip_fixture(name: str, tmp_path: Path, extra: dict[str, str] | None = None) -> Path:
    """Zip a fixture repo. An `extra` entry replaces a fixture file of the same
    name rather than being added alongside it (extract_zip rejects duplicates)."""
    root = FIXTURES / name
    path = tmp_path / f"{name}.zip"
    extra = extra or {}
    with zipfile.ZipFile(path, "w") as zf:
        for f in root.rglob("*"):
            rel = f.relative_to(root).as_posix() if f.is_file() else None
            if rel and rel not in extra:
                zf.write(f, f"{name}-main/{rel}")
        for rel, content in extra.items():
            zf.writestr(f"{name}-main/{rel}", content)
    return path


def run_fixture(name, tmp_path, target_host="", extra=None):
    src = tmp_path / "src"
    src.mkdir()
    extract_zip(zip_fixture(name, tmp_path, extra), src)
    return analyse(src, "zip", target_host)


@pytest.fixture(scope="module")
def nextjs(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("nextjs")
    # Dependency folders must never be analysed even if they contain "vulnerable" code.
    return run_fixture("nextjs-pg", tmp, "shop.acme-demo.com",
                       extra={"node_modules/evil/index.js": 'const {Pool}=require("pg");new Pool().query("x"+process.argv[2]);'})


def sqli(result):
    return [f for f in result["findings"] if f["type"] == "SQL Injection"]


def xss(result):
    return [f for f in result["findings"] if f["type"] == "Cross-Site Scripting"]


def by_file(findings):
    out = {}
    for f in findings:
        out.setdefault(f["file"], []).append(f)
    return out


def test_profile(nextjs):
    p = nextjs["profile"]
    assert nextjs["support_status"] == "supported"
    assert p["framework"] == "Next.js" and p["framework_version"] == "14.2.3"
    assert p["runtime"] == "Node.js" and p["router"] == "app+pages"
    assert "PostgreSQL (pg)" in p["database_libraries"]
    assert p["package_manager"] == "npm" and p["typescript"] is True
    assert "DATABASE_URL" in nextjs["env_var_names"] and "STRIPE_SECRET_KEY" in nextjs["env_var_names"]


def test_routes_discovered_from_source(nextjs):
    routes = {r["path"]: r for r in nextjs["routes"]}
    assert routes["/api/search"]["methods"] == ["GET"]
    assert routes["/api/products/[id]"]["methods"] == ["DELETE", "GET"]
    assert routes["/api/report"]["file"] == "app/(admin)/api/report/route.ts"  # route group stripped
    assert routes["/api/raw"]["methods"] == ["POST"]  # exported arrow function
    assert routes["/api/legacy"]["router"] == "pages" and routes["/api/legacy"]["methods"] == ["GET"]


def test_true_positives(nextjs):
    files = by_file(f for f in sqli(nextjs) if f["status"] == "potential")
    search = files["app/api/search/route.ts"][0]
    assert search["line"] == 6 and search["endpoint"] == "/api/search" and search["method"] == "GET"
    assert search["confidence"] == "high" and search["severity"] == "high"
    assert search["technical_details"]["source"]["kind"] == "URL query parameter"
    assert search["technical_details"]["source"]["name"] == "q"
    assert search["technical_details"]["query_construction"] == "interpolated"

    product = files["app/api/products/[id]/route.ts"]
    assert [f["line"] for f in product] == [6]  # GET only; DELETE is parameterised
    assert product[0]["technical_details"]["source"]["kind"] == "route parameter"

    raw = files["app/api/raw/route.ts"][0]
    assert raw["severity"] == "critical" and raw["technical_details"]["query_construction"] == "direct"

    report = files["app/(admin)/api/report/route.ts"][0]
    assert report["technical_details"]["source"]["kind"] == "form data"
    assert report["endpoint"] == "/api/report"

    legacy = files["pages/api/legacy.js"][0]
    assert legacy["method"] == "GET" and legacy["technical_details"]["source"]["kind"] == "URL query parameter"

    # Helper in lib/db.ts reached with request-body input from POST /api/users.
    helper = files["lib/db.ts"][0]
    assert helper["line"] == 6 and helper["endpoint"] == "/api/users" and helper["method"] == "POST"
    assert helper["confidence"] == "medium"
    assert helper["technical_details"]["call_site"]["file"] == "app/api/users/route.ts"
    assert helper["technical_details"]["source"]["kind"] == "request body"


def test_false_positive_handling(nextjs):
    flagged = {f["file"] for f in sqli(nextjs) if f["status"] == "potential"}
    for safe in ["app/api/safe/route.ts", "app/api/sort/route.ts", "app/api/limit/route.ts",
                 "app/api/constant/route.ts"]:
        assert safe not in flagged, safe
    assert not any(f["file"].startswith("node_modules") for f in nextjs["findings"])
    interactions = {(d["file"], d["line"]): d for d in nextjs["db_interactions"]}
    assert interactions[("app/api/safe/route.ts", 6)]["query_construction"] == "parameterised"
    assert interactions[("app/api/safe/route.ts", 7)]["query_construction"] == "parameterised"
    assert interactions[("app/api/limit/route.ts", 7)]["uses_user_input"] is False
    assert interactions[("app/api/products/[id]/route.ts", 11)]["query_construction"] == "parameterised"


def test_inconclusive_helper(nextjs):
    inconclusive = [f for f in sqli(nextjs) if f["status"] == "inconclusive"]
    assert [(f["file"], f["line"]) for f in inconclusive] == [("lib/reports.ts", 5)]
    assert inconclusive[0]["confidence"] == "low"


def test_no_confirmed_findings_in_phase_1(nextjs):
    assert all(f["status"] in ("potential", "inconclusive") for f in nextjs["findings"])


def test_xss_dom_sink(nextjs):
    found = [f for f in xss(nextjs) if f["rule_id"] == "routes.xss.dom-sink-tainted"]
    assert len(found) == 1
    f = found[0]
    assert f["file"] == "components/Preview.tsx"
    assert f["end_line"] >= f["line"]
    assert f["technical_details"]["source"]["kind"] == "URL/browser state"
    assert "innerHTML" in f["evidence_summary"]


def test_xss_reflected_response(nextjs):
    found = [f for f in xss(nextjs) if f["rule_id"] == "routes.xss.reflected-response"]
    assert len(found) == 1
    f = found[0]
    assert f["file"] == "app/api/echo/route.ts"
    assert f["endpoint"] == "/api/echo" and f["method"] == "GET"
    assert f["confidence"] == "high" and f["severity"] == "high"
    assert f["technical_details"]["source"]["kind"] == "URL query parameter"
    assert f["technical_details"]["source"]["name"] == "name"


def test_findings_carry_a_snapshot_of_their_enclosing_function(nextjs):
    """S8a: the snapshot (rather than just file/line) is persisted at scan
    time, since the worker has no way to rebuild it later."""
    search = next(f for f in sqli(nextjs) if f["file"] == "app/api/search/route.ts")
    snapshot = search["snapshot"]
    assert snapshot is not None
    assert snapshot["file"] == "app/api/search/route.ts"
    assert snapshot["start_line"] < search["line"] < snapshot["end_line"]
    assert "export async function GET" in snapshot["code"]
    assert "pool.query" in snapshot["code"]

    dom_sink = next(f for f in xss(nextjs) if f["rule_id"] == "routes.xss.dom-sink-tainted")
    assert dom_sink["snapshot"] is not None
    assert dom_sink["snapshot"]["code"].strip().startswith("export function Preview")

    # Semgrep-sourced findings aren't behind a VulnClass plugin yet, so they
    # have no snapshot - confirmed absent rather than silently fabricated.
    secret_finding = next(f for f in nextjs["findings"] if f["rule_id"] == "routes.secrets.aws-access-key")
    assert secret_finding.get("snapshot") is None


def test_semgrep_rules(nextjs):
    rules = {(f["rule_id"], f["file"], f["line"]) for f in nextjs["findings"]}
    assert ("routes.exec.child-process-dynamic", "app/api/exec/route.ts", 5) in rules
    assert not any(r[0] == "routes.exec.child-process-dynamic" and r[2] == 6 for r in rules)  # constant command
    assert ("routes.config.tls-verification-disabled", "config/aws.js", 4) in rules
    assert any(r[0] == "routes.secrets.aws-access-key" and r[1] == "config/aws.js" for r in rules)


def test_secrets_are_redacted_everywhere(nextjs):
    dump = json.dumps(nextjs)
    assert "AKIAQWERTYUIOPASDFGH" not in dump
    secret = next(f for f in nextjs["findings"] if f["rule_id"] == "routes.secrets.aws-access-key")
    assert "AKIA…[redacted]" in secret["evidence_summary"]


def test_password_hashes_are_not_reported_as_secrets(nextjs):
    seed = [f for f in nextjs["findings"] if f["file"] == "lib/seed.js"]
    assert [(f["rule_id"], f["line"]) for f in seed] == [("routes.secrets.generic-assignment", 8)]
    assert "Winter2024Launch!" not in json.dumps(nextjs)


def test_repository_matching(nextjs):
    matching = [e for e in nextjs["match_evidence"] if e["matches_target"]]
    kinds = {e["kind"] for e in matching}
    assert "homepage" in kinds and "website_reference" in kinds


def test_plain_language(nextjs):
    f = next(f for f in sqli(nextjs) if f["file"] == "app/api/search/route.ts")
    assert "database query" in f["plain_description"]
    assert "tainted" not in f["plain_description"].lower() and "sink" not in f["plain_description"].lower()
    assert "$1" in f["recommendation"]


def test_unsupported_stack(tmp_path):
    result = run_fixture("flask-app", tmp_path)
    assert result["support_status"] == "unsupported"
    assert "Python" in result["support_reason"]
    assert result["routes"] == [] and not any(f["type"] == "SQL Injection" for f in result["findings"])


def test_partial_support_without_pg(tmp_path):
    result = run_fixture("nextjs-prisma", tmp_path)
    assert result["support_status"] == "partial"
    assert "Prisma ORM" in result["support_reason"]
    assert [r["path"] for r in result["routes"]] == ["/api/items"]


def test_fingerprint_survives_reformatting(tmp_path_factory):
    """M1 acceptance test: reformatting a vulnerable file (reindenting, adding
    blank lines, shifting its line numbers) must not change its fingerprint."""
    base = run_fixture("nextjs-pg", tmp_path_factory.mktemp("fp_base"), "shop.acme-demo.com")

    moved_root = tmp_path_factory.mktemp("fp_moved_src")
    copytree(FIXTURES / "nextjs-pg", moved_root, dirs_exist_ok=True)
    target = moved_root / "app" / "api" / "search" / "route.ts"
    reformatted = "\n\n\n" + target.read_text().replace("const q = ", "const   q    =   ")
    target.write_text(reformatted)

    zip_path = tmp_path_factory.mktemp("fp_moved_zip") / "nextjs-pg.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for f in moved_root.rglob("*"):
            if f.is_file():
                zf.write(f, f"nextjs-pg-main/{f.relative_to(moved_root).as_posix()}")
    src_dir = tmp_path_factory.mktemp("fp_moved_extract")
    extract_zip(zip_path, src_dir)
    moved = analyse(src_dir, "zip", "shop.acme-demo.com")

    before = next(f for f in sqli(base) if f["file"] == "app/api/search/route.ts")
    after = next(f for f in sqli(moved) if f["file"] == "app/api/search/route.ts")
    assert before["line"] != after["line"]
    assert before["fingerprint"] == after["fingerprint"]


def test_main_reports_fatal_for_bad_archive(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ROUTES_SOURCE_KIND", "zip")
    monkeypatch.setattr(analyzer_main, "WORK", tmp_path)
    analyzer_main.main()
    out = capsys.readouterr().out
    assert out.startswith("ROUTES_RESULT ")
    data = json.loads(out[len("ROUTES_RESULT "):])
    assert data["fatal"] is True and "Upload it again" in data["error"]
