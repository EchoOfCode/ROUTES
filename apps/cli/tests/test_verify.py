"""`routes verify`: request validation happens before the engine is contacted; no token flag exists."""

import json

from tests.test_commands import invoke


def test_verify_rejects_unsafe_patch_and_plan_before_contacting_engine(routes_home, tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text("{}")
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"tests": [{"id": "t", "name": "t", "request": {"path": "/"}, "expect": {}}]}))
    bad = tmp_path / "bad.diff"
    bad.write_text("--- a/../../x\n+++ b/../../x\n@@ -1 +1 @@\n-a\n+b\n")
    r = invoke("verify", str(app), "--tests", str(plan), "--patch", str(bad))
    assert r.exit_code == 1 and "patch was rejected" in r.output
    plan.write_text(json.dumps({"tests": [{"id": "t", "name": "t", "request": {"path": "http://169.254.169.254/"},
                                           "expect": {}}]}))
    r = invoke("verify", str(app), "--tests", str(plan))
    assert r.exit_code == 1 and "Invalid test plan" in r.output


def test_verify_has_no_token_option(routes_home):
    r = invoke("verify", "--help")
    assert "--private" in r.output and "--token" not in r.output
