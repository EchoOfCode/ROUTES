import json
import zipfile
from pathlib import Path

import httpx
import pytest

from routes_core.buildrun import BuildRunInvalid, BuildRunRequest, submit
from routes_core.engine import EngineClient
from routes_core.sources import classify

PLAN = {"tests": [{"id": "t", "name": "t", "request": {"path": "/"}, "expect": {"status": [200]}}]}


def engine(record):
    def handler(request: httpx.Request):
        record.append((request.method, request.url.path, request.content))
        if request.url.path == "/uploads":
            return httpx.Response(201, json={"upload_id": "0f8fad5b-d9cb-469f-a165-70867728950e"})
        if request.url.path == "/credentials":
            return httpx.Response(201, json={"handle": "h1"})
        return httpx.Response(201, json={"id": "run1", "kind": "build_run", "status": "pending"})
    return EngineClient("http://engine", "t" * 32, transport=httpx.MockTransport(handler))


def make_app(root: Path) -> Path:
    (root / "app").mkdir(parents=True)
    (root / "app" / "page.js").write_text("export default () => null")
    (root / "public").mkdir()
    (root / "public" / "logo.png").write_bytes(b"\x89PNG")
    (root / "node_modules" / "x").mkdir(parents=True)
    (root / "node_modules" / "x" / "index.js").write_text("")
    (root / "native.node").write_bytes(b"\x7fELF")
    return root


def test_folder_is_packed_for_building_and_left_untouched(tmp_path):
    src = make_app(tmp_path / "src")
    before = sorted(p.relative_to(src).as_posix() for p in src.rglob("*"))
    record = []
    uploaded = {}

    client = engine(record)
    real = client.upload_zip

    def capture(path):
        with zipfile.ZipFile(path) as zf:
            uploaded["names"] = sorted(zf.namelist())
        return real(path)

    client.upload_zip = capture
    run = submit(client, BuildRunRequest(source=classify(str(src)), test_plan=PLAN, patch=None), cache_dir=tmp_path / "c")
    assert run["id"] == "run1"
    assert uploaded["names"] == ["app/page.js", "public/logo.png"]          # assets kept, deps/native modules not
    assert sorted(p.relative_to(src).as_posix() for p in src.rglob("*")) == before
    assert list((tmp_path / "c").iterdir()) == []                              # temporary archive deleted
    spec = json.loads(record[-1][2])
    assert spec["kind"] == "build_run" and spec["source"] == "zip" and spec["test_plan"]["tests"][0]["id"] == "t"


def test_private_github_token_goes_only_to_the_credential_endpoint(tmp_path):
    record = []
    token = "github_pat_" + "B" * 60
    req = BuildRunRequest(source=classify("https://github.com/acme/app"), test_plan=PLAN, token=token)
    submit(engine(record), req, cache_dir=tmp_path)
    assert [r[1] for r in record] == ["/credentials", "/runs"]
    assert token.encode() not in record[1][2] and json.loads(record[1][2])["credential_handle"] == "h1"
    assert req.token is None


@pytest.mark.parametrize("kw", [{"patch": "--- a/../x\n+++ b/../x\n@@ -1 +1 @@\n-a\n+b\n"},
                                {"test_plan": {"tests": [{"id": "t", "name": "t", "request": {"path": "http://x/"},
                                                          "expect": {}}]}}])
def test_invalid_requests_are_rejected_before_contacting_the_engine(tmp_path, kw):
    record = []
    req = BuildRunRequest(source=classify("https://github.com/acme/app"), test_plan=kw.get("test_plan", PLAN),
                          patch=kw.get("patch"))
    with pytest.raises(BuildRunInvalid):
        submit(engine(record), req, cache_dir=tmp_path)
    assert record == []
