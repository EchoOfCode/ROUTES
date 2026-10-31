import io

import pytest

from routes_shared import events, github
from routes_shared.uploads import UploadRejected, ZipStager


def test_emit_and_parse_round_trip_with_whitelisted_data():
    buf = io.StringIO()
    events.emit("discovering_pages", "3 of 25", stream=buf, pages_done=3, page_limit=25, bogus=7)
    events.emit("x" * 100, "m" * 500, stream=buf)
    parsed = events.parse_events(buf.getvalue())
    assert parsed[0] == {"stage": "discovering_pages", "message": "3 of 25", "data": {"pages_done": 3, "page_limit": 25}}
    assert len(parsed[1]["stage"]) == 64 and len(parsed[1]["message"]) == 300 and "data" not in parsed[1]


def test_clean_data_rejects_non_integers():
    assert events.clean_data({"pages_done": True, "files": 1.5, "routes": -1, "static_matches": 2}) == {"static_matches": 2}
    assert events.clean_data("nope") == {}


def test_zip_stager(tmp_path):
    with ZipStager(tmp_path) as s:
        s.write(b"PK\x03\x04abc")
    assert (tmp_path / s.upload_id / "source.zip").read_bytes() == b"PK\x03\x04abc" and s.size == 7
    with pytest.raises(UploadRejected):
        with ZipStager(tmp_path) as bad:
            bad.write(b"not a zip")
    assert not (tmp_path / bad.upload_id).exists()
    with pytest.raises(UploadRejected) as exc:
        with ZipStager(tmp_path, max_bytes=8) as big:
            big.write(b"PK\x03\x04")
            big.write(b"12345")
    assert exc.value.status == 413 and not (tmp_path / big.upload_id).exists()
    with pytest.raises(UploadRejected):
        with ZipStager(tmp_path) as empty:
            pass
    assert not (tmp_path / empty.upload_id).exists()


def test_github_parsing():
    assert github.parse_github_url("https://github.com/acme/app.git") == ("acme", "app", None)
    assert github.parse_github_url("github.com/acme/app/tree/feature/x") == ("acme", "app", "feature/x")
    assert github.parse_github_url("https://github.com/acme/app", "v1.2") == ("acme", "app", "v1.2")
    for bad in ("https://gitlab.com/a/b", "https://github.com/acme"):
        with pytest.raises(ValueError):
            github.parse_github_url(bad)
    with pytest.raises(ValueError):
        github.validate_ref("../etc")
    with pytest.raises(ValueError):
        github.validate_github_token("short")
    assert github.validate_github_token("  github_pat_" + "A" * 30 + "  ") == "github_pat_" + "A" * 30
