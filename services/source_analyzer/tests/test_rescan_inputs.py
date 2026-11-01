"""Remediation rescans: exact revision capture and strict patch application."""

import io
import tarfile
import zipfile

import pytest

from source_analyzer import main
from source_analyzer.acquisition.archive import ArchiveError, extract_tar_gz

SHA = "0123456789abcdef0123456789abcdef01234567"
ROUTE = "export async function GET(request) {\n  return run(`SELECT ${q}`);\n}\n"
PATCH = ("--- a/app/route.js\n+++ b/app/route.js\n@@ -2 +2 @@\n-  return run(`SELECT ${q}`);\n"
         "+  return run(\"SELECT $1\", [q]);\n")


def github_tarball(path, comment=SHA):
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": comment}) as tf:
        data = ROUTE.encode()
        info = tarfile.TarInfo("acme-shop-0123456/app/route.js")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))


def test_github_archive_commit_is_captured(tmp_path):
    github_tarball(tmp_path / "repo.tar.gz")
    report = extract_tar_gz(tmp_path / "repo.tar.gz", tmp_path / "src")
    assert report.commit_sha == SHA
    github_tarball(tmp_path / "other.tar.gz", comment="not a sha")
    assert extract_tar_gz(tmp_path / "other.tar.gz", tmp_path / "src2").commit_sha is None


def _zip(path):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("app/route.js", ROUTE)
        z.writestr("package.json", "{}")


def test_rescan_applies_the_candidate_patch_strictly(tmp_path, monkeypatch):
    inp = tmp_path / "input"
    inp.mkdir()
    _zip(inp / "source.zip")
    (inp / "patch.diff").write_text(PATCH)
    monkeypatch.setattr(main, "PATCH_FILE", inp / "patch.diff")
    monkeypatch.setattr(main, "Path", lambda p: inp / "source.zip" if p == "/input/source.zip" else type(inp)(p))
    src, _notes, commit, patched = main.acquire("zip", tmp_path / "work")
    assert patched and commit is None
    assert "$1" in (src / "app/route.js").read_text()


def test_a_patch_that_does_not_apply_stops_the_rescan(tmp_path, monkeypatch):
    inp = tmp_path / "input"
    inp.mkdir()
    _zip(inp / "source.zip")
    (inp / "patch.diff").write_text(PATCH.replace("@@ -2 +2 @@", "@@ -1 +1 @@"))
    monkeypatch.setattr(main, "PATCH_FILE", inp / "patch.diff")
    monkeypatch.setattr(main, "Path", lambda p: inp / "source.zip" if p == "/input/source.zip" else type(inp)(p))
    with pytest.raises(ArchiveError, match="could not be applied"):
        main.acquire("zip", tmp_path / "work")
