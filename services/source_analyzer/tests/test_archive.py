import io
import stat
import tarfile
import zipfile

import pytest

from source_analyzer.acquisition import archive
from source_analyzer.acquisition.archive import ArchiveError, extract_tar_gz, extract_zip, safe_member_path


def make_zip(tmp_path, entries, name="a.zip"):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry in entries:
            if isinstance(entry, zipfile.ZipInfo):
                zf.writestr(entry, b"target")
            else:
                zf.writestr(entry[0], entry[1])
    return path


@pytest.mark.parametrize("name", ["../evil.js", "a/../../evil", "/etc/passwd", "C:\\win.ini", "a\x00b", "..\\..\\x"])
def test_unsafe_member_paths(name):
    assert safe_member_path(name) is None


def test_extracts_and_strips_single_root(tmp_path):
    z = make_zip(tmp_path, [("project/package.json", "{}"), ("project/app/page.tsx", "x")])
    out = tmp_path / "out"
    out.mkdir()
    report = extract_zip(z, out)
    assert (out / "package.json").exists() and (out / "app" / "page.tsx").exists()
    assert report.root_prefix_stripped == "project"
    assert stat.S_IMODE((out / "package.json").stat().st_mode) == 0o600


def test_rejects_traversal(tmp_path):
    z = make_zip(tmp_path, [("ok.js", "1"), ("../../escape.js", "2")])
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(ArchiveError):
        extract_zip(z, out)
    assert not (tmp_path / "escape.js").exists()


def test_skips_symlinks(tmp_path):
    link = zipfile.ZipInfo("link")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    z = make_zip(tmp_path, [("a.js", "1"), link])
    out = tmp_path / "out"
    out.mkdir()
    report = extract_zip(z, out)
    assert report.skipped_links == 1 and not (out / "link").exists()


def test_excludes_dependency_and_build_dirs_but_keeps_lockfiles(tmp_path):
    z = make_zip(tmp_path, [("node_modules/x/index.js", "1"), (".git/config", "1"), (".next/server.js", "1"),
                            ("package-lock.json", "{}"), ("src/a.ts", "1")])
    out = tmp_path / "out"
    out.mkdir()
    report = extract_zip(z, out)
    assert report.skipped_excluded == 3
    assert (out / "package-lock.json").exists() and not (out / "node_modules").exists()


def test_zip_bomb_rejected(tmp_path):
    z = make_zip(tmp_path, [("bomb.txt", "0" * (20 * 1024 * 1024))])
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(ArchiveError, match="bomb"):
        extract_zip(z, out)


def test_total_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, "MAX_TOTAL_BYTES", 1000)
    z = make_zip(tmp_path, [("a.txt", "x" * 600), ("b.txt", "y" * 600)])
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(ArchiveError, match="500 MB|limit"):
        extract_zip(z, out)


def test_file_count_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, "MAX_MEMBERS", 5)
    z = make_zip(tmp_path, [(f"f{i}.js", "1") for i in range(6)])
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(ArchiveError, match="entries"):
        extract_zip(z, out)


def test_lying_size_header_detected(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, "MAX_FILE_BYTES", 100)
    z = make_zip(tmp_path, [("big.js", "x" * 500)])
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(ArchiveError):
        extract_zip(z, out)


def test_duplicate_and_malformed(tmp_path):
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"PK\x03\x04garbage")
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(ArchiveError):
        extract_zip(bad, out)
    dup = tmp_path / "dup.zip"
    with zipfile.ZipFile(dup, "w") as zf:
        zf.writestr("a.js", "1")
        zf.writestr("A.js", "2")
    with pytest.raises(ArchiveError, match="duplicate"):
        extract_zip(dup, out)


def _tar(tmp_path, members):
    path = tmp_path / "repo.tar.gz"
    with tarfile.open(path, "w:gz") as tf:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "sym":
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return path


def test_tarball_symlink_skipped_and_root_stripped(tmp_path):
    t = _tar(tmp_path, [("acme-app-abc123/package.json", b"{}", "file"), ("acme-app-abc123/passwd", b"", "sym")])
    out = tmp_path / "out"
    out.mkdir()
    report = extract_tar_gz(t, out)
    assert (out / "package.json").exists() and not (out / "passwd").exists()
    assert report.skipped_links == 1


def test_tarball_traversal_and_truncation(tmp_path):
    t = _tar(tmp_path, [("../../evil", b"x", "file")])
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(ArchiveError):
        extract_tar_gz(t, out)
    good = _tar(tmp_path, [("r/a.js", b"x" * 100_000, "file")])
    data = good.read_bytes()
    truncated = tmp_path / "trunc.tar.gz"
    truncated.write_bytes(data[: len(data) // 2])
    out2 = tmp_path / "out2"
    out2.mkdir()
    with pytest.raises(ArchiveError, match="truncated|corrupt"):
        extract_tar_gz(truncated, out2)
