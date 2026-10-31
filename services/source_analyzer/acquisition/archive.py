"""Safe extraction of untrusted ZIP and tar.gz archives.

Protections: format validation, member-count and total/per-file size caps
(checked against declared *and* actual bytes, so lying headers don't help),
compression-ratio guard against ZIP bombs, rejection of absolute paths,
drive letters, ``..`` traversal and NUL bytes, symlinks/hardlinks/devices
skipped, and excluded directories never written. Files are written with
0600 permissions into a tmpfs workspace that is mounted ``noexec``.
"""

from __future__ import annotations

import os
import stat
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

MAX_MEMBERS = 20_000
MAX_TOTAL_BYTES = 500 * 1024 * 1024
MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_RATIO = 200  # uncompressed/compressed, per member
MAX_PATH_DEPTH = 40
CHUNK = 1024 * 1024

from routes_shared.sourcefiles import EXCLUDED_DIRS, SKIPPED_SUFFIXES  # noqa: E402,F401


class ArchiveError(Exception):
    """Raised for malformed or suspicious archives. Message is user-facing."""


@dataclass
class ExtractionReport:
    files_written: int = 0
    bytes_written: int = 0
    skipped_links: int = 0
    skipped_excluded: int = 0
    skipped_binary: int = 0
    root_prefix_stripped: str | None = None
    warnings: list[str] = field(default_factory=list)


def safe_member_path(name: str) -> PurePosixPath | None:
    """Return a safe relative path, or None if the member must be rejected."""
    if not name or "\x00" in name:
        return None
    name = name.replace("\\", "/")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        return None
    parts = [p for p in PurePosixPath(name).parts if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts) or len(parts) > MAX_PATH_DEPTH:
        return None
    return PurePosixPath(*parts)


def _excluded(path: PurePosixPath, excluded_dirs=EXCLUDED_DIRS) -> bool:
    return any(part in excluded_dirs for part in path.parts[:-1])


def _write(target_root: Path, rel: PurePosixPath, source, declared: int, report: ExtractionReport, budget: list[int],
           *, executable: bool = False) -> None:
    dest = (target_root / rel).resolve()
    root = target_root.resolve()
    if root not in dest.parents:
        raise ArchiveError("The archive contains a path that escapes the extraction directory.")
    dest.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    # Owner-only permissions; the executable bit is the only mode bit ever kept
    # (never setuid/setgid/sticky), and only when the caller asks for it.
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o700 if executable else 0o600)
    with os.fdopen(fd, "wb") as out:
        while chunk := source.read(CHUNK):
            written += len(chunk)
            budget[0] += len(chunk)
            if written > MAX_FILE_BYTES:
                raise ArchiveError(f"A file in the archive is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB.")
            if budget[0] > MAX_TOTAL_BYTES:
                raise ArchiveError("The archive expands beyond the 500 MB extraction limit.")
            if declared and written > declared:
                raise ArchiveError("The archive's size information is inconsistent.")
            out.write(chunk)
    report.files_written += 1
    report.bytes_written += written


def extract_zip(archive: Path, target: Path, *, skip_suffixes: tuple[str, ...] = SKIPPED_SUFFIXES,
                excluded_dirs=EXCLUDED_DIRS, keep_exec: bool = False) -> ExtractionReport:
    report = ExtractionReport()
    if not zipfile.is_zipfile(archive):
        raise ArchiveError("The upload is not a valid ZIP archive.")
    try:
        zf = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ArchiveError("The ZIP archive is malformed.") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            raise ArchiveError(f"The archive contains more than {MAX_MEMBERS} entries.")
        if sum(i.file_size for i in infos) > MAX_TOTAL_BYTES:
            raise ArchiveError("The archive expands beyond the 500 MB extraction limit.")
        if any(i.flag_bits & 0x1 for i in infos):
            raise ArchiveError("Encrypted archives are not supported.")
        names = set()
        budget = [0]
        for info in infos:
            rel = safe_member_path(info.filename)
            if rel is None:
                raise ArchiveError("The archive contains an unsafe file path.")
            key = str(rel).lower()
            if key in names:
                raise ArchiveError("The archive contains duplicate entries.")
            names.add(key)
            mode = (info.external_attr >> 16) & 0xFFFF
            if info.is_dir():
                continue
            file_type = stat.S_IFMT(mode)
            # Many tools store no type bits at all (treated as regular files);
            # anything explicitly typed as non-regular (symlink, device...) is skipped.
            if file_type and file_type != stat.S_IFREG:
                report.skipped_links += 1
                continue
            if _excluded(rel, excluded_dirs):
                report.skipped_excluded += 1
                continue
            if rel.name.lower().endswith(skip_suffixes):
                report.skipped_binary += 1
                continue
            if info.compress_size and info.file_size / max(info.compress_size, 1) > MAX_RATIO and info.file_size > 1024 * 1024:
                raise ArchiveError("The archive looks like a compression bomb and was rejected.")
            try:
                with zf.open(info) as src:
                    _write(target, rel, src, info.file_size, report, budget,
                           executable=keep_exec and bool(mode & 0o100) and file_type == stat.S_IFREG)
            except (zipfile.BadZipFile, EOFError, OSError) as exc:
                if isinstance(exc, ArchiveError):
                    raise
                raise ArchiveError("The ZIP archive is corrupt.") from exc
    _strip_single_root(target, report)
    return report


def extract_tar_gz(archive: Path, target: Path, *, skip_suffixes: tuple[str, ...] = SKIPPED_SUFFIXES,
                   excluded_dirs=EXCLUDED_DIRS, keep_exec: bool = False) -> ExtractionReport:
    """GitHub tarballs (``owner-repo-sha/`` prefix) with the same protections."""
    report = ExtractionReport()
    budget = [0]
    count = 0
    try:
        with tarfile.open(archive, mode="r:gz") as tf:
            for member in tf:
                count += 1
                if count > MAX_MEMBERS:
                    raise ArchiveError(f"The repository contains more than {MAX_MEMBERS} entries.")
                rel = safe_member_path(member.name)
                if rel is None:
                    raise ArchiveError("The repository archive contains an unsafe path.")
                if member.isdir() or member.type == tarfile.XGLTYPE or member.type == tarfile.XHDTYPE:
                    continue
                if member.issym() or member.islnk() or not member.isreg():
                    report.skipped_links += 1
                    continue
                if member.size > MAX_FILE_BYTES:
                    report.skipped_binary += 1
                    continue
                if _excluded(rel, excluded_dirs):
                    report.skipped_excluded += 1
                    continue
                if rel.name.lower().endswith(skip_suffixes):
                    report.skipped_binary += 1
                    continue
                src = tf.extractfile(member)
                if src is None:
                    continue
                with src:
                    _write(target, rel, src, member.size, report, budget,
                           executable=keep_exec and bool(member.mode & 0o100))
    except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
        if isinstance(exc, ArchiveError):
            raise
        raise ArchiveError("The repository archive is corrupt or was truncated.") from exc
    _strip_single_root(target, report)
    return report


def _strip_single_root(target: Path, report: ExtractionReport) -> None:
    """Archives often wrap everything in one top-level folder; analyse its contents."""
    entries = [p for p in target.iterdir()]
    if len(entries) == 1 and entries[0].is_dir() and not entries[0].is_symlink():
        report.root_prefix_stripped = entries[0].name
        inner = entries[0]
        for child in inner.iterdir():
            child.rename(target / child.name)
        inner.rmdir()
