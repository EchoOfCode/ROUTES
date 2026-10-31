"""Source selection for an assessment: GitHub repository, ZIP file or local directory.

Local directories are packed into a temporary ZIP that is uploaded to the
engine like any other archive, so the analyzer sandbox applies the same
archive protections. The developer's files are only read, never modified.
"""

from __future__ import annotations

import os
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from routes_shared.github import is_github_url, parse_github_url
from routes_shared.sourcefiles import EXCLUDED_DIRS, SKIPPED_SUFFIXES
from routes_shared.uploads import MAX_UPLOAD_BYTES, ZIP_SIGNATURES

MAX_PACKED_FILES = 20_000
MAX_FILE_BYTES = 50 * 1024 * 1024


class SourceError(ValueError):
    """User-facing problem with the selected source."""


@dataclass(frozen=True)
class SourceSpec:
    kind: str                 # "github" | "zip" | "directory"
    label: str                # what to show the developer
    owner: str | None = None
    repo: str | None = None
    ref: str | None = None
    path: Path | None = None  # zip file or directory

    @property
    def is_github(self) -> bool:
        return self.kind == "github"


def classify(value: str, *, ref: str | None = None) -> SourceSpec:
    value = value.strip()
    if not value:
        raise SourceError("Give a GitHub repository URL, a .zip file or a project folder.")
    if is_github_url(value):
        owner, repo, parsed_ref = parse_github_url(value, ref)
        return SourceSpec("github", f"github.com/{owner}/{repo}" + (f"@{parsed_ref}" if parsed_ref else ""),
                          owner=owner, repo=repo, ref=parsed_ref)
    if value.lower().startswith(("http://", "https://", "git@", "ssh://")):
        raise SourceError("Only GitHub repositories (https://github.com/owner/repository) can be imported.")
    path = Path(value).expanduser()
    if not path.exists():
        raise SourceError(f"{value} does not exist.")
    path = path.resolve()
    if path.is_dir():
        return SourceSpec("directory", str(path), path=path)
    if path.is_file():
        if path.suffix.lower() != ".zip":
            raise SourceError("Only .zip archives can be analysed. For a folder, give the folder path.")
        size = path.stat().st_size
        if size > MAX_UPLOAD_BYTES:
            raise SourceError("ZIP archives are limited to 100 MB.")
        if size == 0:
            raise SourceError("The ZIP file is empty.")
        with path.open("rb") as fh:
            if not fh.read(4).startswith(ZIP_SIGNATURES):
                raise SourceError("The file is not a valid ZIP archive.")
        return SourceSpec("zip", path.name, path=path)
    raise SourceError(f"{value} is not a regular file or folder.")


@dataclass
class PackReport:
    files: int = 0
    bytes: int = 0
    skipped_excluded: int = 0
    skipped_links: int = 0
    skipped_large: int = 0


def pack_directory(root: Path, workdir: Path) -> tuple[Path, PackReport]:
    """Create ``<workdir>/<random>.zip`` from ``root``. Excluded folders (dependencies,
    build output, VCS data) and binary assets are left out; symbolic links and
    special files are never followed. Raises SourceError if the archive would
    exceed the upload limit."""
    root = Path(root).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="routes-pack-", suffix=".zip", dir=workdir)
    os.close(fd)
    target = Path(name)
    report = PackReport()
    try:
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                current = Path(dirpath)
                kept = []
                for d in dirnames:
                    full = current / d
                    if d in EXCLUDED_DIRS:
                        report.skipped_excluded += 1
                    elif full.is_symlink():
                        report.skipped_links += 1
                    else:
                        kept.append(d)
                dirnames[:] = sorted(kept)
                for fname in sorted(filenames):
                    full = current / fname
                    try:
                        st = full.lstat()
                    except OSError:
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        report.skipped_links += 1
                        continue
                    if fname.lower().endswith(SKIPPED_SUFFIXES):
                        report.skipped_excluded += 1
                        continue
                    if st.st_size > MAX_FILE_BYTES:
                        report.skipped_large += 1
                        continue
                    report.files += 1
                    report.bytes += st.st_size
                    if report.files > MAX_PACKED_FILES:
                        raise SourceError(f"The folder has more than {MAX_PACKED_FILES} files to analyse.")
                    zf.write(full, full.relative_to(root).as_posix())
                    if target.stat().st_size > MAX_UPLOAD_BYTES:
                        raise SourceError("The packed project is larger than 100 MB. Analyse a smaller folder.")
        if report.files == 0:
            raise SourceError("The folder does not contain any files ROUTES can analyse.")
        if target.stat().st_size > MAX_UPLOAD_BYTES:
            raise SourceError("The packed project is larger than 100 MB. Analyse a smaller folder.")
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return target, report
