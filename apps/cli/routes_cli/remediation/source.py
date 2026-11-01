"""The source a remediation works on: where the code comes from, and the exact
region of each finding.

The CLI never stores source code, so the code is read again when a run starts:
from the local folder, from the ZIP file, or from GitHub at the commit the
assessment recorded (so the snapshot matches what was analysed). The same
source, pinned to the same revision, is what the engine builds and rescans.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import httpx
from routes_core.sources import SourceError, SourceSpec, classify, pack_directory
from routes_shared.remediation import Snapshot

FALLBACK_CONTEXT_LINES = 15
IMPORT_HEADER_LINES = 40
MAX_WHOLE_FILE_LINES = 400
MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024


class RemediationSourceError(ValueError):
    """The code for a finding cannot be read or rebuilt."""


@dataclass
class Region:
    snapshot: Snapshot
    exact: bool            # True: the analyzer's function boundaries; False: a window around the line


@dataclass
class RemediationSource:
    spec: SourceSpec                        # what the engine builds (pinned for GitHub)
    commit: str | None
    cache_dir: Path
    _files: dict[str, str] = field(default_factory=dict)
    _rescan_zip: Path | None = None

    @property
    def label(self) -> str:
        return self.spec.label + (f" @ {self.commit[:12]}" if self.commit and self.spec.is_github else "")

    # ------------------------------------------------------------ reading
    def read(self, rel: str) -> str:
        rel = _safe_rel(rel)
        if rel not in self._files:
            self._files[rel] = self._load(rel)
        return self._files[rel]

    def _load(self, rel: str) -> str:
        spec = self.spec
        if spec.kind == "directory":
            path = (spec.path / rel).resolve()
            if spec.path.resolve() not in path.parents or not path.is_file():
                raise RemediationSourceError(f"{rel} was not found in {spec.label}.")
            if path.stat().st_size > MAX_SOURCE_FILE_BYTES:
                raise RemediationSourceError(f"{rel} is too large to remediate.")
            return path.read_bytes().decode("utf-8", errors="replace")
        if spec.kind == "zip":
            with zipfile.ZipFile(spec.path) as zf:
                names = [n for n in zf.namelist() if not n.endswith("/")]
                match = [n for n in names if n == rel] or [n for n in names if n.endswith("/" + rel)]
                if len(match) != 1:
                    raise RemediationSourceError(f"{rel} was not found in {spec.label}.")
                info = zf.getinfo(match[0])
                if info.file_size > MAX_SOURCE_FILE_BYTES:
                    raise RemediationSourceError(f"{rel} is too large to remediate.")
                return zf.read(info).decode("utf-8", errors="replace")
        if spec.is_github:
            ref = self.commit or spec.ref or "HEAD"
            url = f"https://raw.githubusercontent.com/{spec.owner}/{spec.repo}/{ref}/{rel}"
            try:
                r = httpx.get(url, timeout=20.0, follow_redirects=False)
            except httpx.HTTPError as exc:
                raise RemediationSourceError(f"Could not download {rel} from GitHub: {exc}") from exc
            if r.status_code != 200:
                raise RemediationSourceError(f"Could not download {rel} from GitHub (HTTP {r.status_code}). Private "
                                             "repositories: run `routes remediate --source <local clone>`.")
            return r.text
        raise RemediationSourceError("Unsupported source.")

    def region(self, finding) -> Region:
        if not finding.file:
            raise RemediationSourceError("The finding does not point at a file.")
        content = self.read(finding.file)
        lines = content.replace("\r\n", "\n").split("\n")
        if lines and lines[-1] == "":
            lines = lines[:-1]
        if not finding.line:
            # A file-level finding (e.g. missing security headers in next.config): the whole file.
            if not lines or len(lines) > MAX_WHOLE_FILE_LINES:
                raise RemediationSourceError(f"{finding.file} is too large to remediate as a whole file.")
            return Region(Snapshot(file=finding.file, start_line=1, end_line=len(lines), code="\n".join(lines)),
                          True)
        stored = (finding.technical_details or {}).get("remediation_region") or {}
        start, end = stored.get("start_line"), stored.get("end_line")
        exact = isinstance(start, int) and isinstance(end, int) and 1 <= start <= finding.line <= end <= len(lines)
        if not exact:
            start = max(1, finding.line - FALLBACK_CONTEXT_LINES)
            end = min(len(lines), finding.line + FALLBACK_CONTEXT_LINES)
        if finding.line > len(lines):
            raise RemediationSourceError(f"{finding.file} has only {len(lines)} lines; the source has changed since "
                                         "the assessment. Run the analysis again.")
        if 1 < start <= IMPORT_HEADER_LINES:
            # Include the import block so a fix may import an existing helper (e.g. the auth session).
            start = 1
        return Region(Snapshot(file=finding.file, start_line=start, end_line=end,
                               code="\n".join(lines[start - 1:end])), exact)

    # ------------------------------------------------------------ engine
    def rescan_spec(self) -> SourceSpec:
        """The engine's ``source`` run takes GitHub or an uploaded ZIP; a folder is
        packed once (read only) and reused for every rescan of this run."""
        if self.spec.kind != "directory":
            return self.spec
        if self._rescan_zip is None:
            self._rescan_zip, _ = pack_directory(self.spec.path, self.cache_dir)
        return SourceSpec("zip", self.spec.label, path=self._rescan_zip)

    def close(self) -> None:
        if self._rescan_zip is not None:
            self._rescan_zip.unlink(missing_ok=True)
            self._rescan_zip = None


def _safe_rel(rel: str) -> str:
    p = PurePosixPath(rel.replace("\\", "/"))
    if p.is_absolute() or ".." in p.parts or not p.parts:
        raise RemediationSourceError(f"Unsafe path in finding: {rel}")
    return str(p)


def resolve(assessment, *, override: str | None, cache_dir: Path) -> RemediationSource:
    """The source of `assessment` (or `override`), pinned to the analysed commit."""
    project = assessment.project
    commit = (assessment.summary or {}).get("source_commit")
    try:
        if override:
            spec = classify(override)
        elif project.source_kind and project.source_location:
            if project.source_private:
                raise RemediationSourceError(
                    "This project's repository is private. Remediate from a local clone: "
                    "`routes remediate --source <folder>`.")
            spec = classify(project.source_location, ref=project.source_ref)
        else:
            raise RemediationSourceError("The assessment has no source. Run `routes analyze <source>` first, or "
                                         "give it with --source.")
    except SourceError as exc:
        raise RemediationSourceError(f"The source cannot be used: {exc}") from exc
    if spec.is_github:
        if commit:
            spec = SourceSpec("github", spec.label, owner=spec.owner, repo=spec.repo, ref=commit)
    else:
        commit = None   # only GitHub revisions are recorded; a folder is used as it is now
    return RemediationSource(spec=spec, commit=commit, cache_dir=cache_dir)
