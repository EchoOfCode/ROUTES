"""Private artifact store for remediation records.

Large or sensitive content (redacted source context, model prompts and
responses, testbenches, patches, sandbox logs) is kept out of database rows.
Each artifact is an immutable, content-addressed file:

    <ARTIFACTS_DIR>/<remediation id>/<kind>/<sha256>

and a ``remediation_artifacts`` row holding only metadata (kind, hash, size,
redaction status, expiry). Files are created 0600 in 0700 directories and
written atomically (temporary file + rename); writing the same content twice
returns the existing record.

Nothing is stored unredacted: before writing, every artifact is checked with
the independent post-redaction detector, and content that still contains a
secret-like value is refused, never silently stored.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import tempfile
import uuid
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from routes_shared.redaction import unredacted_secret_count

from app.core.config import get_settings
from app.models import Remediation, RemediationArtifact
from app.models.base import utcnow

log = logging.getLogger("routes.artifacts")

KINDS = frozenset({
    "context_snapshot", "model_input", "model_output", "plan", "testbench", "patch", "candidate",
    "sandbox_log", "test_evidence", "reanalysis", "report",
})
REDACTION_STATUSES = frozenset({"redacted", "derived", "none_needed"})
MAX_ARTIFACT_BYTES = 5 * 1024 * 1024


class ArtifactRejected(ValueError):
    """The content may not be stored (secret-like value, size, unknown kind)."""


class ArtifactMissing(LookupError):
    pass


def _root() -> Path:
    return Path(get_settings().artifacts_dir)


def _path_for(remediation_id: uuid.UUID, kind: str, sha: str) -> Path:
    return _root() / str(remediation_id) / kind / sha


def store(db: Session, remediation_id: uuid.UUID, kind: str, content: str | bytes, *,
          redaction_status: str, contains_source: bool, media_type: str = "text/plain") -> RemediationArtifact:
    """Write an artifact and add its metadata row to ``db`` (flushed, not
    committed: the caller's transaction decides)."""
    if kind not in KINDS:
        raise ArtifactRejected(f"unknown artifact kind {kind!r}")
    if redaction_status not in REDACTION_STATUSES:
        raise ArtifactRejected(f"unknown redaction status {redaction_status!r}")
    data = content.encode("utf-8") if isinstance(content, str) else bytes(content)
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ArtifactRejected("artifact larger than 5 MB")
    if unredacted_secret_count(data.decode("utf-8", "replace")):
        raise ArtifactRejected(f"{kind} artifact still contains a secret-like value; refusing to store it")
    sha = hashlib.sha256(data).hexdigest()

    existing = db.scalar(select(RemediationArtifact).where(
        RemediationArtifact.remediation_id == remediation_id, RemediationArtifact.kind == kind,
        RemediationArtifact.sha256 == sha))
    path = _path_for(remediation_id, kind, sha)
    if existing is not None and existing.deleted_at is None and path.is_file():
        return existing

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise

    retention = timedelta(days=get_settings().remediation_artifact_retention_days)
    if existing is not None:  # metadata survived but the file had been purged
        existing.deleted_at = None
        existing.expires_at = utcnow() + retention
        db.flush()
        return existing
    row = RemediationArtifact(
        remediation_id=remediation_id, kind=kind, sha256=sha, size_bytes=len(data), media_type=media_type,
        storage_key=f"{remediation_id}/{kind}/{sha}", redaction_status=redaction_status,
        contains_source=contains_source, expires_at=utcnow() + retention,
    )
    db.add(row)
    db.flush()
    return row


def read(artifact: RemediationArtifact) -> bytes:
    """Read an artifact's content, verifying its hash. Authorization is the
    caller's job (the API checks run ownership first)."""
    if artifact.deleted_at is not None:
        raise ArtifactMissing("the artifact has expired and was deleted")
    path = _root() / artifact.storage_key
    root = _root().resolve()
    if root not in path.resolve().parents:
        raise ArtifactMissing("invalid storage key")
    try:
        data = path.read_bytes()
    except FileNotFoundError as exc:
        raise ArtifactMissing("the artifact file is missing") from exc
    if hashlib.sha256(data).hexdigest() != artifact.sha256:
        raise ArtifactMissing("the artifact failed its integrity check")
    return data


def read_text(artifact: RemediationArtifact | None) -> str | None:
    if artifact is None:
        return None
    try:
        return read(artifact).decode("utf-8")
    except ArtifactMissing:
        return None


def purge_expired(db: Session) -> int:
    """Delete expired artifact files and mark their rows deleted, then remove
    directories of runs that no longer exist (deleted by retention)."""
    now = utcnow()
    expired = db.scalars(select(RemediationArtifact).where(
        RemediationArtifact.deleted_at.is_(None), RemediationArtifact.expires_at < now)).all()
    for artifact in expired:
        try:
            (_root() / artifact.storage_key).unlink(missing_ok=True)
        except OSError:
            log.warning("could not delete expired artifact %s", artifact.id)
            continue
    if expired:
        db.execute(update(RemediationArtifact).where(RemediationArtifact.id.in_([a.id for a in expired]))
                   .values(deleted_at=now))
    root = _root()
    removed_dirs = 0
    if root.is_dir():
        live = {str(i) for i in db.scalars(select(Remediation.id)).all()}
        for child in root.iterdir():
            if child.is_dir() and not child.is_symlink() and child.name not in live:
                try:
                    uuid.UUID(child.name)
                except ValueError:
                    continue
                # A run's first artifact can be written before its row is
                # committed elsewhere; only sweep directories idle for an hour.
                if now.timestamp() - child.stat().st_mtime < 3600:
                    continue
                shutil.rmtree(child, ignore_errors=True)
                removed_dirs += 1
    db.commit()
    return len(expired) + removed_dirs
