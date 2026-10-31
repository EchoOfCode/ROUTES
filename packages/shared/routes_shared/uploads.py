"""Staging of uploaded ZIP archives (shared by the API and the Sandbox Manager).

The stager only streams bytes to disk with a hard size cap and checks the ZIP
signature. The archive is never opened here: extraction and all archive
safety checks happen inside the disposable analyzer sandbox, which receives
the staged file through a read-only, per-upload volume subpath.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import uuid
from pathlib import Path

ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06")
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
CHUNK = 1024 * 1024


class UploadRejected(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def safe_filename(name: str | None) -> str:
    base = os.path.basename((name or "upload.zip").replace("\\", "/"))
    cleaned = "".join(ch for ch in base if ch.isalnum() or ch in "._- ")[:120].strip()
    return cleaned or "upload.zip"


class ZipStager:
    """Write one upload to ``<root>/<uuid>/source.zip``. Use as a context manager:
    any exception (including a rejected chunk) removes the partial upload."""

    def __init__(self, root: str | os.PathLike, *, max_bytes: int = MAX_UPLOAD_BYTES):
        self.root = Path(root)
        self.max_bytes = max_bytes
        self.upload_id = str(uuid.uuid4())
        self.directory = self.root / self.upload_id
        self.size = 0
        self._digest = hashlib.sha256()
        self._fh = None
        self._first = True

    def __enter__(self) -> "ZipStager":
        self.directory.mkdir(parents=True, mode=0o750)
        self._fh = (self.directory / "source.zip").open("xb")
        return self

    def write(self, chunk: bytes) -> None:
        if not chunk:
            return
        if self._first:
            if not chunk.startswith(ZIP_SIGNATURES):
                raise UploadRejected(400, "invalid_upload", "The file is not a valid ZIP archive.")
            self._first = False
        self.size += len(chunk)
        if self.size > self.max_bytes:
            raise UploadRejected(413, "upload_too_large", "ZIP uploads are limited to 100 MB.")
        self._digest.update(chunk)
        self._fh.write(chunk)

    @property
    def sha256(self) -> str:
        return self._digest.hexdigest()

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._fh is not None:
            self._fh.close()
        if exc_type is None and self.size == 0:
            self.discard()
            raise UploadRejected(400, "invalid_upload", "The uploaded file is empty.")
        if exc_type is not None:
            self.discard()
            return
        os.chmod(self.directory / "source.zip", 0o644)
        os.chmod(self.directory, 0o755)

    def discard(self) -> None:
        shutil.rmtree(self.directory, ignore_errors=True)


def discard_upload(root: str | os.PathLike, upload_id: str | None) -> None:
    if not upload_id:
        return
    try:
        uuid.UUID(upload_id)
    except ValueError:
        return
    shutil.rmtree(Path(root) / upload_id, ignore_errors=True)
