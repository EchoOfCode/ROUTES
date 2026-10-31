"""Staging of uploaded ZIP archives.

The API only streams the upload to disk with a hard size cap and checks the
ZIP signature. The archive is never opened here: extraction and all archive
safety checks happen inside the disposable analyzer sandbox, which receives
the staged file through a read-only, per-upload volume subpath.
"""

import hashlib
import os
import shutil
import uuid
from pathlib import Path

from fastapi import UploadFile

from app.core.config import get_settings
from app.core.errors import ApiError

ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06")
CHUNK = 1024 * 1024


def _safe_filename(name: str | None) -> str:
    base = os.path.basename((name or "upload.zip").replace("\\", "/"))
    cleaned = "".join(ch for ch in base if ch.isalnum() or ch in "._- ")[:120].strip()
    return cleaned or "upload.zip"


async def stage_zip(upload: UploadFile) -> tuple[str, str, int, str]:
    """Returns (upload_id, display filename, size, sha256)."""
    settings = get_settings()
    filename = _safe_filename(upload.filename)
    if not filename.lower().endswith(".zip"):
        raise ApiError(400, "invalid_upload", "Upload a .zip archive.")
    upload_id = str(uuid.uuid4())
    directory = Path(settings.uploads_dir) / upload_id
    directory.mkdir(parents=True, mode=0o750)
    target = directory / "source.zip"
    digest = hashlib.sha256()
    size = 0
    try:
        with target.open("xb") as fh:
            first = True
            while chunk := await upload.read(CHUNK):
                if first:
                    if not chunk.startswith(ZIP_SIGNATURES):
                        raise ApiError(400, "invalid_upload", "The file is not a valid ZIP archive.")
                    first = False
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise ApiError(413, "upload_too_large", "ZIP uploads are limited to 100 MB.")
                digest.update(chunk)
                fh.write(chunk)
        if size == 0:
            raise ApiError(400, "invalid_upload", "The uploaded file is empty.")
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    os.chmod(target, 0o644)
    os.chmod(directory, 0o755)
    return upload_id, filename, size, digest.hexdigest()


def discard_upload(upload_id: str | None) -> None:
    if not upload_id:
        return
    try:
        uuid.UUID(upload_id)
    except ValueError:
        return
    shutil.rmtree(Path(get_settings().uploads_dir) / upload_id, ignore_errors=True)
