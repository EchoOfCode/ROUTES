"""Staging of uploaded ZIP archives (see ``routes_shared.uploads``)."""

from fastapi import UploadFile

from routes_shared.uploads import CHUNK, UploadRejected, ZipStager, safe_filename
from routes_shared.uploads import discard_upload as _discard

from app.core.config import get_settings
from app.core.errors import ApiError


async def stage_zip(upload: UploadFile) -> tuple[str, str, int, str]:
    """Returns (upload_id, display filename, size, sha256)."""
    settings = get_settings()
    filename = safe_filename(upload.filename)
    if not filename.lower().endswith(".zip"):
        raise ApiError(400, "invalid_upload", "Upload a .zip archive.")
    try:
        with ZipStager(settings.uploads_dir, max_bytes=settings.max_upload_bytes) as stager:
            while chunk := await upload.read(CHUNK):
                stager.write(chunk)
    except UploadRejected as exc:
        raise ApiError(exc.status, exc.code, exc.message) from exc
    return stager.upload_id, filename, stager.size, stager.sha256


def discard_upload(upload_id: str | None) -> None:
    _discard(get_settings().uploads_dir, upload_id)
