"""CSRF protection: double-submit cookie + Origin verification.

The session cookie is SameSite=Lax and HttpOnly. In addition every unsafe
request must carry an ``X-CSRF-Token`` header equal to the readable
``routes_csrf`` cookie, and a present Origin header must be allow-listed.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.config import get_settings
from app.core.security import CSRF_COOKIE, CSRF_HEADER, tokens_match

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _reject(message: str) -> JSONResponse:
    return JSONResponse(status_code=403, content={"error": {"code": "csrf_failed", "message": message, "details": {}}})


class CsrfMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in SAFE_METHODS or not request.url.path.startswith("/api/"):
            return await call_next(request)
        origin = request.headers.get("origin")
        if origin and origin.rstrip("/") not in get_settings().origins:
            return _reject("Request origin is not allowed.")
        if not tokens_match(request.cookies.get(CSRF_COOKIE), request.headers.get(CSRF_HEADER)):
            return _reject("Missing or invalid CSRF token. Refresh the page and try again.")
        return await call_next(request)
