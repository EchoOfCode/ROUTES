from datetime import UTC, datetime, timedelta

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.errors import ApiError
from app.core.security import SESSION_COOKIE, hash_token
from app.models import User, UserSession

_TOUCH_INTERVAL = timedelta(minutes=5)


def get_current_session(request: Request, db: Session = Depends(get_db)) -> UserSession:
    token = request.cookies.get(SESSION_COOKIE)
    if not token or len(token) > 200:
        raise ApiError(401, "unauthenticated", "Sign in to continue.")
    now = datetime.now(UTC)
    session = db.scalar(select(UserSession).where(UserSession.token_hash == hash_token(token)))
    if session is None or session.expires_at <= now:
        raise ApiError(401, "unauthenticated", "Your session has expired. Sign in again.")
    if now - session.last_seen_at > _TOUCH_INTERVAL:
        session.last_seen_at = now
        db.commit()
    return session


def get_current_user(
    session: UserSession = Depends(get_current_session), db: Session = Depends(get_db)
) -> User:
    user = db.get(User, session.user_id)
    if user is None:
        raise ApiError(401, "unauthenticated", "Sign in to continue.")
    return user
