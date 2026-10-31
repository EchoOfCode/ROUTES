from datetime import UTC, datetime, timedelta

from fastapi import Response
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.security import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    hash_password,
    hash_token,
    needs_rehash,
    new_token,
    verify_password,
)
from app.models import User, UserSession


def register_user(db: Session, email: str, password: str, display_name: str) -> User:
    email = email.strip().lower()
    if db.scalar(select(User.id).where(func.lower(User.email) == email)):
        raise ApiError(409, "email_taken", "An account with this email already exists.")
    user = User(email=email, password_hash=hash_password(password), display_name=display_name)
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ApiError(409, "email_taken", "An account with this email already exists.") from exc
    return user


def authenticate(db: Session, email: str, password: str) -> User:
    user = db.scalar(select(User).where(func.lower(User.email) == email.strip().lower()))
    if not verify_password(user.password_hash if user else None, password) or user is None:
        raise ApiError(401, "invalid_credentials", "The email or password is incorrect.")
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        db.commit()
    return user


def create_session(db: Session, user: User, user_agent: str) -> str:
    token = new_token()
    now = datetime.now(UTC)
    db.add(
        UserSession(
            user_id=user.id,
            token_hash=hash_token(token),
            expires_at=now + timedelta(hours=get_settings().session_ttl_hours),
            user_agent=(user_agent or "")[:300],
        )
    )
    # Opportunistic cleanup of this user's expired sessions.
    db.execute(delete(UserSession).where(UserSession.user_id == user.id, UserSession.expires_at <= now))
    db.commit()
    return token


def set_session_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )


def set_csrf_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    # Readable by the frontend on purpose (double-submit pattern).
    response.set_cookie(
        CSRF_COOKIE, token, max_age=settings.session_ttl_hours * 3600, httponly=False,
        secure=settings.cookie_secure, samesite="strict", path="/",
    )


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


def change_password(db: Session, user: User, current: str, new: str, keep_session_id) -> None:
    if not verify_password(user.password_hash, current):
        raise ApiError(400, "invalid_password", "The current password is incorrect.")
    user.password_hash = hash_password(new)
    # Changing a password signs out every other session.
    db.execute(delete(UserSession).where(UserSession.user_id == user.id, UserSession.id != keep_session_id))
    db.commit()
