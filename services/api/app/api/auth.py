from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.core.deps import get_current_session, get_current_user
from app.core.ratelimit import enforce_rate_limit
from app.core.redis import get_redis
from app.core.security import new_token
from app.models import User, UserSession
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    RegisterRequest,
    SessionOut,
    UpdateProfileRequest,
    UserOut,
)
from app.services import auth as auth_service

router = APIRouter(prefix="/auth", tags=["auth"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.get("/csrf")
def csrf(response: Response, request: Request) -> dict:
    token = request.cookies.get("routes_csrf") or new_token()
    auth_service.set_csrf_cookie(response, token)
    return {"csrf_token": token}


@router.post("/register", response_model=UserOut, status_code=201)
def register(body: RegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    enforce_rate_limit(get_redis(), "register", _client_ip(request), 20, 3600)
    user = auth_service.register_user(db, body.email, body.password, body.display_name)
    token = auth_service.create_session(db, user, request.headers.get("user-agent", ""))
    auth_service.set_session_cookie(response, token)
    return user


@router.post("/login", response_model=UserOut)
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    limit = get_settings().login_rate_limit
    enforce_rate_limit(get_redis(), "login-ip", _client_ip(request), limit * 3, 900)
    enforce_rate_limit(get_redis(), "login-email", body.email.lower(), limit, 900)
    user = auth_service.authenticate(db, body.email, body.password)
    token = auth_service.create_session(db, user, request.headers.get("user-agent", ""))
    auth_service.set_session_cookie(response, token)
    return user


@router.post("/logout", status_code=204)
def logout(
    response: Response, session: UserSession = Depends(get_current_session), db: Session = Depends(get_db)
):
    db.execute(delete(UserSession).where(UserSession.id == session.id))
    db.commit()
    auth_service.clear_auth_cookies(response)
    response.status_code = 204
    return response


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@router.patch("/me", response_model=UserOut)
def update_me(body: UpdateProfileRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user.display_name = " ".join(body.display_name.split())
    db.commit()
    return user


@router.post("/change-password", status_code=204)
def change_password(
    body: ChangePasswordRequest,
    response: Response,
    user: User = Depends(get_current_user),
    session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db),
):
    auth_service.change_password(db, user, body.current_password, body.new_password, session.id)
    response.status_code = 204
    return response


@router.get("/sessions", response_model=list[SessionOut])
def sessions(session: UserSession = Depends(get_current_session), db: Session = Depends(get_db)):
    rows = db.scalars(
        select(UserSession).where(UserSession.user_id == session.user_id).order_by(UserSession.last_seen_at.desc())
    ).all()
    return [
        SessionOut(id=s.id, created_at=s.created_at, last_seen_at=s.last_seen_at, user_agent=s.user_agent,
                   current=s.id == session.id)
        for s in rows
    ]


@router.post("/sessions/revoke-others", status_code=204)
def revoke_others(response: Response, session: UserSession = Depends(get_current_session), db: Session = Depends(get_db)):
    db.execute(delete(UserSession).where(UserSession.user_id == session.user_id, UserSession.id != session.id))
    db.commit()
    response.status_code = 204
    return response
