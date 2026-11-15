import os
import secrets
from datetime import datetime, timedelta, timezone
from hashlib import sha256

from fastapi import HTTPException
from sqlalchemy import delete, select

from backend.api.database.models import AppSession, User
from backend.core.scan_index import utc


COOKIE = "s3cure_session"
SESSION_LIFETIME = timedelta(minutes=30)
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def allowed_origins():
    default = "http://127.0.0.1:5173,http://localhost:5173"
    return [origin.strip().rstrip("/") for origin in os.getenv("S3CURE_ORIGINS", default).split(",")
            if origin.strip() and origin.strip() != "*"]


def session_digest(token):
    return sha256(token.encode("utf-8")).hexdigest()


def require_trusted_origin(request):
    origin = request.headers.get("origin")
    if origin and origin not in allowed_origins():
        raise HTTPException(status_code=403, detail="Untrusted request origin.")


def create_session(db, request, response, user):
    now = datetime.now(timezone.utc)
    token = secrets.token_urlsafe(32)
    session = AppSession(digest=session_digest(token), user_id=user.id,
                         csrf_token=secrets.token_urlsafe(32), expires_at=now + SESSION_LIFETIME)
    previous = request.cookies.get(COOKIE)
    db.execute(delete(AppSession).where(AppSession.expires_at <= now))
    if previous:
        db.execute(delete(AppSession).where(AppSession.digest == session_digest(previous)))
    db.add(session)
    db.commit()
    secure = request.url.scheme == "https" or request.url.hostname not in {"127.0.0.1", "localhost", "::1"}
    secure = secure or os.getenv("S3CURE_SECURE_COOKIES", "").lower() in {"true", "1"}
    response.set_cookie(COOKIE, token, max_age=int(SESSION_LIFETIME.total_seconds()),
                        httponly=True, secure=secure, samesite="strict", path="/api")
    return session


def resolve_session(db, request):
    token = request.cookies.get(COOKIE)
    if not token or len(token) != 43:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    row = db.execute(
        select(AppSession, User).join(User, User.id == AppSession.user_id)
        .where(AppSession.digest == session_digest(token))
    ).one_or_none()
    if row is None or utc(row[0].expires_at) <= datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    session, user = row
    if request.method not in SAFE_METHODS:
        require_trusted_origin(request)
        provided = request.headers.get("x-csrf-token", "").encode("utf-8")
        if not secrets.compare_digest(provided, session.csrf_token.encode("ascii")):
            raise HTTPException(status_code=403, detail="Invalid CSRF token.")
    return session, user


def end_session(db, response, session):
    db.delete(session)
    db.commit()
    response.delete_cookie(COOKIE, path="/api", httponly=True, samesite="strict")
