from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session
from backend.api.database.connection import get_db
from backend.api.database.models import AppRole
from backend.core.authentication.sessions import resolve_session
from backend.core.graphLoader.s3Loader import S3Loader

def get_loader():
    return S3Loader()


def get_authenticated_session(
    request: Request, db: Session = Depends(get_db),
    loader: S3Loader = Depends(get_loader),
):
    session, user = resolve_session(db, request)
    if loader.is_service_identity(user.username):
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    return session, user


def get_current_user(authentication=Depends(get_authenticated_session)):
    return authentication[1]


def get_requester_role(user=Depends(get_current_user), db: Session = Depends(get_db)):
    assignment = db.get(AppRole, user.id)
    return assignment.role if assignment else "USER"
