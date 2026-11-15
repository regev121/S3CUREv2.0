from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.api.database.connection import get_db, lock_app_identity
from backend.api.database.models import AppRole, S3Account, User
from backend.api.deps import get_authenticated_session, get_loader, get_requester_role
from backend.core.authentication.security import (
    encrypt_data, get_password_hash, verify_password,
)
from backend.core.authentication.sessions import create_session, end_session, require_trusted_origin
from backend.core.request_limits import consume_limit
from backend.core.graphLoader.s3Loader import IdentityConflict, IdentityNotFound

router = APIRouter()


class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.@-]*$")
    password: SecretStr = Field(min_length=1, max_length=72)


class LoginCredentials(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr = Field(min_length=1, max_length=72)


class S3AccountCreate(BaseModel):
    alias: str
    endpoint: str
    access_key: str
    secret_key: SecretStr = Field(min_length=8, max_length=128)


def _require_new_identity(loader, username):
    if loader.is_service_identity(username):
        raise HTTPException(status_code=409, detail="That username is reserved.")
    try:
        loader.get_user_info(username)
    except IdentityNotFound:
        return
    raise HTTPException(status_code=409, detail="This MinIO identity already exists.")


@router.post("/login")
def login(credentials: LoginCredentials, request: Request, response: Response,
          db: Session = Depends(get_db), loader=Depends(get_loader)):
    require_trusted_origin(request)
    consume_limit(db, "login-ip", request.client.host if request.client else "unknown", limit=40, seconds=300)
    consume_limit(db, "login-account", credentials.username.casefold(), limit=8, seconds=300)
    user = None if loader.is_service_identity(credentials.username) else (
        db.query(User).filter(User.username == credentials.username).first()
    )
    valid = verify_password(credentials.password.get_secret_value(), user.hashed_password if user else None)
    if not user or not valid:
        raise HTTPException(
            status_code=401, detail="Incorrect username or password.",
        )
    session = create_session(db, request, response, user)
    assignment = db.get(AppRole, user.id)
    return _profile(user, assignment.role if assignment else "USER", session)


@router.post("/logout", status_code=204)
def logout(response: Response, authentication=Depends(get_authenticated_session), db: Session = Depends(get_db)):
    end_session(db, response, authentication[0])


@router.post("/register")
def register(user: UserRegister, role=Depends(get_requester_role),
             db: Session = Depends(get_db), loader=Depends(get_loader)):
    if role != "ADMIN":
        raise HTTPException(status_code=403, detail="Only admins can create S3CURE accounts.")
    password = user.password.get_secret_value()
    if len(password.encode("utf-8")) > 72:
        raise HTTPException(status_code=422, detail="Password must be at most 72 bytes.")
    lock_app_identity(db, user.username)
    if db.query(User).filter(func.lower(User.username) == user.username.lower()).first():
        raise HTTPException(status_code=409, detail="User exists.")
    new_user = User(username=user.username, hashed_password=get_password_hash(password))
    db.add(new_user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="User exists.")
    # The same username identifies the app user and the MinIO scan target.
    try:
        loader.provision_app_identity(user.username)
    except IdentityConflict as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    db.commit()
    return {"message": "User created", "id": new_user.id}


@router.post("/account/add/{user_id}")
def add_s3_account(user_id: int, account: S3AccountCreate, db: Session = Depends(get_db),
                   role=Depends(get_requester_role), loader=Depends(get_loader)):
    if role != "ADMIN":
        raise HTTPException(status_code=403, detail="Only admins can provision S3 accounts.")
    if db.get(User, user_id) is None:
        raise HTTPException(status_code=404, detail="User does not exist.")
    lock_app_identity(db, account.access_key)
    _require_new_identity(loader, account.access_key)
    secret = account.secret_key.get_secret_value()
    new_account = S3Account(
        user_id=user_id, alias_name=account.alias, endpoint_url=account.endpoint,
        access_key_encrypted=encrypt_data(account.access_key),
        secret_key_encrypted=encrypt_data(secret),
    )
    loader.create_identity(account.access_key, secret)
    db.add(new_account)
    db.commit()
    return {"message": "S3 account created"}


def _profile(user, role, session):
    return {"username": user.username, "role": role, "id": user.id, "csrf_token": session.csrf_token}


@router.get("/me")
def get_current_user_info(authentication=Depends(get_authenticated_session), role=Depends(get_requester_role)):
    session, user = authentication
    return _profile(user, role, session)
