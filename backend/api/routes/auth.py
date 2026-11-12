from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.api.database.connection import get_db, lock_app_identity
from backend.api.database.models import User, S3Account
from backend.api.deps import get_current_user, get_loader, get_requester_role
from backend.core.authentication.security import (
    create_access_token, encrypt_data, get_password_hash, verify_password,
)
from backend.core.graphLoader.s3Loader import IdentityConflict, IdentityNotFound

router = APIRouter()


class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.@-]*$")
    password: str = Field(min_length=1)


class S3AccountCreate(BaseModel):
    alias: str
    endpoint: str
    access_key: str
    secret_key: str


def _require_new_identity(loader, username):
    if loader.is_scanner_name(username):
        raise HTTPException(status_code=409, detail="That username is reserved.")
    try:
        loader.get_user_info(username)
    except IdentityNotFound:
        return
    raise HTTPException(status_code=409, detail="This MinIO identity already exists.")


@router.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db),
          loader=Depends(get_loader)):
    user = None if loader.is_scanner_name(form.username) else (
        db.query(User).filter(User.username == form.username).first()
    )
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(
            status_code=401, detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"access_token": create_access_token({"sub": user.username}), "token_type": "bearer"}


@router.post("/register")
def register(user: UserRegister, role=Depends(get_requester_role),
             db: Session = Depends(get_db), loader=Depends(get_loader)):
    if role != "ADMIN":
        raise HTTPException(status_code=403, detail="Only admins can create S3CURE accounts.")
    if len(user.password.encode("utf-8")) > 72:
        raise HTTPException(status_code=422, detail="Password must be at most 72 bytes.")
    lock_app_identity(db, user.username)
    if db.query(User).filter(func.lower(User.username) == user.username.lower()).first():
        raise HTTPException(status_code=409, detail="User exists.")
    new_user = User(username=user.username, hashed_password=get_password_hash(user.password))
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
    _require_new_identity(loader, account.access_key)
    new_account = S3Account(
        user_id=user_id, alias_name=account.alias, endpoint_url=account.endpoint,
        access_key_encrypted=encrypt_data(account.access_key),
        secret_key_encrypted=encrypt_data(account.secret_key),
    )
    loader.create_identity(account.access_key, account.secret_key)
    db.add(new_account)
    db.commit()
    return {"message": "S3 account created"}


@router.get("/me")
def get_current_user_info(current_user: User = Depends(get_current_user),
                          role=Depends(get_requester_role)):
    return {"username": current_user.username, "role": role, "id": current_user.id}
