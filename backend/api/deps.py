from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from backend.api.database.connection import get_db
from backend.api.database.models import User
from backend.core.authentication.security import SECRET_KEY, ALGORITHM
from backend.core.graphLoader.s3Loader import S3Loader

# חשוב: ה-Url הזה חייב להיות הנתיב המדויק ללוגין שלך
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def get_loader():
    return S3Loader()


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db),
    loader: S3Loader = Depends(get_loader),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not isinstance(username, str) or not username or loader.is_scanner_name(username):
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception

    return user


def get_requester_role(user=Depends(get_current_user), loader=Depends(get_loader)):
    return loader.get_role(user.username)
