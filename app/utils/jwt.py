from datetime import datetime, timedelta
from typing import Optional, Annotated, Union

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from decouple import config
from pydantic import BaseModel

JWT_SECRET = config("secret")
JWT_ALGORITHM = config("algorithm")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")


class TokenData(BaseModel):
    email: Union[str, None] = None


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=600)
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except:
        return None


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                          detail="Could not validate credentials",
                                          headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        payload = TokenData(email=email)
        return payload
    except:
        raise credentials_exception
