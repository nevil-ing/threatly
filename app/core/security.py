import os
from datetime import datetime, timedelta
from  typing  import Optional, Any

from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import ValidationError

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.core.config import settings
from app.schemas.user import TokenData
from app import models
from app.core.database import SessionLocal


SECRET_KEY = os.environ.get("SECRET_KEY", "")
ALGORITHM = os.environ.get("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hashes a plain password."""
    return pwd_context.hash(password)

#jwt token handling
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Creates a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[TokenData]:
    """Decodes a JWT token and returns the payload (TokenData)."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        
        token_data = TokenData(username=username)
        return token_data
    except JWTError:
        return None
    except ValidationError: # Handle Pydantic validation error for TokenData
        return None


#OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/vi/auth/token")

#dependecy to get current user
async def get_current_user(token: str = Depends(oauth2_scheme)) -> models.User:
    """

    gets the current user based on the provided token.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
        )
    token_data = decode_access_token(token)
    if token_data is None or token_data.username is None:
        raise credentials_exception
    db = SessionLocal()
    
    try:
        from app.services import user_service
        user = await user.get_user_by_username(db, username=token_data.username)
    finally:
        db.close()   
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user

# Dependency for optional authentication
async def get_current_user_optional(token: str = Depends(oauth2_scheme, use_cache=False)) -> Optional[models.User]:
    if not token:
        return None
    try:
        return await get_current_user(token)
    except HTTPException as e:
        # If token is invalid or user not found, just return None instead of raising 401
        if e.status_code == status.HTTP_401_UNAUTHORIZED or e.status_code == 400:
             return None
        raise e # Re-raise other potential exceptions

async def get_current_active_user(current_user: models.User = Depends(get_current_user)):
     # You can add checks if the user is active
     if not current_user.is_active:
         raise HTTPException(status_code=400, detail="Inactive user")
     return current_user