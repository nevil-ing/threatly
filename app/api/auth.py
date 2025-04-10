
from datetime import timedelta
from typing import List 

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app import schemas, models, services 
from app.core.database import get_db
from app.core.security import create_access_token, verify_password, ACCESS_TOKEN_EXPIRE_MINUTES, get_current_active_user

router = APIRouter()

@router.post("/token", response_model=schemas.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Handles user login and returns a JWT access token."""
    user = services.user_service.get_user_by_username(db, username=form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active: # Check if user is active
         raise HTTPException(
             status_code=status.HTTP_400_BAD_REQUEST,
             detail="Inactive user",
         )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
        # You could add more data to the token payload here if needed (e.g., user_id, roles)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/users/", response_model=schemas.User, status_code=status.HTTP_201_CREATED)
def create_new_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """Creates a new user."""
    db_user = services.user_service.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    created_user = services.user_service.create_user(db=db, user=user)
    return created_user

@router.get("/users/me", response_model=schemas.User)
async def read_users_me(current_user: models.User = Depends(get_current_active_user)):
    """Gets the profile for the currently authenticated user."""
    return current_user

# You might add more user management endpoints here (e.g., get all users - requires admin privileges usually)
@router.get("/users/", response_model=List[schemas.User]) # Example: Get all users (needs protection/admin role)
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_active_user)):
     # Add role check here if needed: if current_user.role != "admin": raise HTTPException(...)
     users = db.query(models.User).offset(skip).limit(limit).all() # Simple example
     return users