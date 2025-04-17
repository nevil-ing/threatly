from typing import Dict
from fastapi import APIRouter, Depends
from src.core.security import get_current_user

router = APIRouter()

@router.get("/")
async def root():
    """ Publicly accessible root endpoint. """
    return {"message": "Hello from FastAPI with Supabase Auth (Poetry & Docker!)"}

@router.get("/users/me", response_model=Dict) # Using Dict for simplicity, define Pydantic models for better validation
async def read_users_me(user_payload: dict = Depends(get_current_user)):
    """ Protected endpoint. Returns user info from the verified JWT payload. """
    user_id = user_payload.get("sub") # 'sub' claim is the standard User ID in JWT
    user_email = user_payload.get("email") # Email claim (if present)
    # You can access other claims as needed, e.g., user_payload.get('user_metadata')

    return {
        "message": "Access granted to protected endpoint!",
        "user_id": user_id,
        "email": user_email,
        "all_claims": user_payload # Return all claims for inspection/debugging
    }
