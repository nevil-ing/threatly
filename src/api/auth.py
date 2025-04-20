from typing import Dict
from fastapi import APIRouter, Depends
from src.core.security import get_current_user

router = APIRouter()

@router.get("/users/me", response_model=Dict)
async def read_users_me(user_payload: dict = Depends(get_current_user)):
    """ Protected endpoint. Returns user info from the verified JWT payload. """
    user_id = user_payload.get("sub") 
    user_email = user_payload.get("email") 
   

    return {
        "message": "Access granted to protected endpoint!",
        "user_id": user_id,
        "email": user_email,
        "all_claims": user_payload 
    }
