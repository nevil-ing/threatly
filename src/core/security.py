import os
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError, ExpiredSignatureError
from dotenv import load_dotenv
from pathlib import Path

env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)


SUPABASE_AUDIENCE = os.getenv("SUPABASE_AUDIENCE")
SUPABASE_ISSUER = os.getenv("SUPABASE_ISSUER")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET") 


if not all([SUPABASE_AUDIENCE, SUPABASE_ISSUER, SUPABASE_JWT_SECRET]):
    raise EnvironmentError(
        "Supabase environment variables are required for HS256."
    )

security_scheme = HTTPBearer()

async def verify_token_hs256(token: HTTPAuthorizationCredentials = Depends(security_scheme)) -> dict:
    """
    Verifies the Supabase JWT using HS256.
    Checks signature, audience, issuer, expiry.
    """
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    jwt_token = token.credentials
    try:
     
        payload = jwt.decode(
            jwt_token,
            SUPABASE_JWT_SECRET, 
            algorithms=["HS256"], 
            audience=SUPABASE_AUDIENCE,
            issuer=SUPABASE_ISSUER,
        )
        return payload

    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except JWTError as e:
       
        print(f"Token validation failed (HS256): {e}")
      
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token validation failed: {e}")
    except Exception as e:
        print(f"Unexpected error during token validation: {e}")
        raise HTTPException(status_code=500, detail="Internal server error validating token")


async def get_current_user(payload: dict = Depends(verify_token_hs256)) -> dict: 
    return payload