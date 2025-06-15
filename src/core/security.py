import os
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError, ExpiredSignatureError
from dotenv import load_dotenv
from pathlib import Path
# Load .env from the parent directory (adjust path if needed)
env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

# --- Configuration for HS256 ---
SUPABASE_AUDIENCE = os.getenv("SUPABASE_AUDIENCE")
SUPABASE_ISSUER = os.getenv("SUPABASE_ISSUER")
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET") # Ensure this matches your .env var name

# Check for required HS256 variables
if not all([SUPABASE_AUDIENCE, SUPABASE_ISSUER, SUPABASE_JWT_SECRET]):
    raise EnvironmentError(
        "Supabase environment variables (AUDIENCE, ISSUER, JWT_SECRET) are required for HS256."
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
        # For HS256, you use the shared secret, not JWKS
        payload = jwt.decode(
            jwt_token,
            SUPABASE_JWT_SECRET, # Use the shared secret
            algorithms=["HS256"], # Specify HS256 algorithm
            audience=SUPABASE_AUDIENCE,
            issuer=SUPABASE_ISSUER,
        )
        return payload

    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except JWTError as e:
        # Log the specific JWT error for better debugging
        print(f"Token validation failed (HS256): {e}")
        # You can add more detailed logging here if needed
        # print(f"Token being decoded: {jwt_token[:30]}...")
        # print(f"Expected Issuer: {SUPABASE_ISSUER}")
        # print(f"Expected Audience: {SUPABASE_AUDIENCE}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token validation failed: {e}")
    except Exception as e:
        print(f"Unexpected error during token validation: {e}")
        raise HTTPException(status_code=500, detail="Internal server error validating token")

# Dependency Injection - ensure your routes use this new function
async def get_current_user(payload: dict = Depends(verify_token_hs256)) -> dict: # Use the HS256 verifier
    return payload