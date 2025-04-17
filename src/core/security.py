import os
import requests
from functools import lru_cache
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError, ExpiredSignatureError
from dotenv import load_dotenv

dotenv_path = os.path.join(os.path.dirname(__file__), '..', '.env')
load_dotenv(dotenv_path=dotenv_path)


SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_JWKS_URL = os.getenv("SUPABASE_JWKS_URL")
SUPABASE_AUDIENCE = os.getenv("SUPABASE_AUDIENCE")
SUPABASE_ISSUER = os.getenv("SUPABASE_ISSUER")

if not all([SUPABASE_URL, SUPABASE_JWKS_URL, SUPABASE_AUDIENCE, SUPABASE_ISSUER]):
    raise EnvironmentError(
        "Supabase environment variables (URL, JWKS_URL, AUDIENCE, ISSUER) are required."
    )
    
 #JWKS Fetching
 
 #adding Cache to avoid fetching the JWKS everytime
@lru_cache(maxsize=1)
def get_jwks():
    """ Fetches Supabase JWKS, caching the result. """
    try:
        response = requests.get(SUPABASE_JWKS_URL, timeout=10) # Increased timeout slightly
        response.raise_for_status() # Error for bad status codes
        return response.json()
    except requests.exceptions.Timeout:
        print(f"Error: Timeout fetching JWKS from {SUPABASE_JWKS_URL}")
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Timeout fetching authentication keys.",
        )
    except requests.exceptions.RequestException as e:
        print(f"Error fetching JWKS: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not fetch authentication keys.",
        )
    except (ValueError, KeyError) as e:
        print(f"Error parsing JWKS: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error parsing authentication keys.",
        )
        
        
#--- Token Verification ----
security_scheme = HTTPBearer()

async def verify_token(token: HTTPAuthorizationCredentials = Depends(security_scheme)) -> dict:
    """
    Verifies the Supabase JWT. Decodes, checks signature, audience, issuer, expiry.

    Returns:
        Decoded token payload (claims).
    Raises:
        HTTPException: If token is invalid or verification fails.
    """
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    jwt_token = token.credentials
    try:
        jwks = get_jwks() # Fetch (potentially cached) public keys
        unverified_header = jwt.get_unverified_header(jwt_token)
        kid = unverified_header.get("kid") # Key ID from token header

        if not kid:
             raise JWTError("Token header missing 'kid'")

        # Find the specific RSA public key in JWKS matching the token's kid
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == kid:
                rsa_key = {
                    "kty": key["kty"], "kid": key["kid"], "use": key["use"],
                    "n": key["n"], "e": key["e"]
                }
                break

        if not rsa_key:
            print(f"Error: Public key with kid '{kid}' not found in JWKS.")
            raise JWTError(f"Public key with kid '{kid}' not found.")

        payload = jwt.decode(
            jwt_token,
            rsa_key,
            algorithms=["RS256"],
            audience=SUPABASE_AUDIENCE,
            issuer=SUPABASE_ISSUER,
        )
        return payload

    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token validation failed: {e}")
    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"Unexpected error during token validation: {e}")
        raise HTTPException(status_code=500, detail="Internal server error validating token")


#Dependency Injection
async def get_current_user(payload: dict = Depends(verify_token)) -> dict:
    """
    FastAPI dependency that verifies the token and returns the user payload (claims).
    If verification fails, verify_token raises HTTPException, stopping the request.
    """
    
    return payload
