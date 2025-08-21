from fastapi import APIRouter, Depends

router = APIRouter()

@router.get("/")
def health_check():
    return {"status": "ok"}