from fastapi import FastAPI
from app.api import logs
import uvicorn 
from app.core.database import engine, Base 



app = FastAPI(title="Sentinel XDR Backend API")
app.include_router(logs.router, prefix="/api/v1")

if __name__ == "__main__":
  
    uvicorn.run(app, host="0.0.0.0", port = 8000)