from fastapi import FastAPI
from app.api import logs
import uvicorn 
from app.core.database import engine, Base 
from app.middleware.logging_middleware import log_requests

def init_db():
    Base.metadata.create_all(bind=engine)
    
app = FastAPI(title="Sentinel XDR Backend API")
app.middleware("http")(log_requests)
app.include_router(logs.router, prefix="/api/v1")





if __name__ == "__main__":
  
    uvicorn.run(app, host="0.0.0.0", port = 8000)