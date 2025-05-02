from fastapi import FastAPI
from src.api import  auth, log, alert
import uvicorn 
from src.core.database import engine, Base 
from src.middleware.logging_middleware import log_requests

def init_db():
    Base.metadata.create_all(bind=engine)
    
app = FastAPI(title="Sentinel XDR Backend API")
app.middleware("http")(log_requests)

#include routes
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(log.router, prefix="/api/v1", tags=["Logs"])
app.include_router(alert.router, prefix="/api/v1", tags=["Alerts"])





if __name__ == "__main__":
  
    uvicorn.run(app, host="0.0.0.0", port = 8000)