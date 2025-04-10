from fastapi import FastAPI
from app.api import logs, alerts, auth
import uvicorn 
from app.core.database import engine, Base 
from app.middleware.logging_middleware import log_requests

def init_db():
    Base.metadata.create_all(bind=engine)
    
app = FastAPI(title="Sentinel XDR Backend API")
app.middleware("http")(log_requests)

#include routes
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(logs.router, prefix="/api/v1", tags=["Logs"])
app.include_router(alerts.router, prefix="/api/v1", tags=["Alerts"])
t




if __name__ == "__main__":
  
    uvicorn.run(app, host="0.0.0.0", port = 8000)