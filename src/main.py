from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware 
from src.api import  auth, log, alert, incident, dashboard
import uvicorn
from src.middleware.logging_middleware import log_requests


app = FastAPI(title="Sentinel XDR Backend API")
app.middleware("http")(log_requests) 

origins = [
    "http://localhost:3000",  
    "http://127.0.0.1:3000", 
    
]


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

#include routes
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(log.router, prefix="/api/v1", tags=["Logs"])
app.include_router(alert.router, prefix="/api/v1", tags=["Alerts"])
app.include_router(incident.router, prefix="/api/v1", tags=["Incidents"])
app.include_router(dashboard.router, prefix="/api/v1", tags=["Dashboard"])


if __name__ == "__main__":
   
   uvicorn.run(app, host="0.0.0.0", port = 8000)