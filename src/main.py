# /app/src/main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Assume these imports are correct for your project structure
from src.api import auth, log, alert, incident, dashboard, health
from src.middleware.logging_middleware import log_requests
from src.models import User, Log, Alert, IncidentResponse # You need to import your models
from src.database import Base, engine # You need to import your db engine

# Import the admin app and its configuration components
from fastadmin import fastapi_app as admin_app
from fastadmin.providers.auth import UsernamePasswordProvider
from fastadmin.resources import Model

# --- START OF fastadmin CONFIGURATION ---
# This setup is done once, when the file is loaded. Not in a startup event.

admin_app.set_logo_url("https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png")

admin_app.set_providers([
    UsernamePasswordProvider(
        admin_model=User, 
        login_logo_url="", 
        session_secret="supersecret"  # IMPORTANT: Change this and load from a secret/env var
    )
])

admin_app.add_resources([
    Model(User),
    Model(Log),
    Model(Alert),
    Model(IncidentResponse),
])



# Your database initialization function
def init_db():
    Base.metadata.create_all(bind=engine)

# Create and configure your main application
app = FastAPI(title="Sentinel XDR Backend API")
app.middleware("http")(log_requests)

# Mount the fully configured admin app
app.mount("/admin", admin_app)

# CORS Middleware
origins = [
    "http://localhost:3000",
    "http://152.53.44.111:3000",
    "https://linda.teapec.com",
    "https://api.teapec.com",
    "http://api.teapec.com"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Include your API routers
app.include_router(health.router, prefix="/health", tags=["Health"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(log.router, prefix="/api/v1", tags=["Logs"])
app.include_router(alert.router, prefix="/api/v1", tags=["Alerts"])
app.include_router(incident.router, prefix="/api/v1", tags=["Incidents"])
app.include_router(dashboard.router, prefix="/api/v1", tags=["Dashboard"])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)