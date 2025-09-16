from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.api import auth, log, alert, incident, dashboard, health
from src.database import engine, Base
from src.models import User, Log, Alert, Incident
from src.middleware.logging_middleware import log_requests
from fastadmin import fastapi_app as admin_app, UsernamePasswordProvider, Model
import uvicorn
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_db():
    """Initialize database tables"""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise

# Initialize FastAPI app
app = FastAPI(
    title="Sentinel XDR Backend API",
    description="Extended Detection and Response system API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add logging middleware
app.middleware("http")(log_requests)

@app.on_event("startup")
async def startup():
    """Startup event handler"""
    try:
        # Initialize database
        init_db()
        
        # Configure admin panel
        await admin_app.configure(
            logo_url="https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png",
            providers=[
                UsernamePasswordProvider(
                    admin_model=User, 
                    login_logo_url="", 
                    session_secret="supersecret"  # TODO: Use environment variable
                )
            ],
            resources=[
                Model(User),
                Model(Log),
                Model(Alert),
                Model(Incident),
            ],
        )
        logger.info("Application started successfully")
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise

@app.on_event("shutdown")
async def shutdown():
    """Shutdown event handler"""
    logger.info("Application shutting down")

# Mount admin panel
app.mount("/admin", admin_app)

# CORS configuration
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://152.53.44.111:3000",
    "https://linda.teapec.com",
    "https://api.teapec.com",
    "http://api.teapec.com"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Include API routes
app.include_router(health.router, prefix="/health", tags=["Health"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(log.router, prefix="/api/v1", tags=["Logs"])
app.include_router(alert.router, prefix="/api/v1", tags=["Alerts"])
app.include_router(incident.router, prefix="/api/v1", tags=["Incidents"])
app.include_router(dashboard.router, prefix="/api/v1", tags=["Dashboard"])

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Sentinel XDR Backend API", 
        "version": "1.0.0",
        "docs": "/docs"
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",  # Use string format for better reloading
        host="0.0.0.0", 
        port=8000,
        reload=True,  # Enable auto-reload in development
        log_level="info"
    )