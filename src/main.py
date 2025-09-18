from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import logging
import sys
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import your modules with error handling
try:
    from src.api import auth, alert, incident, dashboard, health
    from src.api import log as log_api  # Rename to avoid conflict
    from src.core.database import engine, Base
    from src.middleware.logging_middleware import log_requests
    logger.info("Successfully imported core modules")
except ImportError as e:
    logger.error(f"Failed to import core modules: {e}")
    sys.exit(1)

# Import models with error handling
try:
    from src.core.models import User, Alert, Incident
    from src.core.models import Log as LogModel  # Rename to avoid conflict
    logger.info("Successfully imported models")
except ImportError as e:
    logger.error(f"Failed to import models: {e}")
    # Try alternative path
    try:
        from src.models import User, Alert, Incident
        from src.models import Log as LogModel
        logger.info("Successfully imported models from alternative path")
    except ImportError as e2:
        logger.error(f"Failed to import models from both paths: {e2}")
        sys.exit(1)

# Import admin components with error handling
admin_app = None
try:
    from fastadmin import fastapi_app as admin_app, UsernamePasswordProvider, Model
    logger.info("Successfully imported fastadmin")
except ImportError:
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
        
        # Configure admin panel if available
        if admin_app:
            try:
                await admin_app.configure(
                    logo_url="https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png",
                    providers=[
                        UsernamePasswordProvider(
                            admin_model=User, 
                            login_logo_url="", 
                            session_secret=os.getenv("ADMIN_SECRET", "supersecret")  # Use env var
                        )
                    ],
                    resources=[
                        Model(User),
                        Model(LogModel),
                        Model(Alert),
                        Model(Incident),
                    ],
                )
                logger.info("Admin panel configured successfully")
            except Exception as e:
                logger.error(f"Failed to configure admin panel: {e}")
        
        logger.info("Application started successfully")
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise

@app.on_event("shutdown")
async def shutdown():
    """Shutdown event handler"""
    logger.info("Application shutting down")

# Mount admin panel if available
if admin_app:
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
app.include_router(log_api.router, prefix="/api/v1", tags=["Logs"])  # Use renamed import
app.include_router(alert.router, prefix="/api/v1", tags=["Alerts"])
app.include_router(incident.router, prefix="/api/v1", tags=["Incidents"])
app.include_router(dashboard.router, prefix="/api/v1", tags=["Dashboard"])

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Sentinel XDR Backend API", 
        "version": "1.0.0",
        "docs": "/docs",
        "admin": "/admin" if admin_app else "Not available"
    }

# Health check endpoint
@app.get("/ping")
async def ping():
    return {"status": "ok", "message": "Server is running"}

if __name__ == "__main__":
    uvicorn.run(
        "src.main:app",  # Updated path to match your structure
        host="0.0.0.0", 
        port=8000,
        reload=True,
        log_level="info"
    )