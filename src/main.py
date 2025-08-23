from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.api import auth, log, alert, incident, dashboard, health
import uvicorn
from src.middleware.logging_middleware import log_requests
from arq import create_pool
from arq.connections import RedisSettings
from src.core.config import settings
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages the application's lifespan.
    - Connects to Redis on startup.
    - Closes the connection on shutdown.
    """
    # This code runs ON STARTUP
    try:
        app.state.redis = await create_pool(RedisSettings.from_dsn(settings.REDIS_URL))
        print("Redis connection pool created successfully")
    except Exception as e:
        print(f"Failed to create Redis connection: {e}")
        app.state.redis = None
    
    yield  # The application is now running
    
    # This code runs ON SHUTDOWN
    try:
        if hasattr(app.state, 'redis') and app.state.redis:
            await app.state.redis.close()
            print("Redis connection closed successfully")
    except Exception as e:
        print(f"Error closing Redis connection: {e}")

app = FastAPI(title="Sentinel XDR Backend API", lifespan=lifespan)


app.middleware("http")(log_requests)

origins = [
    "http://localhost:3000",
    "http://152.53.44.111:3000",
    "https://linda.teapec.com"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes
app.include_router(health.router, prefix="/health", tags=["Health"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(log.router, prefix="/api/v1", tags=["Logs"])
app.include_router(alert.router, prefix="/api/v1", tags=["Alerts"])
app.include_router(incident.router, prefix="/api/v1", tags=["Incidents"])
app.include_router(dashboard.router, prefix="/api/v1", tags=["Dashboard"])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)