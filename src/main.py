from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.api import auth, log, alert, incident, dashboard, health
import uvicorn
from src.middleware.logging_middleware import log_requests
from fastadmin import fastapi_app as admin_app

def init_db():
    Base.metadata.create_all(bind=engine)

app = FastAPI(title="Sentinel XDR Backend API")
app.middleware("http")(log_requests) 
@app.on_event("startup")
async def startup():
    await admin_app.configure(
        logo_url="https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png",
        providers=[
            UsernamePasswordProvider(
                admin_model=User, login_logo_url="", session_secret="supersecret"
            )
        ],
        resources=[
            Model(User),
            Model(Log),
            Model(Alert),
            Model(IncidentResponse),
        ],
    )
app.mount("/admin", admin_app)
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

# Include routes
app.include_router(health.router, prefix="/health", tags=["Health"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(log.router, prefix="/api/v1", tags=["Logs"])
app.include_router(alert.router, prefix="/api/v1", tags=["Alerts"])
app.include_router(incident.router, prefix="/api/v1", tags=["Incidents"])
app.include_router(dashboard.router, prefix="/api/v1", tags=["Dashboard"])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)