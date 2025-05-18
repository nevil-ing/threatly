from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware 
from src.api import  auth, log, alert
import uvicorn
from src.core.database import engine, Base
from src.middleware.logging_middleware import log_requests

def init_db():
    Base.metadata.create_all(bind=engine)

app = FastAPI(title="Sentinel XDR Backend API")
app.middleware("http")(log_requests) # Your custom logging middleware

origins = [
    "http://localhost:3000",  
    "http://127.0.0.1:3000", 
    # Add other origins if necessary
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

# Call init_db if you want to create tables on startup
# init_db() # Uncomment if this is your intention

if __name__ == "__main__":
    # Consider calling init_db() here as well if you run this file directly for development
    # and want the DB initialized.
    uvicorn.run(app, host="0.0.0.0", port = 8000)