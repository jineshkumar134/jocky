"""
JOCKY FastAPI Application Entrypoint
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.config import get_settings
from api.routes import health

settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Cybersecurity + Blockchain Forensic Domain-Specific Language and Investigation Framework",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Enable CORS for frontend dashboard development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers with both /api and root prefixes for serverless compatibility
from api.routes import cases
app.include_router(health.router, prefix="/api")
app.include_router(cases.router, prefix="/api")
app.include_router(health.router)
app.include_router(cases.router)


@app.get("/")
async def root():
    return {
        "service": settings.APP_NAME,
        "status": "online",
        "phase": settings.PHASE,
        "docs": "/docs",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host=settings.API_HOST, port=settings.API_PORT, reload=settings.DEBUG)
