"""
Health Check Routes for JOCKY API
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from server.config import Settings, get_settings

router = APIRouter(tags=["Health"])


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    phase: str
    environment: str


@router.get("/health", response_model=HealthResponse)
async def health_check(settings: Settings = Depends(get_settings)):
    """
    Health check endpoint to verify backend service status.
    """
    return HealthResponse(
        status="healthy",
        service=settings.APP_NAME,
        version=settings.VERSION,
        phase=settings.PHASE,
        environment=settings.ENVIRONMENT,
    )
