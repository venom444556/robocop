"""Main FastAPI application entry point for RoboCop."""

import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import get_settings
from database import init_db, engine
from api import submissions, analysis, reports, webhooks, dashboard, search, management, yara_rules
from api.websocket import router as ws_router, manager
from middleware import RateLimitMiddleware, RequestLoggingMiddleware, AuthMiddleware

logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler - startup and shutdown events."""
    # Startup
    os.makedirs(settings.upload_dir, exist_ok=True)
    await init_db()
    logger.info("Application startup complete — %s v1.0.0", settings.app_name)
    yield
    # Shutdown: close WebSocket connections, dispose database engine
    for ws in list(manager.active_connections):
        try:
            await ws.close(code=1001, reason="Server shutting down")
        except Exception:
            logger.debug("Failed to close WebSocket during shutdown", exc_info=True)
        manager.active_connections.discard(ws)
    await engine.dispose()
    logger.info("Application shutdown complete")


app = FastAPI(
    title=settings.app_name,
    description="AI-powered malware analysis with multi-agent reasoning",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware - configure via CORS_ORIGINS environment variable
cors_origins = [o.strip() for o in settings.cors_origins.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization"],
)

# Security and operational middleware
# Middleware executes in reverse registration order in Starlette:
# Request → RequestLoggingMiddleware → RateLimitMiddleware → AuthMiddleware → Route
app.add_middleware(RateLimitMiddleware, requests_per_minute=120, burst=20)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(AuthMiddleware)


# Exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled errors."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    # Don't expose internal error details to users
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


# Include routers
app.include_router(submissions.router, prefix="/api/submissions", tags=["Submissions"])
app.include_router(analysis.router, prefix="/api/analysis", tags=["Analysis"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(webhooks.router, prefix="/api/webhooks", tags=["Webhooks"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(search.router, prefix="/api/search", tags=["Search"])
app.include_router(management.router, prefix="/api/management", tags=["Management"])
app.include_router(yara_rules.router, prefix="/api/yara-rules", tags=["YARA Rules"])
app.include_router(ws_router, tags=["WebSocket"])


@app.get("/")
async def root():
    """Root endpoint - API health check."""
    return {
        "name": settings.app_name,
        "status": "healthy",
        "version": "1.0.0"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
