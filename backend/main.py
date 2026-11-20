"""GitShield AI Backend Entrypoint.

Initializes the FastAPI application, CORS middleware, global error handling,
and REST API routes.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.api.routes import router
from backend.core.config import settings
from backend.core.logging import logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events manager for FastAPI startup and shutdown."""
    logger.info("=" * 60)
    logger.info("Starting GitShield AI Security Intelligence Engine")
    logger.info(f"Environment: {settings.APP_ENV}")
    logger.info(f"LLM Provider: {settings.LLM_PROVIDER} ({settings.LLM_MODEL})")
    logger.info(f"LLM Gateway Base URL: {settings.LLM_BASE_URL}")
    logger.info(f"Masked API Key: {settings.get_masked_api_key()}")
    logger.info("=" * 60)
    yield
    logger.info("GitShield AI Engine shutting down.")


app = FastAPI(
    title="GitShield AI API",
    description="Multi-Agent AI-Powered GitHub Security Analysis & Remediation Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for Streamlit frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Attach REST routes
app.include_router(router)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all exception handler to avoid leaking trace details to clients."""
    logger.error(f"Unhandled server error on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Please check server logs for details."},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.BACKEND_HOST,
        port=settings.BACKEND_PORT,
        reload=(settings.APP_ENV == "development"),
    )
