"""FastAPI application entry point for the Static Analysis Engine."""

import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router, set_analysis_service
from app.services.analysis_service import AnalysisService

# Load environment variables
load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — initialize services on startup."""
    # Read configuration from environment
    sonar_url = os.getenv("SONARQUBE_URL", "http://localhost:9000")
    sonar_token = os.getenv("SONARQUBE_TOKEN")
    sonar_enabled = os.getenv("SONARQUBE_ENABLED", "false").lower() == "true"

    # Create and wire up the analysis service
    service = AnalysisService(
        sonar_url=sonar_url,
        sonar_token=sonar_token,
        sonar_enabled=sonar_enabled,
    )
    set_analysis_service(service)

    # Ensure results directory exists
    os.makedirs("results", exist_ok=True)

    yield  # Application runs here


app = FastAPI(
    title="Static Analysis Engine",
    description=(
        "A reusable backend service that accepts Python source code, "
        "analyzes it using AST, Pylint, Bandit, Radon, and optionally "
        "SonarQube, and produces structured JSON findings suitable for "
        "consumption by AI agents."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(router)
