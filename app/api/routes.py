"""FastAPI routes for the Static Analysis Engine."""

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.models.analysis import AnalysisResult
from app.services.analysis_service import AnalysisService

router = APIRouter()

# Singleton analysis service — initialized via lifespan in main.py
_analysis_service: AnalysisService | None = None


def get_analysis_service() -> AnalysisService:
    """Get the analysis service singleton."""
    global _analysis_service
    if _analysis_service is None:
        _analysis_service = AnalysisService()
    return _analysis_service


def set_analysis_service(service: AnalysisService) -> None:
    """Set the analysis service (used during app startup)."""
    global _analysis_service
    _analysis_service = service


# ─── Health Check ────────────────────────────────────────────────────────

@router.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint."""
    service = get_analysis_service()
    sonar_status = "unavailable"
    if service.sonar_enabled:
        sonar_status = "available" if service.sonarqube.is_available() else "unavailable"
    else:
        sonar_status = "disabled"

    return {
        "status": "healthy",
        "tools": {
            "AST": "available",
            "Pylint": "available",
            "Bandit": "available",
            "Radon": "available",
            "SonarQube": sonar_status,
        },
    }


# ─── Analyze ─────────────────────────────────────────────────────────────

@router.post(
    "/analyze",
    response_model=AnalysisResult,
    tags=["Analysis"],
    summary="Analyze source code",
    description=(
        "Upload a Python source file (.py) or a ZIP archive (.zip) "
        "containing Python source files for static analysis."
    ),
)
async def analyze(file: UploadFile = File(...)):
    """
    Analyze uploaded source code.

    Accepts:
    - A single `.py` file
    - A `.zip` archive containing `.py` files

    Returns structured JSON with all findings from AST, Pylint,
    Bandit, Radon, and SonarQube (if available).
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    content = await file.read()

    service = get_analysis_service()
    result = await service.analyze_file(content, file.filename)
    return result


# ─── Get Results ─────────────────────────────────────────────────────────

@router.get(
    "/results/{analysis_id}",
    response_model=AnalysisResult,
    tags=["Results"],
    summary="Get analysis results",
    description="Retrieve structured findings for a previous analysis by its ID.",
)
async def get_results(analysis_id: str):
    """Retrieve analysis results by ID."""
    service = get_analysis_service()
    result = service.get_result(analysis_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"Analysis '{analysis_id}' not found",
        )
    return result


# ─── List Analyses ───────────────────────────────────────────────────────

@router.get(
    "/results",
    tags=["Results"],
    summary="List all analyses",
    description="List all stored analysis IDs.",
)
async def list_results():
    """List all available analysis result IDs."""
    service = get_analysis_service()
    analyses = service.list_results()
    return {"analyses": analyses, "count": len(analyses)}
