"""FastAPI REST API Routes.

Exposes endpoints for repository submission, job status polling,
real-time telemetry event streaming, findings, reports, and diagnostic checks.
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, Response, status
from fastapi.responses import PlainTextResponse

from backend.api.schemas import (
    HealthResponse,
    LLMStatusResponse,
    AnalyzeRequest,
    AnalyzeResponse,
    ExecutionEvent,
    UnifiedVulnerability,
    AnalysisReport,
    RepositoryOverview,
)
from backend.core.config import settings
from backend.core.llm_factory import LLMFactory
from backend.core.security import validate_github_url
from backend.services.job_service import job_service
from backend.services.report_service import report_service
from backend.core.logging import logger

router = APIRouter()


# -----------------------------------------------------------------------------
# Diagnostics & Health Endpoints
# -----------------------------------------------------------------------------

@router.get("/health", response_model=HealthResponse, tags=["Diagnostics"])
async def get_health() -> HealthResponse:
    """Retrieve service health status and current execution environment."""
    return HealthResponse(
        status="healthy",
        app_env=settings.APP_ENV,
        version="1.0.0",
    )


@router.get("/api/v1/llm/status", response_model=LLMStatusResponse, tags=["Diagnostics"])
async def get_llm_status() -> LLMStatusResponse:
    """Check connectivity and model availability for the configured IBM LLM gateway."""
    try:
        status_info = await LLMFactory.check_connectivity()
        return LLMStatusResponse(
            status=status_info.get("status", "UNKNOWN"),
            provider=status_info.get("provider", settings.LLM_PROVIDER),
            model=status_info.get("model", settings.LLM_MODEL),
            base_url=status_info.get("base_url", settings.LLM_BASE_URL),
            masked_key=status_info.get("masked_key"),
            message=status_info.get("message"),
            latency_ms=status_info.get("latency_ms"),
            response_sample=status_info.get("response_sample"),
        )
    except Exception as e:
        logger.error(f"Error checking LLM status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to check LLM gateway status: {type(e).__name__}",
        )


@router.post("/api/v1/validate-url", tags=["Repository"])
async def validate_repo_url(payload: dict):
    """Validate a candidate GitHub repository URL without launching a scan."""
    raw_url = payload.get("url", "")
    is_valid, owner, repo, message = validate_github_url(raw_url)
    if not is_valid:
        return {
            "valid": False,
            "error": message,
        }
    return {
        "valid": True,
        "owner": owner,
        "repo": repo,
        "normalized_url": message,
    }


# -----------------------------------------------------------------------------
# Analysis Execution Endpoints
# -----------------------------------------------------------------------------

@router.post("/api/v1/analyze", response_model=AnalyzeResponse, status_code=status.HTTP_202_ACCEPTED, tags=["Analysis"])
async def start_analysis(request: AnalyzeRequest) -> AnalyzeResponse:
    """Submit a GitHub repository URL to initiate asynchronous multi-agent security analysis."""
    try:
        response = job_service.submit_job(request)
        return response
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to submit analysis job: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to initialize job.")


@router.get("/api/v1/analyze/{job_id}", tags=["Analysis"])
async def get_analysis_status(job_id: str):
    """Retrieve the current status, timing, and progress of an analysis job."""
    record = job_service.get_job(job_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {job_id} not found.")

    return {
        "job_id": record.job_id,
        "status": record.status,
        "repository_url": record.request.repository_url,
        "owner": record.owner,
        "repository_name": record.repo,
        "created_at": record.created_at,
        "completed_at": record.completed_at,
        "error": record.error,
        "events_count": len(record.events),
        "has_report": record.report is not None,
    }


@router.get("/api/v1/events/{job_id}", response_model=List[ExecutionEvent], tags=["Analysis"])
async def get_analysis_events(job_id: str) -> List[ExecutionEvent]:
    """Retrieve all real-time execution telemetry events recorded for an active or completed job."""
    record = job_service.get_job(job_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {job_id} not found.")

    return job_service.get_events(job_id)


@router.get("/api/v1/repositories/{job_id}", response_model=RepositoryOverview, tags=["Analysis"])
async def get_repository_overview(job_id: str) -> RepositoryOverview:
    """Retrieve technology stack and directory overview for an analyzed repository."""
    record = job_service.get_job(job_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {job_id} not found.")

    if not record.report or not record.report.repository:
        raise HTTPException(
            status_code=status.HTTP_425_TOO_EARLY if record.status == "RUNNING" else status.HTTP_404_NOT_FOUND,
            detail="Repository overview is not ready yet.",
        )

    return record.report.repository


@router.get("/api/v1/findings/{job_id}", response_model=List[UnifiedVulnerability], tags=["Analysis"])
async def get_findings(
    job_id: str,
    category: Optional[str] = Query(None, description="Filter findings by security category"),
    severity: Optional[str] = Query(None, description="Filter findings by severity rating"),
    validation_status: Optional[str] = Query(None, description="Filter by validation verdict"),
) -> List[UnifiedVulnerability]:
    """Retrieve the unified list of security vulnerabilities with optional filtering."""
    record = job_service.get_job(job_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {job_id} not found.")

    findings = job_service.get_findings(job_id)

    # Apply query parameter filters
    if category:
        findings = [f for f in findings if f.category.lower() == category.lower()]
    if severity:
        findings = [f for f in findings if f.severity.upper() == severity.upper()]
    if validation_status:
        findings = [f for f in findings if f.validation_status.upper() == validation_status.upper()]

    return findings


# -----------------------------------------------------------------------------
# Report Generation & Export Endpoints
# -----------------------------------------------------------------------------

@router.get("/api/v1/report/{job_id}", response_model=AnalysisReport, tags=["Reports"])
async def get_report(job_id: str) -> AnalysisReport:
    """Retrieve the complete synthesized analysis report object."""
    record = job_service.get_job(job_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Job {job_id} not found.")

    report = job_service.get_report(job_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_425_TOO_EARLY if record.status == "RUNNING" else status.HTTP_404_NOT_FOUND,
            detail="Analysis report is not ready yet.",
        )

    return report


@router.get("/api/v1/report/{job_id}/markdown", response_class=PlainTextResponse, tags=["Reports"])
async def get_markdown_report(job_id: str):
    """Export and download the analysis report in clean Markdown format."""
    record = job_service.get_job(job_id)
    if not record or not record.report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report {job_id} not available.")

    md_content = report_service.generate_markdown_report(record.report)
    return PlainTextResponse(
        content=md_content,
        headers={"Content-Disposition": f"attachment; filename=gitshield_report_{job_id}.md"},
    )


@router.get("/api/v1/report/{job_id}/json", tags=["Reports"])
async def get_json_report(job_id: str):
    """Export and download the complete analysis report as a JSON file."""
    record = job_service.get_job(job_id)
    if not record or not record.report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report {job_id} not available.")

    json_str = report_service.generate_json_report(record.report)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=gitshield_report_{job_id}.json"},
    )
