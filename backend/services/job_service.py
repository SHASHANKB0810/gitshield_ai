"""Job Management and Event Pipeline Service.

Manages background analysis tasks, stores execution telemetry,
and persists analysis reports.
"""

import asyncio
from datetime import datetime, timezone
import uuid
from typing import Dict, List, Optional
from backend.api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    ExecutionEvent,
    AnalysisReport,
    UnifiedVulnerability,
)
from backend.graph.workflow import analysis_graph
from backend.core.security import validate_github_url
from backend.core.logging import logger


class JobRecord:
    """In-memory data structure tracking a single analysis job."""

    def __init__(self, job_id: str, request: AnalyzeRequest, owner: str, repo: str):
        self.job_id = job_id
        self.request = request
        self.owner = owner
        self.repo = repo
        self.status = "QUEUED"
        self.created_at = datetime.now(timezone.utc)
        self.completed_at: Optional[datetime] = None
        self.events: List[ExecutionEvent] = []
        self.report: Optional[AnalysisReport] = None
        self.error: Optional[str] = None


class JobService:
    """Service handling background LangGraph job dispatch and state queries."""

    def __init__(self):
        self.jobs: Dict[str, JobRecord] = {}

    def submit_job(self, req: AnalyzeRequest) -> AnalyzeResponse:
        """Validate request and spawn a background analysis job.

        Args:
            req: Analysis request containing GitHub repository URL.

        Returns:
            AnalyzeResponse containing job UUID.
        """
        is_valid, owner, repo_name, norm_url = validate_github_url(req.repository_url)
        if not is_valid:
            raise ValueError(f"Invalid repository URL: {norm_url}")

        job_id = f"job_{uuid.uuid4().hex[:12]}"
        req.repository_url = norm_url

        record = JobRecord(
            job_id=job_id,
            request=req,
            owner=owner,
            repo=repo_name,
        )
        self.jobs[job_id] = record

        # Spawn background execution if an event loop is running
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._execute_analysis_job(job_id))
        except RuntimeError:
            # Fallback when invoked from non-async context
            logger.debug(f"[JobService] No active event loop. Job {job_id} queued.")

        return AnalyzeResponse(
            job_id=job_id,
            repository_url=norm_url,
            owner=owner,
            repository_name=repo_name,
            status="QUEUED",
            created_at=record.created_at,
        )

    async def _execute_analysis_job(self, job_id: str):
        """Internal worker executing the compiled LangGraph workflow."""
        record = self.jobs.get(job_id)
        if not record:
            return

        record.status = "RUNNING"
        logger.info(f"[JobService] Initiating LangGraph workflow for job {job_id}")

        initial_state = {
            "job_id": job_id,
            "repository_url": record.request.repository_url,
            "branch": record.request.branch,
            "enable_validation": record.request.enable_validation,
            "enable_remediation": record.request.enable_remediation,
            "local_repo_path": None,
            "repository_overview": None,
            "raw_findings": [],
            "validated_findings": [],
            "risk_assessments": [],
            "remediations": [],
            "events": [],
            "status": "RUNNING",
            "error": None,
            "report": None,
        }

        try:
            # Stream execution nodes to capture events incrementally
            async for step_output in analysis_graph.astream(initial_state):
                for node_name, node_state in step_output.items():
                    if "events" in node_state and node_state["events"]:
                        for evt in node_state["events"]:
                            # Avoid appending duplicate events
                            if not any(e.event_id == evt.event_id for e in record.events):
                                record.events.append(evt)

                    if "report" in node_state and node_state["report"]:
                        record.report = node_state["report"]

                    if "status" in node_state:
                        record.status = node_state["status"]

            record.completed_at = datetime.now(timezone.utc)
            if not record.report and record.status != "FAILED":
                record.status = "COMPLETED"

            logger.info(f"[JobService] Analysis job {job_id} finalized with status: {record.status}")

        except Exception as e:
            logger.error(f"[JobService] Error in job execution {job_id}: {e}", exc_info=True)
            record.status = "FAILED"
            record.error = str(e)
            record.completed_at = datetime.now(timezone.utc)
            err_event = ExecutionEvent(
                event_id=f"evt_{uuid.uuid4().hex[:8]}",
                job_id=job_id,
                agent="System Orchestrator",
                tool="LangGraph Engine",
                status="FAILED",
                message=f"Workflow failed: {type(e).__name__} - {e}",
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                error_details=str(e),
            )
            record.events.append(err_event)

    def get_job(self, job_id: str) -> Optional[JobRecord]:
        """Retrieve job record by ID."""
        return self.jobs.get(job_id)

    def get_events(self, job_id: str) -> List[ExecutionEvent]:
        """Retrieve all real-time events emitted for a job."""
        record = self.jobs.get(job_id)
        return record.events if record else []

    def get_report(self, job_id: str) -> Optional[AnalysisReport]:
        """Retrieve complete analysis report for a job."""
        record = self.jobs.get(job_id)
        return record.report if record else None

    def get_findings(self, job_id: str) -> List[UnifiedVulnerability]:
        """Retrieve unified vulnerabilities list."""
        record = self.jobs.get(job_id)
        if record and record.report:
            return record.report.vulnerabilities
        return []


# Global service instance
job_service = JobService()
