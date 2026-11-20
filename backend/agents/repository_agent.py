"""Agent 1: Repository Analysis Agent.

Safely retrieves repository code, maps directory layout, identifies programming
languages, frameworks, and key target files.
"""

from datetime import datetime, timezone
import uuid
from typing import Dict, Any, Tuple
from backend.services.repository_service import repository_service
from backend.api.schemas import RepositoryOverview, ExecutionEvent
from backend.core.logging import logger


class RepositoryAgent:
    """Agent responsible for repository ingestion, file mapping, and tech stack discovery."""

    def __init__(self):
        self.service = repository_service

    def run(
        self,
        repository_url: str,
        job_id: str,
        branch: str = None,
    ) -> Tuple[bool, RepositoryOverview, str, ExecutionEvent]:
        """Execute repository retrieval and technology inspection.

        Returns:
            Tuple of (success: bool, overview: RepositoryOverview, local_path: str, event: ExecutionEvent)
        """
        started_at = datetime.now(timezone.utc)
        logger.info(f"[Agent 1: RepositoryAgent] Starting repository analysis for: {repository_url}")

        success, local_path_or_err, repo_name = self.service.clone_repository(
            repository_url=repository_url,
            job_id=job_id,
            branch=branch,
        )

        if not success:
            event = ExecutionEvent(
                event_id=f"evt_{uuid.uuid4().hex[:8]}",
                job_id=job_id,
                agent="Repository Analysis Agent",
                tool="Git Ingestion Service",
                status="FAILED",
                message=f"Failed to ingest repository: {local_path_or_err}",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                error_details=local_path_or_err,
            )
            empty_overview = RepositoryOverview(
                repository_name=repo_name or "unknown",
                owner="unknown",
                url=repository_url,
            )
            return False, empty_overview, "", event

        # Inspect repository
        overview = self.service.inspect_repository(
            repo_dir=local_path_or_err,
            repo_name=repo_name,
            owner=repository_url.split("github.com/")[-1].split("/")[0],
            url=repository_url,
        )

        completed_at = datetime.now(timezone.utc)
        lang_summary = ", ".join(overview.languages[:3]) if overview.languages else "Unknown"
        event = ExecutionEvent(
            event_id=f"evt_{uuid.uuid4().hex[:8]}",
            job_id=job_id,
            agent="Repository Analysis Agent",
            tool="Repository Analyzer",
            status="COMPLETED",
            message=f"Repository mapped ({overview.total_files_analyzed} files, {lang_summary}).",
            started_at=started_at,
            completed_at=completed_at,
            findings_count=len(overview.important_files),
        )

        logger.info(f"[Agent 1: RepositoryAgent] Finished. Discovered {overview.total_files_analyzed} files.")
        return True, overview, local_path_or_err, event


# Singleton instance
repository_agent = RepositoryAgent()
