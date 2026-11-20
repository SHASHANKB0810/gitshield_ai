"""Base Static Security Scanner Interface.

Defines the contract, execution event recording, and common utilities
for all deterministic security scanners.
"""

from abc import ABC, abstractmethod
from datetime import datetime
import uuid
from typing import List, Optional, Tuple
from backend.api.schemas import RawFinding, ExecutionEvent
from backend.core.logging import logger


class BaseScanner(ABC):
    """Abstract base class for deterministic static security scanners."""

    def __init__(self, name: str, timeout_seconds: int = 60):
        self.name = name
        self.timeout_seconds = timeout_seconds

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the scanner CLI or underlying engine is installed and available."""
        pass

    @abstractmethod
    def scan(self, repo_path: str, job_id: str) -> Tuple[List[RawFinding], ExecutionEvent]:
        """Execute the security scanner and return normalized findings and telemetry.

        Args:
            repo_path: Path to the target local repository root.
            job_id: ID of the active analysis job.

        Returns:
            Tuple of (findings: List[RawFinding], event: ExecutionEvent)
        """
        pass

    def create_event(
        self,
        job_id: str,
        status: str,
        message: str,
        started_at: datetime,
        completed_at: Optional[datetime] = None,
        findings_count: Optional[int] = None,
        error_details: Optional[str] = None,
    ) -> ExecutionEvent:
        """Create a standardized execution event for this scanner."""
        return ExecutionEvent(
            event_id=f"evt_{uuid.uuid4().hex[:8]}",
            job_id=job_id,
            agent="Security Detection Agent",
            tool=self.name,
            status=status,  # type: ignore[arg-type]
            message=message,
            started_at=started_at,
            completed_at=completed_at,
            findings_count=findings_count,
            error_details=error_details,
        )

    def extract_snippet(self, file_path: str, line_num: Optional[int], window: int = 4) -> str:
        """Extract sanitized surrounding code context around a given line number."""
        if not line_num or line_num <= 0:
            return ""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            total_lines = len(lines)
            start_line = max(0, line_num - 1 - window)
            end_line = min(total_lines, line_num + window)

            context_lines = []
            for idx in range(start_line, end_line):
                curr_line_num = idx + 1
                prefix = ">" if curr_line_num == line_num else " "
                context_lines.append(f"{prefix} {curr_line_num:4d} | {lines[idx].rstrip()}")

            return "\n".join(context_lines)
        except Exception as e:
            logger.debug(f"Failed to read snippet for {file_path}:{line_num}: {e}")
            return ""
