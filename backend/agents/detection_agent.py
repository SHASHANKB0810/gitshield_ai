"""Agent 2: Security Detection Agent.

Orchestrates deterministic static security scanners (Semgrep, Bandit, Gitleaks, pip-audit),
normalizes outputs, removes duplicates, and records execution events.
"""

from datetime import datetime, timezone
import uuid
from typing import List, Tuple
from backend.api.schemas import RawFinding, ExecutionEvent
from backend.scanners.bandit_scanner import BanditScanner
from backend.scanners.semgrep_scanner import SemgrepScanner
from backend.scanners.gitleaks_scanner import GitleaksScanner
from backend.scanners.dependency_scanner import DependencyScanner
from backend.core.logging import logger


class DetectionAgent:
    """Agent that coordinates static security scanner execution and normalizes raw findings."""

    def __init__(self):
        self.scanners = [
            BanditScanner(),
            SemgrepScanner(),
            GitleaksScanner(),
            DependencyScanner(),
        ]

    def run(self, repo_path: str, job_id: str) -> Tuple[List[RawFinding], List[ExecutionEvent]]:
        """Run all configured scanners against the local repository directory.

        Args:
            repo_path: Path to cloned repository directory.
            job_id: Analysis job identifier.

        Returns:
            Tuple of (deduplicated_findings: List[RawFinding], events: List[ExecutionEvent])
        """
        logger.info(f"[Agent 2: DetectionAgent] Starting static security scan on {repo_path}")
        all_findings: List[RawFinding] = []
        events: List[ExecutionEvent] = []

        for scanner in self.scanners:
            logger.info(f"[Agent 2: DetectionAgent] Executing scanner: {scanner.name}")
            try:
                findings, event = scanner.scan(repo_path, job_id)
                all_findings.extend(findings)
                events.append(event)
            except Exception as e:
                logger.error(f"[Agent 2: DetectionAgent] Scanner {scanner.name} failed: {e}")
                err_event = ExecutionEvent(
                    event_id=f"evt_{uuid.uuid4().hex[:8]}",
                    job_id=job_id,
                    agent="Security Detection Agent",
                    tool=scanner.name,
                    status="FAILED",
                    message=f"{scanner.name} scan encountered an unhandled error: {type(e).__name__}",
                    started_at=datetime.now(timezone.utc),
                    completed_at=datetime.now(timezone.utc),
                    error_details=str(e),
                )
                events.append(err_event)

        # Deduplicate findings with matching file and line number
        deduped_findings = self._deduplicate_findings(all_findings)
        logger.info(
            f"[Agent 2: DetectionAgent] Completed. Discovered {len(all_findings)} raw alerts, "
            f"normalized to {len(deduped_findings)} distinct findings."
        )

        return deduped_findings, events

    def _deduplicate_findings(self, findings: List[RawFinding]) -> List[RawFinding]:
        """Merge identical file:line reports from multiple scanners."""
        seen_keys = set()
        unique_findings = []

        for f in findings:
            # Group by file and line number (or title if line number is None)
            key = (f.file, f.line, f.category) if f.line else (f.file, f.title)
            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(f)

        return unique_findings


# Singleton instance
detection_agent = DetectionAgent()
