"""LangGraph Shared State Schema.

Defines the typed dictionary and data structures passed between
all 5 specialized agents in the GitShield AI analysis graph.
"""

from typing import Annotated, Dict, List, Optional, TypedDict
import operator
from backend.api.schemas import (
    RepositoryOverview,
    RawFinding,
    ValidatedFinding,
    RiskAssessment,
    RemediationResult,
    ExecutionEvent,
    AnalysisReport,
)


class AnalysisState(TypedDict):
    """Shared state object for LangGraph execution."""

    # Job Configuration
    job_id: str
    repository_url: str
    branch: Optional[str]
    enable_validation: bool
    enable_remediation: bool

    # Filesystem & Ingestion
    local_repo_path: Optional[str]
    repository_overview: Optional[RepositoryOverview]

    # Findings Pipeline
    raw_findings: List[RawFinding]
    validated_findings: List[ValidatedFinding]
    risk_assessments: List[RiskAssessment]
    remediations: List[RemediationResult]

    # Telemetry Events (Appended via operator.add)
    events: Annotated[List[ExecutionEvent], operator.add]

    # Execution State
    status: str  # QUEUED, RUNNING, COMPLETED, FAILED
    error: Optional[str]
    report: Optional[AnalysisReport]
