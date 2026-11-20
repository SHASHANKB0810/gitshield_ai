"""API Schemas and Data Models.

Defines Pydantic request and response models for all API endpoints,
telemetry events, scanner findings, validation results, and reports.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


# -----------------------------------------------------------------------------
# Base System & Health Schemas
# -----------------------------------------------------------------------------

class HealthResponse(BaseModel):
    """Health check response schema."""
    status: str = Field(default="healthy", description="Service health state")
    app_env: str = Field(..., description="Running environment")
    version: str = Field(default="1.0.0", description="GitShield AI version")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class LLMStatusResponse(BaseModel):
    """LLM gateway configuration and connectivity status schema."""
    status: str = Field(..., description="Connection status: HEALTHY, UNCONFIGURED, ERROR, TIMEOUT")
    provider: str = Field(..., description="Configured LLM provider")
    model: str = Field(..., description="Configured model identifier")
    base_url: str = Field(..., description="Gateway Base URL")
    masked_key: Optional[str] = Field(None, description="Masked API credential preview")
    message: Optional[str] = Field(None, description="Diagnostic status message")
    latency_ms: Optional[float] = Field(None, description="Round-trip latency in milliseconds")
    response_sample: Optional[str] = Field(None, description="Minimal inference output sample")


# -----------------------------------------------------------------------------
# Repository Analysis & Job Schemas
# -----------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    """Analysis request payload."""
    repository_url: str = Field(..., description="Full GitHub HTTPS URL (e.g. https://github.com/owner/repo)")
    branch: Optional[str] = Field(default=None, description="Optional target git branch")
    enable_validation: bool = Field(default=True, description="Enable Claude false-positive validation")
    enable_remediation: bool = Field(default=True, description="Enable patch generation and verification")


class AnalyzeResponse(BaseModel):
    """Immediate response after initiating an analysis job."""
    job_id: str = Field(..., description="Unique UUID tracking the analysis job")
    repository_url: str = Field(..., description="Normalized repository URL")
    owner: str = Field(..., description="Repository owner")
    repository_name: str = Field(..., description="Repository name")
    status: Literal["QUEUED", "RUNNING", "COMPLETED", "FAILED"] = Field(
        default="QUEUED", description="Initial job status"
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# -----------------------------------------------------------------------------
# Execution Telemetry & Event Schemas
# -----------------------------------------------------------------------------

class ExecutionEvent(BaseModel):
    """Real-time operational execution event emitted by an agent or tool."""
    event_id: str = Field(..., description="Unique event identifier")
    job_id: str = Field(..., description="Associated analysis job ID")
    agent: str = Field(..., description="Logical agent name (e.g. Security Detection Agent)")
    tool: Optional[str] = Field(None, description="Specific tool executed (e.g. Semgrep, Bandit)")
    status: Literal["PENDING", "RUNNING", "COMPLETED", "FAILED", "SKIPPED"] = Field(
        ..., description="Execution status of this operation"
    )
    message: str = Field(..., description="Short descriptive progress message")
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = Field(None)
    findings_count: Optional[int] = Field(None, description="Count of findings discovered")
    error_details: Optional[str] = Field(None, description="Error diagnostics if failed")


# -----------------------------------------------------------------------------
# Findings & Security Data Models
# -----------------------------------------------------------------------------

class RawFinding(BaseModel):
    """Normalized raw finding produced by static security scanners."""
    id: str = Field(..., description="Finding identifier, e.g. VULN-001")
    title: str = Field(..., description="Concise vulnerability title")
    category: str = Field(default="Other", description="Security category, e.g. Injection, Secrets, Dependencies")
    file: str = Field(..., description="Relative file path within repository")
    line: Optional[int] = Field(None, description="1-based line number")
    tool: str = Field(..., description="Detection tool name: Semgrep, Bandit, Gitleaks, pip-audit")
    description: str = Field(..., description="Technical finding description")
    evidence: str = Field(..., description="Sanitized code snippet or context")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] = Field(
        default="MEDIUM", description="Initial scanner severity"
    )
    confidence: float = Field(default=0.8, ge=0.0, le=1.0, description="Estimated confidence score")


class ValidatedFinding(BaseModel):
    """Finding augmented with LLM false-positive analysis and validation."""
    id: str = Field(..., description="Matches RawFinding ID")
    validation_status: Literal["CONFIRMED", "LIKELY", "FALSE_POSITIVE", "NEEDS_MANUAL_REVIEW"] = Field(
        ..., description="Validation outcome"
    )
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    reasoning: str = Field(..., description="Step-by-step reasoning explaining the determination")
    supporting_evidence: List[str] = Field(default_factory=list, description="Relevant code or context references")
    false_positive_reason: Optional[str] = Field(None, description="Reason if marked as false positive")


class RiskAssessment(BaseModel):
    """Contextual risk evaluation for a validated vulnerability."""
    id: str = Field(..., description="Matches finding ID")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] = Field(...)
    cwe: Optional[str] = Field(None, description="CWE identifier, e.g. CWE-89")
    owasp_category: Optional[str] = Field(None, description="OWASP Top 10 category, e.g. A03:2021-Injection")
    exploitability: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(default="MEDIUM")
    potential_impact: str = Field(..., description="Business and technical impact description")
    priority: int = Field(default=3, ge=1, le=5, description="Remediation priority (1=Urgent, 5=Low)")
    reasoning: str = Field(..., description="Justification for risk score")


class RemediationResult(BaseModel):
    """Recommended code patch and verification status."""
    id: str = Field(..., description="Matches finding ID")
    recommended_fix: str = Field(..., description="Summary of recommended remediation strategy")
    original_code: str = Field(..., description="Original vulnerable code snippet")
    patched_code: str = Field(..., description="Suggested secure replacement code")
    explanation: str = Field(..., description="Detailed explanation of how the patch resolves the issue")
    verification_status: Literal["PASSED", "FAILED", "UNVERIFIABLE", "SKIPPED"] = Field(
        default="UNVERIFIABLE", description="Status of local automated rescan verification"
    )
    verification_details: List[str] = Field(default_factory=list)
    regression_risks: List[str] = Field(default_factory=list, description="Potential backward compatibility risks")


class UnifiedVulnerability(BaseModel):
    """Complete consolidated vulnerability object combining finding, validation, risk, and patch."""
    id: str
    title: str
    category: str
    file: str
    line: Optional[int] = None
    tool: str
    description: str
    evidence: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    validation_status: Literal["CONFIRMED", "LIKELY", "FALSE_POSITIVE", "NEEDS_MANUAL_REVIEW"]
    confidence: float
    validation_reasoning: Optional[str] = None
    cwe: Optional[str] = None
    owasp_category: Optional[str] = None
    potential_impact: Optional[str] = None
    priority: int = 3
    remediation: Optional[RemediationResult] = None


class RepositoryOverview(BaseModel):
    """Metadata and technology breakdown of the analyzed repository."""
    repository_name: str
    owner: str
    url: str
    default_branch: str = "main"
    languages: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    dependencies_count: int = 0
    total_files_analyzed: int = 0
    important_files: List[str] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    """Comprehensive final analysis report."""
    job_id: str
    repository: RepositoryOverview
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    total_findings_count: int = 0
    confirmed_count: int = 0
    likely_count: int = 0
    false_positive_count: int = 0
    manual_review_count: int = 0
    severity_distribution: Dict[str, int] = Field(default_factory=dict)
    category_distribution: Dict[str, int] = Field(default_factory=dict)
    vulnerabilities: List[UnifiedVulnerability] = Field(default_factory=list)
    events: List[ExecutionEvent] = Field(default_factory=list)
