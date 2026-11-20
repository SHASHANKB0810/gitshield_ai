"""Integration tests for Phase 5: FastAPI REST API Endpoints."""

import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.job_service import job_service
from backend.api.schemas import (
    AnalysisReport,
    RepositoryOverview,
    UnifiedVulnerability,
    ExecutionEvent,
)
from datetime import datetime, timezone

client = TestClient(app)


def test_health_endpoint():
    """Verify health check response."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_url_validation_endpoint():
    """Verify URL validation endpoint with valid and invalid URLs."""
    resp = client.post("/api/v1/validate-url", json={"url": "https://github.com/fastapi/fastapi"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["owner"] == "fastapi"

    resp = client.post("/api/v1/validate-url", json={"url": "http://insecure.url"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False


def test_analysis_submission_and_polling():
    """Verify POST /api/v1/analyze and status retrieval."""
    resp = client.post(
        "/api/v1/analyze",
        json={"repository_url": "https://github.com/owner/sample-repo"},
    )
    assert resp.status_code == 202
    data = resp.json()
    assert "job_id" in data
    job_id = data["job_id"]

    # Poll status
    status_resp = client.get(f"/api/v1/analyze/{job_id}")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["job_id"] == job_id
    assert status_data["status"] in ("QUEUED", "RUNNING", "COMPLETED", "FAILED")

    # Get events
    events_resp = client.get(f"/api/v1/events/{job_id}")
    assert events_resp.status_code == 200
    assert isinstance(events_resp.json(), list)


def test_report_and_download_endpoints():
    """Verify report retrieval and markdown/json file downloads."""
    # Seed a mock job report
    job_id = "test_report_job_123"
    overview = RepositoryOverview(
        repository_name="sample-project",
        owner="test-owner",
        url="https://github.com/test-owner/sample-project",
        languages=["Python"],
        frameworks=["FastAPI"],
        dependencies_count=10,
        total_files_analyzed=15,
    )
    vuln = UnifiedVulnerability(
        id="VULN-001",
        title="SQL Injection",
        category="Injection",
        file="app/db.py",
        line=10,
        tool="Bandit",
        description="SQL injection in db query",
        evidence="cursor.execute(f'SELECT {user}')",
        severity="HIGH",
        validation_status="CONFIRMED",
        confidence=0.95,
        cwe="CWE-89",
    )
    report = AnalysisReport(
        job_id=job_id,
        repository=overview,
        status="COMPLETED",
        created_at=datetime.now(timezone.utc),
        total_findings_count=1,
        confirmed_count=1,
        likely_count=0,
        false_positive_count=0,
        manual_review_count=0,
        severity_distribution={"HIGH": 1},
        category_distribution={"Injection": 1},
        vulnerabilities=[vuln],
        events=[],
    )

    # Populate job service record
    from backend.services.job_service import JobRecord
    from backend.api.schemas import AnalyzeRequest
    record = JobRecord(
        job_id=job_id,
        request=AnalyzeRequest(repository_url=overview.url),
        owner=overview.owner,
        repo=overview.repository_name,
    )
    record.status = "COMPLETED"
    record.report = report
    job_service.jobs[job_id] = record

    # Test report endpoint
    rep_resp = client.get(f"/api/v1/report/{job_id}")
    assert rep_resp.status_code == 200
    assert rep_resp.json()["total_findings_count"] == 1

    # Test findings query endpoint
    findings_resp = client.get(f"/api/v1/findings/{job_id}?severity=HIGH")
    assert findings_resp.status_code == 200
    assert len(findings_resp.json()) == 1

    # Test markdown download
    md_resp = client.get(f"/api/v1/report/{job_id}/markdown")
    assert md_resp.status_code == 200
    assert "GitShield AI" in md_resp.text
    assert "SQL Injection" in md_resp.text

    # Test json download
    json_resp = client.get(f"/api/v1/report/{job_id}/json")
    assert json_resp.status_code == 200
    assert "sample-project" in json_resp.text
