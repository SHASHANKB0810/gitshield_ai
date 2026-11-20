"""End-to-End Security Benchmarks & Accuracy Tests for GitShield AI."""

import os
from pathlib import Path
import pytest
from backend.services.repository_service import RepositoryService
from backend.agents.detection_agent import detection_agent
from backend.agents.validation_agent import validation_agent
from backend.agents.risk_agent import risk_agent
from backend.agents.remediation_agent import remediation_agent
from backend.services.report_service import report_service


@pytest.fixture
def benchmark_repo(tmp_path) -> str:
    """Create a synthetic multi-language benchmark repo containing real vulnerabilities and safe patterns."""
    repo = tmp_path / "benchmark_repo"
    repo.mkdir()

    # 1. Real SQL Injection (Vulnerable)
    (repo / "sqli_vuln.py").write_text(
        """
def query_user(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return execute_raw(query)
""",
        encoding="utf-8",
    )

    # 2. Safe Parameterized Query (Benign / Safe)
    (repo / "sqli_safe.py").write_text(
        """
def query_user_safe(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    return cursor.execute(query, (user_id,))
""",
        encoding="utf-8",
    )

    # 3. Safe Bcrypt Hashing (Benign / Safe)
    (repo / "auth_safe.py").write_text(
        """
import bcrypt
def hash_pass(pwd):
    salt = bcrypt.gensalt(12)
    return bcrypt.hashpw(pwd.encode(), salt)
""",
        encoding="utf-8",
    )

    # 4. Hardcoded AWS Credential (Vulnerable)
    (repo / "aws_creds.py").write_text(
        """
AWS_KEY = "AKIA9999999999EXAMPLE"
""",
        encoding="utf-8",
    )

    return str(repo)


@pytest.mark.asyncio
async def test_full_security_benchmark(benchmark_repo):
    """Benchmark end-to-end multi-agent pipeline on known vulnerable and safe patterns."""
    job_id = "benchmark_eval_job"

    # Step 1: Deterministic Security Detection
    raw_findings, det_events = detection_agent.run(benchmark_repo, job_id)
    assert len(raw_findings) >= 2
    assert any("sqli_vuln.py" in f.file for f in raw_findings)
    assert any("aws_creds.py" in f.file for f in raw_findings)

    # Step 2: Multi-Agent Validation (Eliminate False Positives)
    validated, val_event = await validation_agent.run(raw_findings, job_id)
    assert len(validated) == len(raw_findings)

    # Verify that safe patterns were not confirmed as true vulnerabilities
    for v in validated:
        raw_f = next(f for f in raw_findings if f.id == v.id)
        if "sqli_safe.py" in raw_f.file or "auth_safe.py" in raw_f.file:
            assert v.validation_status == "FALSE_POSITIVE"

    # Step 3: Risk Assessment on Confirmed Issues
    risk_assessments, risk_event = await risk_agent.run(raw_findings, validated, job_id)
    assert len(risk_assessments) >= 1
    # Check that confirmed issues received CWE mapping
    for risk in risk_assessments:
        assert risk.cwe is not None
        assert risk.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    # Step 4: Remediation and Automated Rescan Verification
    remediations, remed_event = await remediation_agent.run(raw_findings, validated, job_id)
    assert len(remediations) >= 1
    for remed in remediations:
        assert len(remed.patched_code) > 0
        assert remed.verification_status in ("PASSED", "UNVERIFIABLE", "FAILED")
