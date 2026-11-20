"""Unit tests for Phase 3: Specialized Multi-Agent System."""

import pytest
from backend.api.schemas import RawFinding, ValidatedFinding, RiskAssessment
from backend.agents.detection_agent import detection_agent
from backend.agents.validation_agent import validation_agent
from backend.agents.risk_agent import risk_agent
from backend.agents.remediation_agent import remediation_agent


@pytest.fixture
def sample_findings():
    """Create sample raw findings for agent testing."""
    return [
        RawFinding(
            id="VULN-001",
            title="Potential SQL Injection",
            category="Injection",
            file="app/db.py",
            line=12,
            tool="Bandit",
            description="Unsafe SQL query formatting",
            evidence="query = f'SELECT * FROM users WHERE id = {user_id}'\ncursor.execute(query)",
            severity="HIGH",
            confidence=0.9,
        ),
        RawFinding(
            id="VULN-002",
            title="Hardcoded Password Hash",
            category="Secrets & Credentials",
            file="app/auth.py",
            line=25,
            tool="Bandit",
            description="bcrypt password hashing",
            evidence="password_hash = bcrypt.hashpw(password.encode(), salt)",
            severity="MEDIUM",
            confidence=0.7,
        ),
    ]


@pytest.mark.asyncio
async def test_validation_agent_heuristic_fallback(sample_findings):
    """Verify validation agent correctly processes findings and identifies false positives."""
    validated, event = await validation_agent.run(sample_findings, job_id="test_val_job")

    assert len(validated) == 2
    assert event.status == "COMPLETED"

    val_map = {v.id: v for v in validated}
    # VULN-001 should be confirmed or likely
    assert val_map["VULN-001"].validation_status in ("CONFIRMED", "LIKELY")
    # VULN-002 (bcrypt) should be detected as false positive
    assert val_map["VULN-002"].validation_status == "FALSE_POSITIVE"


@pytest.mark.asyncio
async def test_risk_agent_evaluation(sample_findings):
    """Verify risk agent assesses confirmed vulnerabilities."""
    validated = [
        ValidatedFinding(
            id="VULN-001",
            validation_status="CONFIRMED",
            confidence=0.95,
            reasoning="Unsanitized user input reaches SQL query.",
        )
    ]

    assessments, event = await risk_agent.run(
        raw_findings=sample_findings,
        validated_findings=validated,
        job_id="test_risk_job",
    )

    assert len(assessments) == 1
    assert event.status == "COMPLETED"
    assert assessments[0].id == "VULN-001"
    assert assessments[0].severity in ("CRITICAL", "HIGH", "MEDIUM")
    assert assessments[0].cwe == "CWE-89"


@pytest.mark.asyncio
async def test_remediation_agent_patch_and_verification(sample_findings):
    """Verify remediation agent generates patches and runs verification pass."""
    validated = [
        ValidatedFinding(
            id="VULN-001",
            validation_status="CONFIRMED",
            confidence=0.95,
            reasoning="SQL injection confirmed.",
        )
    ]

    remediations, event = await remediation_agent.run(
        raw_findings=sample_findings,
        validated_findings=validated,
        job_id="test_remed_job",
    )

    assert len(remediations) == 1
    assert event.status == "COMPLETED"
    assert remediations[0].id == "VULN-001"
    assert "parameterized" in remediations[0].recommended_fix.lower() or "execute" in remediations[0].patched_code
