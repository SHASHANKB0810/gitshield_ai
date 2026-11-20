"""Unit and integration tests for Phase 4: LangGraph Workflow & State Management."""

import pytest
from backend.graph.state import AnalysisState
from backend.graph.workflow import analysis_graph
from backend.services.job_service import job_service
from backend.api.schemas import AnalyzeRequest


@pytest.mark.asyncio
async def test_langgraph_workflow_execution():
    """Verify end-to-end execution of the LangGraph state machine with an invalid/mock URL."""
    initial_state = {
        "job_id": "test_graph_job",
        "repository_url": "https://github.com/mock-org/non-existent-repo-12345",
        "branch": None,
        "enable_validation": True,
        "enable_remediation": True,
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

    # Execute graph
    final_output = await analysis_graph.ainvoke(initial_state)

    assert final_output is not None
    assert "report" in final_output
    assert final_output["status"] in ("COMPLETED", "FAILED")
    assert len(final_output["events"]) >= 1


@pytest.mark.asyncio
async def test_job_service_submission():
    """Verify job submission and job registry."""
    req = AnalyzeRequest(
        repository_url="https://github.com/fastapi/fastapi",
        enable_validation=True,
        enable_remediation=True,
    )
    resp = job_service.submit_job(req)

    assert resp.job_id.startswith("job_")
    assert resp.owner == "fastapi"
    assert resp.repository_name == "fastapi"
    assert resp.status in ("QUEUED", "RUNNING")

    # Check job lookup
    record = job_service.get_job(resp.job_id)
    assert record is not None
    assert record.owner == "fastapi"
