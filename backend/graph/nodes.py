"""LangGraph Workflow Nodes.

Encapsulates the five specialized agents into callable LangGraph node functions.
"""

import asyncio
from datetime import datetime, timezone
import uuid
from typing import Dict, Any, List
from backend.graph.state import AnalysisState
from backend.agents.repository_agent import repository_agent
from backend.agents.detection_agent import detection_agent
from backend.agents.validation_agent import validation_agent
from backend.agents.risk_agent import risk_agent
from backend.agents.remediation_agent import remediation_agent
from backend.services.repository_service import repository_service
from backend.api.schemas import (
    UnifiedVulnerability,
    AnalysisReport,
    ExecutionEvent,
)
from backend.core.logging import logger


async def repository_analysis_node(state: AnalysisState) -> Dict[str, Any]:
    """Node 1: Clone and inspect repository structure."""
    job_id = state["job_id"]
    repo_url = state["repository_url"]
    branch = state.get("branch")

    logger.info(f"[Graph Node 1] Executing Repository Analysis for {repo_url}")
    success, overview, local_path, event = await asyncio.to_thread(
        repository_agent.run,
        repository_url=repo_url,
        job_id=job_id,
        branch=branch,
    )

    if not success:
        return {
            "local_repo_path": None,
            "repository_overview": overview,
            "status": "FAILED",
            "error": event.message,
            "events": [event],
        }

    return {
        "local_repo_path": local_path,
        "repository_overview": overview,
        "status": "RUNNING",
        "events": [event],
    }


async def security_detection_node(state: AnalysisState) -> Dict[str, Any]:
    """Node 2: Run deterministic static security scanners."""
    job_id = state["job_id"]
    local_path = state.get("local_repo_path")

    if not local_path or state.get("status") == "FAILED":
        return {"raw_findings": [], "events": []}

    logger.info(f"[Graph Node 2] Executing Static Security Detection on {local_path}")
    raw_findings, events = await asyncio.to_thread(
        detection_agent.run,
        repo_path=local_path,
        job_id=job_id,
    )

    return {
        "raw_findings": raw_findings,
        "events": events,
    }


async def vulnerability_validation_node(state: AnalysisState) -> Dict[str, Any]:
    """Node 3: Validate raw findings using Claude Sonnet 5.5."""
    job_id = state["job_id"]
    raw_findings = state.get("raw_findings", [])
    enable_val = state.get("enable_validation", True)

    if not raw_findings or not enable_val or state.get("status") == "FAILED":
        return {"validated_findings": [], "events": []}

    logger.info(f"[Graph Node 3] Validating {len(raw_findings)} raw findings with Claude Sonnet 5.5")
    validated_findings, event = await validation_agent.run(
        findings=raw_findings,
        job_id=job_id,
    )

    return {
        "validated_findings": validated_findings,
        "events": [event],
    }


async def risk_assessment_node(state: AnalysisState) -> Dict[str, Any]:
    """Node 4: Contextual risk and impact assessment."""
    job_id = state["job_id"]
    raw_findings = state.get("raw_findings", [])
    validated_findings = state.get("validated_findings", [])

    if not validated_findings or state.get("status") == "FAILED":
        return {"risk_assessments": [], "events": []}

    logger.info(f"[Graph Node 4] Performing Risk Assessment")
    risk_assessments, event = await risk_agent.run(
        raw_findings=raw_findings,
        validated_findings=validated_findings,
        job_id=job_id,
    )

    return {
        "risk_assessments": risk_assessments,
        "events": [event],
    }


async def remediation_verification_node(state: AnalysisState) -> Dict[str, Any]:
    """Node 5: Patch generation and rescan verification."""
    job_id = state["job_id"]
    raw_findings = state.get("raw_findings", [])
    validated_findings = state.get("validated_findings", [])
    enable_remed = state.get("enable_remediation", True)

    if not validated_findings or not enable_remed or state.get("status") == "FAILED":
        return {"remediations": [], "events": []}

    logger.info(f"[Graph Node 5] Generating Patches & Local Verification")
    remediations, event = await remediation_agent.run(
        raw_findings=raw_findings,
        validated_findings=validated_findings,
        job_id=job_id,
    )

    return {
        "remediations": remediations,
        "events": [event],
    }


async def report_generation_node(state: AnalysisState) -> Dict[str, Any]:
    """Node 6: Synthesize final unified report and clean up temp workspace."""
    job_id = state["job_id"]
    local_path = state.get("local_repo_path")
    overview = state.get("repository_overview")
    raw_findings = state.get("raw_findings", [])
    validated_findings = state.get("validated_findings", [])
    risk_assessments = state.get("risk_assessments", [])
    remediations = state.get("remediations", [])
    events = state.get("events", [])

    logger.info(f"[Graph Node 6] Synthesizing Final Security Report for job {job_id}")

    val_map = {v.id: v for v in validated_findings}
    risk_map = {r.id: r for r in risk_assessments}
    remed_map = {rm.id: rm for rm in remediations}

    unified_vulns: List[UnifiedVulnerability] = []
    severity_dist: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    category_dist: Dict[str, int] = {}

    confirmed_cnt = 0
    likely_cnt = 0
    fp_cnt = 0
    manual_cnt = 0

    for raw in raw_findings:
        val = val_map.get(raw.id)
        risk = risk_map.get(raw.id)
        remed = remed_map.get(raw.id)

        val_status = val.validation_status if val else "LIKELY"
        if val_status == "CONFIRMED":
            confirmed_cnt += 1
        elif val_status == "LIKELY":
            likely_cnt += 1
        elif val_status == "FALSE_POSITIVE":
            fp_cnt += 1
        elif val_status == "NEEDS_MANUAL_REVIEW":
            manual_cnt += 1

        final_sev = risk.severity if risk else raw.severity
        severity_dist[final_sev] = severity_dist.get(final_sev, 0) + 1
        category_dist[raw.category] = category_dist.get(raw.category, 0) + 1

        unified_vulns.append(
            UnifiedVulnerability(
                id=raw.id,
                title=raw.title,
                category=raw.category,
                file=raw.file,
                line=raw.line,
                tool=raw.tool,
                description=raw.description,
                evidence=raw.evidence,
                severity=final_sev,
                validation_status=val_status,  # type: ignore[arg-type]
                confidence=val.confidence if val else raw.confidence,
                validation_reasoning=val.reasoning if val else None,
                cwe=risk.cwe if risk else None,
                owasp_category=risk.owasp_category if risk else None,
                potential_impact=risk.potential_impact if risk else None,
                priority=risk.priority if risk else 3,
                remediation=remed,
            )
        )

    # Clean up local repository directory safely in background thread
    if local_path:
        await asyncio.to_thread(repository_service.cleanup_repository, local_path)

    report_event = ExecutionEvent(
        event_id=f"evt_{uuid.uuid4().hex[:8]}",
        job_id=job_id,
        agent="Report Generation Agent",
        tool="GitShield Report Synthesizer",
        status="COMPLETED",
        message=f"Analysis report synthesized. {len(unified_vulns)} finding(s) cataloged.",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        findings_count=len(unified_vulns),
    )

    report = AnalysisReport(
        job_id=job_id,
        repository=overview or state["repository_overview"],
        status="COMPLETED" if state.get("status") != "FAILED" else "FAILED",
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        total_findings_count=len(unified_vulns),
        confirmed_count=confirmed_cnt,
        likely_count=likely_cnt,
        false_positive_count=fp_cnt,
        manual_review_count=manual_cnt,
        severity_distribution=severity_dist,
        category_distribution=category_dist,
        vulnerabilities=unified_vulns,
        events=events + [report_event],
    )

    return {
        "status": "COMPLETED" if state.get("status") != "FAILED" else "FAILED",
        "report": report,
        "events": [report_event],
    }
