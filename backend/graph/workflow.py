"""LangGraph Multi-Agent Security Analysis Workflow.

Assembles and compiles the StateGraph coordinating all five agents
with conditional routing, progress tracking, and error recovery.
"""

from typing import Literal
from langgraph.graph import StateGraph, END
from backend.graph.state import AnalysisState
from backend.graph.nodes import (
    repository_analysis_node,
    security_detection_node,
    vulnerability_validation_node,
    risk_assessment_node,
    remediation_verification_node,
    report_generation_node,
)
from backend.core.logging import logger


def route_after_ingestion(state: AnalysisState) -> Literal["security_detection", "report_generation"]:
    """Conditional router after repository ingestion."""
    if state.get("status") == "FAILED" or not state.get("local_repo_path"):
        logger.warning("[Graph Routing] Repository ingestion failed. Skipping to report generation.")
        return "report_generation"
    return "security_detection"


def route_after_detection(state: AnalysisState) -> Literal["vulnerability_validation", "report_generation"]:
    """Conditional router after security detection."""
    raw_findings = state.get("raw_findings", [])
    if not raw_findings:
        logger.info("[Graph Routing] Zero raw findings discovered. Skipping directly to report.")
        return "report_generation"
    return "vulnerability_validation"


def create_analysis_workflow() -> StateGraph:
    """Build and compile the multi-agent security analysis LangGraph workflow."""
    workflow = StateGraph(AnalysisState)

    # 1. Register Graph Nodes
    workflow.add_node("repository_analysis", repository_analysis_node)
    workflow.add_node("security_detection", security_detection_node)
    workflow.add_node("vulnerability_validation", vulnerability_validation_node)
    workflow.add_node("risk_assessment", risk_assessment_node)
    workflow.add_node("remediation_verification", remediation_verification_node)
    workflow.add_node("report_generation", report_generation_node)

    # 2. Set Entrypoint
    workflow.set_entry_point("repository_analysis")

    # 3. Define Conditional & Linear Edges
    workflow.add_conditional_edges(
        "repository_analysis",
        route_after_ingestion,
        {
            "security_detection": "security_detection",
            "report_generation": "report_generation",
        },
    )

    workflow.add_conditional_edges(
        "security_detection",
        route_after_detection,
        {
            "vulnerability_validation": "vulnerability_validation",
            "report_generation": "report_generation",
        },
    )

    workflow.add_edge("vulnerability_validation", "risk_assessment")
    workflow.add_edge("risk_assessment", "remediation_verification")
    workflow.add_edge("remediation_verification", "report_generation")
    workflow.add_edge("report_generation", END)

    return workflow.compile()


# Compile global workflow runner
analysis_graph = create_analysis_workflow()
