"""Agent 4: Risk Assessment Agent.

Evaluates exploitability, blast radius, CWE, OWASP Top 10 categories,
and assigns prioritized risk rankings using Claude Sonnet 5.5.
"""

from datetime import datetime, timezone
import uuid
from typing import List, Optional, Tuple
from pydantic import BaseModel, Field
from langchain_core.messages import SystemMessage, HumanMessage

from backend.api.schemas import RawFinding, ValidatedFinding, RiskAssessment, ExecutionEvent
from backend.agents.prompts.risk_prompt import RISK_ASSESSMENT_SYSTEM_PROMPT
from backend.core.llm_factory import LLMFactory
from backend.core.logging import logger
from backend.core.config import settings


class RiskOutput(BaseModel):
    """Structured container for risk assessment outcomes."""
    assessments: List[RiskAssessment] = Field(
        default_factory=list,
        description="List of contextual risk evaluations",
    )


class RiskAgent:
    """Agent responsible for threat modeling, CWE/OWASP classification, and risk prioritization."""

    def __init__(self):
        self.system_prompt = RISK_ASSESSMENT_SYSTEM_PROMPT

    async def run(
        self,
        raw_findings: List[RawFinding],
        validated_findings: List[ValidatedFinding],
        job_id: str,
    ) -> Tuple[List[RiskAssessment], ExecutionEvent]:
        """Perform risk assessment on confirmed/likely findings.

        Returns:
            Tuple of (assessments: List[RiskAssessment], event: ExecutionEvent)
        """
        started_at = datetime.now(timezone.utc)
        logger.info(f"[Agent 4: RiskAgent] Assessing risk for findings.")

        # Filter for findings that require risk evaluation
        active_validated = [
            v for v in validated_findings
            if v.validation_status in ("CONFIRMED", "LIKELY", "NEEDS_MANUAL_REVIEW")
        ]
        raw_map = {f.id: f for f in raw_findings}

        if not active_validated:
            event = ExecutionEvent(
                event_id=f"evt_{uuid.uuid4().hex[:8]}",
                job_id=job_id,
                agent="Risk Assessment Agent",
                tool=f"Claude Sonnet 5.5 ({settings.LLM_PROVIDER})",
                status="COMPLETED",
                message="No actionable vulnerabilities requiring risk assessment.",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                findings_count=0,
            )
            return [], event

        if not settings.LLM_API_KEY:
            logger.warning("[Agent 4: RiskAgent] LLM API key not set. Using heuristic risk scoring.")
            return self._heuristic_fallback(active_validated, raw_map, job_id, started_at)

        try:
            llm = LLMFactory.get_chat_model(temperature=0.0)
            structured_llm = llm.with_structured_output(RiskOutput)

            items_payload = []
            for v in active_validated:
                raw_f = raw_map.get(v.id)
                if not raw_f:
                    continue
                items_payload.append(
                    f"ID: {v.id}\n"
                    f"Title: {raw_f.title}\n"
                    f"Category: {raw_f.category}\n"
                    f"Location: {raw_f.file}:{raw_f.line or 'N/A'}\n"
                    f"Scanner Description: {raw_f.description}\n"
                    f"Validation Status: {v.validation_status} (Reasoning: {v.reasoning})\n"
                )

            prompt_content = (
                "Please evaluate the risk, CWE identifier, OWASP Top 10 category, severity, and remediation priority "
                "for the following confirmed or likely security vulnerabilities:\n\n"
                + "\n---\n".join(items_payload)
            )

            response: RiskOutput = await structured_llm.ainvoke([
                SystemMessage(content=self.system_prompt),
                HumanMessage(content=prompt_content),
            ])

            assessments = response.assessments if response else []
            assess_map = {a.id: a for a in assessments}

            final_assessments: List[RiskAssessment] = []
            for v in active_validated:
                if v.id in assess_map:
                    final_assessments.append(assess_map[v.id])
                else:
                    raw_f = raw_map.get(v.id)
                    final_assessments.append(
                        self._default_assessment(v, raw_f)
                    )

            completed_at = datetime.now(timezone.utc)
            event = ExecutionEvent(
                event_id=f"evt_{uuid.uuid4().hex[:8]}",
                job_id=job_id,
                agent="Risk Assessment Agent",
                tool=f"Claude Sonnet 5.5 ({settings.LLM_PROVIDER})",
                status="COMPLETED",
                message=f"Risk assessment complete for {len(final_assessments)} item(s).",
                started_at=started_at,
                completed_at=completed_at,
                findings_count=len(final_assessments),
            )
            return final_assessments, event

        except Exception as e:
            logger.error(f"[Agent 4: RiskAgent] Risk assessment error: {e}", exc_info=True)
            return self._heuristic_fallback(active_validated, raw_map, job_id, started_at, error_details=str(e))

    def _default_assessment(self, v: ValidatedFinding, raw_f: Optional[RawFinding]) -> RiskAssessment:
        """Create standard risk evaluation when LLM output omits an item."""
        category = raw_f.category if raw_f else "Insecure Code"
        severity = raw_f.severity if raw_f else "MEDIUM"
        cwe = "CWE-89" if "Injection" in category else "CWE-798" if "Secret" in category else "CWE-699"
        owasp = "A03:2021-Injection" if "Injection" in category else "A07:2021-Identification Failures"

        return RiskAssessment(
            id=v.id,
            severity=severity,
            cwe=cwe,
            owasp_category=owasp,
            exploitability="HIGH" if severity in ("CRITICAL", "HIGH") else "MEDIUM",
            potential_impact=f"Potential security compromise related to {category}.",
            priority=1 if severity == "CRITICAL" else 2 if severity == "HIGH" else 3,
            reasoning=f"Assigned based on {category} finding validation.",
        )

    def _heuristic_fallback(
        self,
        active_validated: List[ValidatedFinding],
        raw_map: dict,
        job_id: str,
        started_at: datetime,
        error_details: Optional[str] = None,
    ) -> Tuple[List[RiskAssessment], ExecutionEvent]:
        """Deterministic risk assessment fallback."""
        results = [self._default_assessment(v, raw_map.get(v.id)) for v in active_validated]
        event = ExecutionEvent(
            event_id=f"evt_{uuid.uuid4().hex[:8]}",
            job_id=job_id,
            agent="Risk Assessment Agent",
            tool="Heuristic Risk Assessor (Fallback)",
            status="COMPLETED" if not error_details else "FAILED",
            message=f"Heuristic risk assessment completed for {len(results)} items.",
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            findings_count=len(results),
            error_details=error_details,
        )
        return results, event


# Singleton instance
risk_agent = RiskAgent()
