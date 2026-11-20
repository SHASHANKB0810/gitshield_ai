"""Agent 3: Vulnerability Validation Agent.

Evaluates raw findings using Claude Sonnet 5.5 to eliminate false positives,
verify taint flows, and assess genuine exploitability.
"""

from datetime import datetime, timezone
import uuid
from typing import List, Optional, Tuple
from pydantic import BaseModel, Field
from langchain_core.messages import SystemMessage, HumanMessage

from backend.api.schemas import RawFinding, ValidatedFinding, ExecutionEvent
from backend.agents.prompts.validation_prompt import VALIDATION_SYSTEM_PROMPT
from backend.core.llm_factory import LLMFactory
from backend.core.security import sanitize_code_context
from backend.core.logging import logger
from backend.core.config import settings


class ValidationOutput(BaseModel):
    """Structured response container for multiple validated findings."""
    validations: List[ValidatedFinding] = Field(
        default_factory=list,
        description="List of validated finding verdicts",
    )


class ValidationAgent:
    """Agent that performs false-positive analysis and reachability checks."""

    def __init__(self):
        self.system_prompt = VALIDATION_SYSTEM_PROMPT

    async def run(
        self,
        findings: List[RawFinding],
        job_id: str,
    ) -> Tuple[List[ValidatedFinding], ExecutionEvent]:
        """Validate raw findings using Claude Sonnet 5.5.

        Args:
            findings: List of raw findings from Detection Agent.
            job_id: Active analysis job ID.

        Returns:
            Tuple of (validated_findings: List[ValidatedFinding], event: ExecutionEvent)
        """
        started_at = datetime.now(timezone.utc)
        logger.info(f"[Agent 3: ValidationAgent] Validating {len(findings)} findings.")

        if not findings:
            event = ExecutionEvent(
                event_id=f"evt_{uuid.uuid4().hex[:8]}",
                job_id=job_id,
                agent="Vulnerability Validation Agent",
                tool=f"Claude Sonnet 5.5 ({settings.LLM_PROVIDER})",
                status="COMPLETED",
                message="No findings to validate.",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                findings_count=0,
            )
            return [], event

        if not settings.LLM_API_KEY:
            logger.warning("[Agent 3: ValidationAgent] LLM API key not configured. Using heuristic validation.")
            return self._heuristic_fallback(findings, job_id, started_at)

        try:
            llm = LLMFactory.get_chat_model(temperature=0.0)
            structured_llm = llm.with_structured_output(ValidationOutput)

            # Build human prompt with sanitized context
            findings_payload = []
            for f in findings:
                sanitized_evidence = sanitize_code_context(f.evidence)
                findings_payload.append(
                    f"Finding ID: {f.id}\n"
                    f"Title: {f.title}\n"
                    f"Category: {f.category}\n"
                    f"Tool: {f.tool}\n"
                    f"File: {f.file}:{f.line or 'N/A'}\n"
                    f"Description: {f.description}\n"
                    f"Code Context:\n```\n{sanitized_evidence}\n```\n"
                )

            prompt_content = (
                "Please analyze and validate each of the following security findings.\n"
                "Determine if each finding is CONFIRMED, LIKELY, FALSE_POSITIVE, or NEEDS_MANUAL_REVIEW.\n\n"
                + "\n---\n".join(findings_payload)
            )

            response: ValidationOutput = await structured_llm.ainvoke([
                SystemMessage(content=self.system_prompt),
                HumanMessage(content=prompt_content),
            ])

            validated_list = response.validations if response else []

            # Ensure all findings receive a validation entry
            validated_map = {v.id: v for v in validated_list}
            final_validated: List[ValidatedFinding] = []

            for f in findings:
                if f.id in validated_map:
                    final_validated.append(validated_map[f.id])
                else:
                    # Default fallback if LLM omitted an ID
                    final_validated.append(
                        ValidatedFinding(
                            id=f.id,
                            validation_status="LIKELY",
                            confidence=f.confidence,
                            reasoning=f"Validated by scanner evidence: {f.description}",
                            supporting_evidence=[f.evidence[:200]] if f.evidence else [],
                        )
                    )

            confirmed_cnt = sum(1 for v in final_validated if v.validation_status in ("CONFIRMED", "LIKELY"))
            fp_cnt = sum(1 for v in final_validated if v.validation_status == "FALSE_POSITIVE")

            completed_at = datetime.now(timezone.utc)
            event = ExecutionEvent(
                event_id=f"evt_{uuid.uuid4().hex[:8]}",
                job_id=job_id,
                agent="Vulnerability Validation Agent",
                tool=f"Claude Sonnet 5.5 ({settings.LLM_PROVIDER})",
                status="COMPLETED",
                message=f"Validation completed. {confirmed_cnt} confirmed/likely, {fp_cnt} false positive(s) filtered.",
                started_at=started_at,
                completed_at=completed_at,
                findings_count=len(final_validated),
            )
            return final_validated, event

        except Exception as e:
            logger.error(f"[Agent 3: ValidationAgent] LLM validation error: {e}", exc_info=True)
            return self._heuristic_fallback(findings, job_id, started_at, error_details=str(e))

    def _heuristic_fallback(
        self,
        findings: List[RawFinding],
        job_id: str,
        started_at: datetime,
        error_details: Optional[str] = None,
    ) -> Tuple[List[ValidatedFinding], ExecutionEvent]:
        """Heuristic validation fallback when LLM gateway is offline."""
        validated: List[ValidatedFinding] = []
        for f in findings:
            # Deterministic heuristic rules
            status = "CONFIRMED"
            fp_reason = None

            if "bcrypt.hashpw" in f.evidence or "hashlib.sha256" in f.evidence:
                status = "FALSE_POSITIVE"
                fp_reason = "Standard password hashing or secure digest detected."
            elif "%s" in f.evidence and "cursor.execute" in f.evidence:
                status = "FALSE_POSITIVE"
                fp_reason = "Query uses parameterized placeholder syntax."

            validated.append(
                ValidatedFinding(
                    id=f.id,
                    validation_status=status,  # type: ignore[arg-type]
                    confidence=0.8,
                    reasoning="Validated by heuristic rule inspection (LLM Gateway offline).",
                    supporting_evidence=[f.evidence[:200]] if f.evidence else [],
                    false_positive_reason=fp_reason,
                )
            )

        event = ExecutionEvent(
            event_id=f"evt_{uuid.uuid4().hex[:8]}",
            job_id=job_id,
            agent="Vulnerability Validation Agent",
            tool="Heuristic Validator (Fallback)",
            status="COMPLETED" if not error_details else "FAILED",
            message=f"Heuristic validation completed for {len(validated)} findings.",
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            findings_count=len(validated),
            error_details=error_details,
        )
        return validated, event


# Singleton instance
validation_agent = ValidationAgent()
