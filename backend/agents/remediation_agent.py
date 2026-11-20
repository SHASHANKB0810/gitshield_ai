"""Agent 5: Remediation and Verification Agent.

Generates minimal, context-aware code patches using Claude Sonnet 5.5
and verifies fixes by rescanning patched buffers against security rules.
"""

from datetime import datetime, timezone
import os
import tempfile
import uuid
from typing import List, Optional, Tuple
from pydantic import BaseModel, Field
from langchain_core.messages import SystemMessage, HumanMessage

from backend.api.schemas import (
    RawFinding,
    ValidatedFinding,
    RiskAssessment,
    RemediationResult,
    ExecutionEvent,
)
from backend.agents.prompts.remediation_prompt import REMEDIATION_SYSTEM_PROMPT
from backend.core.llm_factory import LLMFactory
from backend.core.security import sanitize_code_context
from backend.core.logging import logger
from backend.core.config import settings
from backend.scanners.bandit_scanner import BanditScanner
from backend.scanners.semgrep_scanner import SemgrepScanner


class RemediationItem(BaseModel):
    """Schema for an individual patch recommendation produced by LLM."""
    id: str
    recommended_fix: str
    original_code: str
    patched_code: str
    explanation: str
    regression_risks: List[str] = Field(default_factory=list)


class RemediationBatch(BaseModel):
    """Container for batch patch generation."""
    remediations: List[RemediationItem] = Field(default_factory=list)


class RemediationAgent:
    """Agent responsible for patch generation and local automated verification."""

    def __init__(self):
        self.system_prompt = REMEDIATION_SYSTEM_PROMPT
        self.bandit = BanditScanner()
        self.semgrep = SemgrepScanner()

    async def run(
        self,
        raw_findings: List[RawFinding],
        validated_findings: List[ValidatedFinding],
        job_id: str,
    ) -> Tuple[List[RemediationResult], ExecutionEvent]:
        """Generate patches and verify fixes."""
        started_at = datetime.now(timezone.utc)
        logger.info(f"[Agent 5: RemediationAgent] Generating and verifying patches.")

        # Target confirmed/likely findings only
        target_ids = {
            v.id for v in validated_findings
            if v.validation_status in ("CONFIRMED", "LIKELY")
        }
        target_raw = [f for f in raw_findings if f.id in target_ids]

        if not target_raw:
            event = ExecutionEvent(
                event_id=f"evt_{uuid.uuid4().hex[:8]}",
                job_id=job_id,
                agent="Remediation and Verification Agent",
                tool=f"Claude Sonnet 5.5 ({settings.LLM_PROVIDER})",
                status="COMPLETED",
                message="No actionable vulnerabilities requiring remediation.",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                findings_count=0,
            )
            return [], event

        if not settings.LLM_API_KEY:
            logger.warning("[Agent 5: RemediationAgent] LLM API key not set. Using template remediation.")
            return self._template_remediation(target_raw, job_id, started_at)

        try:
            llm = LLMFactory.get_chat_model(temperature=0.0)
            structured_llm = llm.with_structured_output(RemediationBatch)

            payload_items = []
            for f in target_raw:
                sanitized_evidence = sanitize_code_context(f.evidence)
                payload_items.append(
                    f"Finding ID: {f.id}\n"
                    f"Title: {f.title}\n"
                    f"Category: {f.category}\n"
                    f"File: {f.file}:{f.line or 'N/A'}\n"
                    f"Description: {f.description}\n"
                    f"Vulnerable Code Context:\n```\n{sanitized_evidence}\n```\n"
                )

            prompt_content = (
                "Please generate minimal, production-grade secure code remediations "
                "for each of the following vulnerabilities. Provide the exact original code, "
                "the suggested patched code, explanation, and potential regression risks:\n\n"
                + "\n---\n".join(payload_items)
            )

            response: RemediationBatch = await structured_llm.ainvoke([
                SystemMessage(content=self.system_prompt),
                HumanMessage(content=prompt_content),
            ])

            items = response.remediations if response else []
            remed_map = {item.id: item for item in items}

            final_results: List[RemediationResult] = []
            for f in target_raw:
                item = remed_map.get(f.id)
                if item:
                    # Run automated verification pass on the suggested patch
                    v_status, v_details = self._verify_patch(item.patched_code, f)
                    result = RemediationResult(
                        id=f.id,
                        recommended_fix=item.recommended_fix,
                        original_code=item.original_code or f.evidence,
                        patched_code=item.patched_code,
                        explanation=item.explanation,
                        verification_status=v_status,  # type: ignore[arg-type]
                        verification_details=v_details,
                        regression_risks=item.regression_risks,
                    )
                else:
                    result = self._generate_fallback_remediation(f)
                final_results.append(result)

            passed_cnt = sum(1 for r in final_results if r.verification_status == "PASSED")
            completed_at = datetime.now(timezone.utc)
            event = ExecutionEvent(
                event_id=f"evt_{uuid.uuid4().hex[:8]}",
                job_id=job_id,
                agent="Remediation and Verification Agent",
                tool=f"Claude Sonnet 5.5 + Local Rescan Verifier",
                status="COMPLETED",
                message=f"Remediation generated for {len(final_results)} items ({passed_cnt} verified by automated rescan).",
                started_at=started_at,
                completed_at=completed_at,
                findings_count=len(final_results),
            )
            return final_results, event

        except Exception as e:
            logger.error(f"[Agent 5: RemediationAgent] Remediation generation error: {e}", exc_info=True)
            return self._template_remediation(target_raw, job_id, started_at, error_details=str(e))

    def _verify_patch(self, patched_code: str, raw_f: RawFinding) -> Tuple[str, List[str]]:
        """Verify that the suggested patch is clean when rescanned by security tools."""
        if not patched_code or not patched_code.strip():
            return "UNVERIFIABLE", ["No executable patch code provided for rescan."]

        # Write patch to temporary file in an isolated temporary directory
        details: List[str] = []
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                file_ext = ".py" if raw_f.file.endswith(".py") else ".txt"
                temp_file = os.path.join(tmp_dir, f"patch_verify{file_ext}")
                with open(temp_file, "w", encoding="utf-8") as f:
                    f.write(patched_code)

                # Rescan using Bandit or Semgrep
                if file_ext == ".py" and self.bandit.is_available():
                    findings, _ = self.bandit.scan(tmp_dir, job_id="verify_temp")
                    if not findings:
                        details.append("Bandit rescan clean: original vulnerability rules no longer trigger.")
                        return "PASSED", details
                    else:
                        details.append(f"Bandit rescan flagged {len(findings)} potential issue(s) in proposed patch.")
                        return "FAILED", details

                # Fallback check using SAST heuristics
                sast_findings, _ = self.semgrep._run_heuristic_sast(tmp_dir, "verify_temp", datetime.now(timezone.utc))
                if not sast_findings:
                    details.append("SAST rescan clean: verified with heuristic rule pass.")
                    return "PASSED", details
                else:
                    details.append("SAST rescan detected unresolved security pattern in patch.")
                    return "FAILED", details

        except Exception as e:
            logger.debug(f"Patch verification error: {e}")
            return "UNVERIFIABLE", [f"Rescan could not complete: {type(e).__name__}"]

    def _generate_fallback_remediation(self, f: RawFinding) -> RemediationResult:
        """Create a default remediation recommendation for a finding."""
        if "SQL" in f.title or f.category == "Injection":
            return RemediationResult(
                id=f.id,
                recommended_fix="Use parameterized database queries instead of string concatenation.",
                original_code=f.evidence,
                patched_code="# Example Parameterized Fix:\ncursor.execute('SELECT * FROM table WHERE col = %s', (val,))",
                explanation="Parameterized queries separate query logic from untrusted input.",
                verification_status="UNVERIFIABLE",
                verification_details=["Template remediation fallback applied."],
                regression_risks=["Ensure database connector supports %s placeholder tuples."],
            )
        elif f.category == "Secrets & Credentials":
            return RemediationResult(
                id=f.id,
                recommended_fix="Move hardcoded secret to environment variable or vault.",
                original_code=f.evidence,
                patched_code="import os\nAPI_KEY = os.environ.get('API_KEY')",
                explanation="Prevents accidental credential leakage into source control.",
                verification_status="UNVERIFIABLE",
                verification_details=["Template remediation fallback applied."],
                regression_risks=["Environment variable must be set in deployment environments."],
            )
        else:
            return RemediationResult(
                id=f.id,
                recommended_fix=f"Review and sanitize input in {f.file}.",
                original_code=f.evidence,
                patched_code="# Apply contextual sanitization or updated dependencies",
                explanation=f.description,
                verification_status="UNVERIFIABLE",
                verification_details=["Manual patch required."],
                regression_risks=[],
            )

    def _template_remediation(
        self,
        target_raw: List[RawFinding],
        job_id: str,
        started_at: datetime,
        error_details: Optional[str] = None,
    ) -> Tuple[List[RemediationResult], ExecutionEvent]:
        """Template remediation fallback when LLM gateway is offline."""
        results = [self._generate_fallback_remediation(f) for f in target_raw]
        event = ExecutionEvent(
            event_id=f"evt_{uuid.uuid4().hex[:8]}",
            job_id=job_id,
            agent="Remediation and Verification Agent",
            tool="Template Remediation Engine (Fallback)",
            status="COMPLETED" if not error_details else "FAILED",
            message=f"Remediation suggestions generated for {len(results)} items.",
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            findings_count=len(results),
            error_details=error_details,
        )
        return results, event


# Singleton instance
remediation_agent = RemediationAgent()
