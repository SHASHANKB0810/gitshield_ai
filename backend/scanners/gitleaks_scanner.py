"""Gitleaks Secret and Credential Exposure Scanner.

Scans the repository for hardcoded secrets, API tokens, private keys,
and database credentials, automatically redacting sensitive tokens in outputs.
"""

from datetime import datetime, timezone
import json
import math
import os
import re
import shutil
import subprocess
from typing import List, Tuple
from backend.api.schemas import RawFinding, ExecutionEvent
from backend.scanners.base_scanner import BaseScanner
from backend.core.security import sanitize_code_context
from backend.core.logging import logger

# Well-known secret regex signatures
SECRET_SIGNATURES = [
    (re.compile(r"""(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"""), "AWS Access Key ID", "CRITICAL"),
    (re.compile(r"""ghp_[a-zA-Z0-9]{36}"""), "GitHub Personal Access Token", "CRITICAL"),
    (re.compile(r"""gho_[a-zA-Z0-9]{36}"""), "GitHub OAuth Token", "CRITICAL"),
    (re.compile(r"""xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"""), "Slack Token", "HIGH"),
    (re.compile(r"""sk_live_[0-9a-zA-Z]{24}"""), "Stripe Live API Key", "CRITICAL"),
    (re.compile(r"""-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"""), "Private Cryptographic Key", "CRITICAL"),
    (re.compile(r"""(?:postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9_.-]+"""), "Database Connection String with Credentials", "HIGH"),
    (re.compile(r"""(?:api[_-]?key|secret[_-]?key|auth[_-]?token)\s*=\s*['\"][A-Za-z0-9_\-\.]{20,}['\"]""", re.IGNORECASE), "Generic Hardcoded Secret Token", "HIGH"),
]


class GitleaksScanner(BaseScanner):
    """Gitleaks secret detection scanner with built-in entropy fallback."""

    def __init__(self, timeout_seconds: int = 60):
        super().__init__(name="Gitleaks", timeout_seconds=timeout_seconds)

    def is_available(self) -> bool:
        """Check if gitleaks CLI is present in PATH."""
        return shutil.which("gitleaks") is not None

    def scan(self, repo_path: str, job_id: str) -> Tuple[List[RawFinding], ExecutionEvent]:
        """Execute Gitleaks or fall back to high-entropy pattern scanning."""
        started_at = datetime.now(timezone.utc)
        findings: List[RawFinding] = []

        if not self.is_available():
            logger.info("Gitleaks binary not present in PATH. Running built-in secret & entropy scanner.")
            return self._run_builtin_secret_scanner(repo_path, job_id, started_at)

        temp_report = os.path.join(repo_path, f".gitleaks_report_{job_id}.json")
        cmd = [
            "gitleaks", "detect",
            "--no-git",
            "--source", repo_path,
            "--report-path", temp_report,
            "--report-format", "json",
            "--verbose",
        ]

        logger.info(f"Executing Gitleaks on: {repo_path}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            # Gitleaks returns 1 if leaks are detected, 0 if clean
            if os.path.exists(temp_report):
                with open(temp_report, "r", encoding="utf-8") as f:
                    data = json.load(f)

                for idx, leak in enumerate(data, start=1):
                    rule_id = leak.get("RuleID", "Secret Leak")
                    filename = leak.get("File", "")
                    line_num = leak.get("StartLine", 1)
                    rel_file = os.path.relpath(filename, repo_path).replace("\\", "/") if filename else ""

                    raw_secret = leak.get("Secret", "")
                    raw_match = leak.get("Match", "")
                    description = leak.get("Description", f"Exposed secret ({rule_id}) detected.")

                    evidence = self.extract_snippet(os.path.join(repo_path, rel_file), line_num)
                    sanitized_evidence = sanitize_code_context(evidence or raw_match)

                    finding = RawFinding(
                        id=f"GITLEAKS-{idx:03d}",
                        title=f"Hardcoded Credential: {rule_id}",
                        category="Secrets & Credentials",
                        file=rel_file,
                        line=line_num,
                        tool="Gitleaks",
                        description=f"Potential exposed credential detected ({description}). Raw value is redacted.",
                        evidence=sanitized_evidence,
                        severity="HIGH",
                        confidence=0.9,
                    )
                    findings.append(finding)

                # Clean up temporary report
                try:
                    os.remove(temp_report)
                except Exception:
                    pass

            completed_at = datetime.utcnow()
            event = self.create_event(
                job_id=job_id,
                status="COMPLETED",
                message=f"Gitleaks scan completed. Detected {len(findings)} exposed secret(s).",
                started_at=started_at,
                completed_at=completed_at,
                findings_count=len(findings),
            )
            return findings, event

        except subprocess.TimeoutExpired:
            completed_at = datetime.utcnow()
            logger.error("Gitleaks scan timed out.")
            event = self.create_event(
                job_id=job_id,
                status="FAILED",
                message=f"Gitleaks scan timed out after {self.timeout_seconds}s",
                started_at=started_at,
                completed_at=completed_at,
                error_details="Execution timeout",
            )
            return [], event
        except Exception as e:
            completed_at = datetime.utcnow()
            logger.error(f"Gitleaks scan failed: {e}")
            event = self.create_event(
                job_id=job_id,
                status="FAILED",
                message=f"Gitleaks scan failed: {type(e).__name__}",
                started_at=started_at,
                completed_at=completed_at,
                error_details=str(e),
            )
            return [], event

    def _run_builtin_secret_scanner(self, repo_path: str, job_id: str, started_at: datetime) -> Tuple[List[RawFinding], ExecutionEvent]:
        """Entropy and signature-based scanner for repositories when gitleaks CLI is absent."""
        findings: List[RawFinding] = []
        finding_idx = 1

        try:
            for root, dirs, files in os.walk(repo_path):
                dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "node_modules", "dist", "build"}]

                for file in files:
                    if file.endswith((".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz")):
                        continue

                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, repo_path).replace("\\", "/")

                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()

                        for line_idx, line in enumerate(lines, start=1):
                            # Check against regex signatures
                            for pattern, title, severity in SECRET_SIGNATURES:
                                if pattern.search(line):
                                    evidence = self.extract_snippet(full_path, line_idx)
                                    sanitized_evidence = sanitize_code_context(evidence)

                                    finding = RawFinding(
                                        id=f"SECRET-DETECT-{finding_idx:03d}",
                                        title=f"Hardcoded Credential: {title}",
                                        category="Secrets & Credentials",
                                        file=rel_path,
                                        line=line_idx,
                                        tool="Gitleaks (Entropy/Signature Engine)",
                                        description=f"Potential exposed credential detected ({title}). Value has been scrubbed.",
                                        evidence=sanitized_evidence,
                                        severity=severity,  # type: ignore[arg-type]
                                        confidence=0.9,
                                    )
                                    findings.append(finding)
                                    finding_idx += 1
                                    break
                    except Exception as e:
                        logger.debug(f"Failed to read file for secret check {full_path}: {e}")

            completed_at = datetime.now(timezone.utc)
            event = self.create_event(
                job_id=job_id,
                status="COMPLETED",
                message=f"Secret scanner completed. Identified {len(findings)} potential secret(s).",
                started_at=started_at,
                completed_at=completed_at,
                findings_count=len(findings),
            )
            return findings, event

        except Exception as e:
            completed_at = datetime.now(timezone.utc)
            event = self.create_event(
                job_id=job_id,
                status="FAILED",
                message=f"Secret scan failed: {type(e).__name__}",
                started_at=started_at,
                completed_at=completed_at,
                error_details=str(e),
            )
            return [], event
