"""Bandit Python Security Scanner Integration.

Executes Bandit for Python AST security analysis and normalizes findings
into unified RawFinding models.
"""

from datetime import datetime, timezone
import json
import os
import shutil
import subprocess
import sys
from typing import Dict, List, Tuple
from backend.api.schemas import RawFinding, ExecutionEvent
from backend.scanners.base_scanner import BaseScanner
from backend.core.logging import logger

# Map Bandit test IDs to high-level security categories
BANDIT_CATEGORY_MAP: Dict[str, str] = {
    "B608": "Injection",                  # Hardcoded SQL query
    "B601": "Injection",                  # Paramiko call
    "B602": "Injection",                  # Subprocess popen with shell=True
    "B603": "Injection",                  # Subprocess call without shell=True
    "B604": "Injection",                  # Any other function with shell=True
    "B605": "Injection",                  # Start process with a shell
    "B606": "Injection",                  # Start process with no shell
    "B607": "Injection",                  # Start process with a partial path
    "B105": "Secrets & Credentials",      # Hardcoded password string
    "B106": "Secrets & Credentials",      # Hardcoded password func arg
    "B107": "Secrets & Credentials",      # Hardcoded password default arg
    "B108": "File Handling",              # Hardcoded /tmp directory
    "B303": "Cryptographic Weakness",     # MD5 / SHA1 usage
    "B304": "Cryptographic Weakness",     # Insecure ciphers
    "B305": "Cryptographic Weakness",     # Insecure cipher modes
    "B301": "Insecure Deserialization",   # Pickle deserialization
    "B302": "Insecure Deserialization",   # Marshal deserialization
    "B506": "Insecure Deserialization",   # Unsafe yaml.load
    "B101": "Insecure Configuration",     # Assert used in production code
    "B311": "Cryptographic Weakness",     # Standard pseudo-random generator
    "B201": "Insecure Configuration",     # Flask app.run(debug=True)
}


class BanditScanner(BaseScanner):
    """Bandit AST security scanner wrapper for Python codebases."""

    def __init__(self, timeout_seconds: int = 60):
        super().__init__(name="Bandit", timeout_seconds=timeout_seconds)

    def is_available(self) -> bool:
        """Check if bandit executable or module is available."""
        if shutil.which("bandit") is not None:
            return True
        try:
            res = subprocess.run(
                [sys.executable, "-m", "bandit", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return res.returncode == 0
        except Exception:
            return False

    def scan(self, repo_path: str, job_id: str) -> Tuple[List[RawFinding], ExecutionEvent]:
        """Execute Bandit across the repository directory."""
        started_at = datetime.now(timezone.utc)
        findings: List[RawFinding] = []

        if not self.is_available():
            event = self.create_event(
                job_id=job_id,
                status="SKIPPED",
                message="Bandit scanner is not installed or available.",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                findings_count=0,
            )
            return findings, event

        # Build execution command
        cmd = [
            sys.executable, "-m", "bandit",
            "-r", repo_path,
            "-f", "json",
            "-q",
        ]

        logger.info(f"Executing Bandit scan on: {repo_path}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            # Bandit returns 1 if issues are found, 0 if clean, >1 on fatal error
            output_json = result.stdout.strip()
            if not output_json and result.stderr:
                logger.warning(f"Bandit produced no JSON output: {result.stderr}")

            if output_json:
                data = json.loads(output_json)
                results_list = data.get("results", [])

                for idx, item in enumerate(results_list, start=1):
                    test_id = item.get("test_id", "")
                    filename = item.get("filename", "")
                    line_num = item.get("line_number")
                    rel_file = os.path.relpath(filename, repo_path).replace("\\", "/")

                    category = BANDIT_CATEGORY_MAP.get(test_id, "Insecure Code")
                    severity_raw = item.get("issue_severity", "MEDIUM").upper()
                    if severity_raw not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
                        severity_raw = "MEDIUM"

                    confidence_raw = item.get("issue_confidence", "MEDIUM").upper()
                    conf_map = {"HIGH": 0.9, "MEDIUM": 0.75, "LOW": 0.5}
                    confidence_val = conf_map.get(confidence_raw, 0.75)

                    raw_code = item.get("code", "")
                    evidence = raw_code if raw_code else self.extract_snippet(filename, line_num)

                    finding = RawFinding(
                        id=f"BANDIT-{test_id}-{idx:03d}",
                        title=f"{item.get('test_name', 'Security Issue')}: {item.get('issue_text', '')}",
                        category=category,
                        file=rel_file,
                        line=line_num,
                        tool="Bandit",
                        description=f"[{test_id}] {item.get('issue_text', '')}. More info: {item.get('more_info', '')}",
                        evidence=evidence,
                        severity=severity_raw,  # type: ignore[arg-type]
                        confidence=confidence_val,
                    )
                    findings.append(finding)

            completed_at = datetime.now(timezone.utc)
            event = self.create_event(
                job_id=job_id,
                status="COMPLETED",
                message=f"Bandit scan completed. Identified {len(findings)} potential issue(s).",
                started_at=started_at,
                completed_at=completed_at,
                findings_count=len(findings),
            )
            return findings, event

        except subprocess.TimeoutExpired:
            completed_at = datetime.now(timezone.utc)
            logger.error("Bandit scan timed out.")
            event = self.create_event(
                job_id=job_id,
                status="FAILED",
                message=f"Bandit scan timed out after {self.timeout_seconds}s",
                started_at=started_at,
                completed_at=completed_at,
                error_details="Execution timeout",
            )
            return [], event

        except Exception as e:
            completed_at = datetime.now(timezone.utc)
            logger.error(f"Bandit scan failed with exception: {e}")
            event = self.create_event(
                job_id=job_id,
                status="FAILED",
                message=f"Bandit scan failed: {type(e).__name__}",
                started_at=started_at,
                completed_at=completed_at,
                error_details=str(e),
            )
            return [], event
