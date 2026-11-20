"""Semgrep Static Application Security Testing (SAST) Scanner.

Executes Semgrep rulesets for multi-language security analysis,
normalizing CWE and OWASP findings into the unified finding schema.
"""

from datetime import datetime, timezone
import json
import os
import re
import shutil
import subprocess
from typing import Dict, List, Tuple
from backend.api.schemas import RawFinding, ExecutionEvent
from backend.scanners.base_scanner import BaseScanner
from backend.core.logging import logger

SEMGREP_CATEGORY_MAP: Dict[str, str] = {
    "sql": "Injection",
    "sqli": "Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "command-injection": "Injection",
    "path-traversal": "File Handling",
    "jwt": "Authentication & Authorization",
    "auth": "Authentication & Authorization",
    "crypto": "Cryptographic Weakness",
    "deserialization": "Insecure Deserialization",
    "secret": "Secrets & Credentials",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "cors": "Insecure Configuration",
}


class SemgrepScanner(BaseScanner):
    """Semgrep SAST scanner wrapper with multi-language rules."""

    def __init__(self, timeout_seconds: int = 90):
        super().__init__(name="Semgrep", timeout_seconds=timeout_seconds)

    def is_available(self) -> bool:
        """Check if semgrep binary is installed in system path."""
        return shutil.which("semgrep") is not None

    def scan(self, repo_path: str, job_id: str) -> Tuple[List[RawFinding], ExecutionEvent]:
        """Execute Semgrep against repository."""
        started_at = datetime.now(timezone.utc)
        findings: List[RawFinding] = []

        if not self.is_available():
            # If Semgrep CLI binary is not present (e.g. on Windows without WSL), run fallback SAST heuristics
            logger.info("Semgrep binary not detected on system path. Running built-in SAST heuristics engine.")
            return self._run_heuristic_sast(repo_path, job_id, started_at)

        cmd = [
            "semgrep",
            "scan",
            "--config", "auto",
            "--json",
            "--quiet",
            "--exclude", ".git",
            "--exclude", ".venv",
            "--exclude", "venv",
            "--exclude", "node_modules",
            repo_path,
        ]

        logger.info(f"Executing Semgrep scan on: {repo_path}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            output_json = result.stdout.strip()
            if output_json:
                data = json.loads(output_json)
                results_list = data.get("results", [])

                for idx, item in enumerate(results_list, start=1):
                    check_id = item.get("check_id", "semgrep-finding")
                    path_str = item.get("path", "")
                    rel_file = os.path.relpath(path_str, repo_path).replace("\\", "/") if path_str else ""
                    
                    start_data = item.get("start", {})
                    line_num = start_data.get("line", 1)

                    extra = item.get("extra", {})
                    message = extra.get("message", "Semgrep security alert")
                    severity_raw = extra.get("severity", "MEDIUM").upper()
                    if severity_raw not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
                        severity_raw = "HIGH" if severity_raw == "ERROR" else "MEDIUM"

                    category = "Insecure Code"
                    for key, cat_name in SEMGREP_CATEGORY_MAP.items():
                        if key in check_id.lower() or key in message.lower():
                            category = cat_name
                            break

                    raw_lines = extra.get("lines", "")
                    evidence = raw_lines if raw_lines else self.extract_snippet(os.path.join(repo_path, rel_file), line_num)

                    finding = RawFinding(
                        id=f"SEMGREP-{idx:03d}",
                        title=f"{check_id.split('.')[-1].replace('-', ' ').title()}: {message.split('.')[0]}",
                        category=category,
                        file=rel_file,
                        line=line_num,
                        tool="Semgrep",
                        description=f"[{check_id}] {message}",
                        evidence=evidence,
                        severity=severity_raw,  # type: ignore[arg-type]
                        confidence=0.85,
                    )
                    findings.append(finding)

            completed_at = datetime.utcnow()
            event = self.create_event(
                job_id=job_id,
                status="COMPLETED",
                message=f"Semgrep scan completed. Identified {len(findings)} potential finding(s).",
                started_at=started_at,
                completed_at=completed_at,
                findings_count=len(findings),
            )
            return findings, event

        except subprocess.TimeoutExpired:
            completed_at = datetime.utcnow()
            logger.error("Semgrep scan timed out.")
            event = self.create_event(
                job_id=job_id,
                status="FAILED",
                message=f"Semgrep scan timed out after {self.timeout_seconds}s",
                started_at=started_at,
                completed_at=completed_at,
                error_details="Execution timeout",
            )
            return [], event
        except Exception as e:
            completed_at = datetime.utcnow()
            logger.error(f"Semgrep scan failed with exception: {e}")
            event = self.create_event(
                job_id=job_id,
                status="FAILED",
                message=f"Semgrep scan failed: {type(e).__name__}",
                started_at=started_at,
                completed_at=completed_at,
                error_details=str(e),
            )
            return [], event

    def _run_heuristic_sast(self, repo_path: str, job_id: str, started_at: datetime) -> Tuple[List[RawFinding], ExecutionEvent]:
        """Built-in SAST heuristics fallback for patterns across Python/JS/TS files."""
        findings: List[RawFinding] = []
        finding_idx = 1

        patterns = [
            (
                re.compile(r"""f["'].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*?\{.+?\}""", re.IGNORECASE),
                "Potential SQL Injection (F-String Formatting)",
                "Injection",
                "HIGH",
                "Unsafe direct interpolation of variables into SQL query string.",
            ),
            (
                re.compile(r"""(?:subprocess\.Popen|subprocess\.call|subprocess\.run|os\.system)\s*\(\s*f?["'].*?\{.+?\}.*?shell\s*=\s*True""", re.IGNORECASE),
                "Command Injection (shell=True with Interpolation)",
                "Injection",
                "CRITICAL",
                "Invoking shell command with unescaped string formatting and shell=True.",
            ),
            (
                re.compile(r"""(?:open|os\.path\.join)\s*\(\s*.*?request\.(?:args|form|GET|POST|values)""", re.IGNORECASE),
                "Potential Path Traversal",
                "File Handling",
                "HIGH",
                "Direct file access using unsanitized user request parameters.",
            ),
            (
                re.compile(r"""(?:innerHTML|dangerouslySetInnerHTML)\s*=""", re.IGNORECASE),
                "Potential Cross-Site Scripting (XSS)",
                "Cross-Site Scripting (XSS)",
                "MEDIUM",
                "Direct DOM HTML injection without contextual sanitization.",
            ),
        ]

        try:
            for root, dirs, files in os.walk(repo_path):
                dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "node_modules", "dist", "build"}]
                for file in files:
                    if not file.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".php")):
                        continue

                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, repo_path).replace("\\", "/")

                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()

                        for line_idx, line_content in enumerate(lines, start=1):
                            for regex, title, category, severity, desc in patterns:
                                if regex.search(line_content):
                                    evidence = self.extract_snippet(full_path, line_idx)
                                    finding = RawFinding(
                                        id=f"SAST-HEURISTIC-{finding_idx:03d}",
                                        title=title,
                                        category=category,
                                        file=rel_path,
                                        line=line_idx,
                                        tool="Semgrep (Heuristics)",
                                        description=desc,
                                        evidence=evidence,
                                        severity=severity,  # type: ignore[arg-type]
                                        confidence=0.8,
                                    )
                                    findings.append(finding)
                                    finding_idx += 1
                    except Exception as e:
                        logger.debug(f"Could not read {full_path}: {e}")

            completed_at = datetime.now(timezone.utc)
            event = self.create_event(
                job_id=job_id,
                status="COMPLETED",
                message=f"SAST engine completed. Found {len(findings)} potential issue(s).",
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
                message=f"SAST engine failed: {type(e).__name__}",
                started_at=started_at,
                completed_at=completed_at,
                error_details=str(e),
            )
            return [], event
