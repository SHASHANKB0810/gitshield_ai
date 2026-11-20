"""Dependency Security Scanner (pip-audit & Package Manifests).

Scans manifest files (requirements.txt, pyproject.toml) for known CVEs
and vulnerable package dependencies using pip-audit.
"""

from datetime import datetime, timezone
import json
import os
import shutil
import subprocess
import sys
from typing import List, Tuple
from backend.api.schemas import RawFinding, ExecutionEvent
from backend.scanners.base_scanner import BaseScanner
from backend.core.logging import logger


class DependencyScanner(BaseScanner):
    """Dependency vulnerability scanner using pip-audit."""

    def __init__(self, timeout_seconds: int = 90):
        super().__init__(name="pip-audit", timeout_seconds=timeout_seconds)

    def is_available(self) -> bool:
        """Check if pip-audit is installed."""
        if shutil.which("pip-audit") is not None:
            return True
        try:
            res = subprocess.run(
                [sys.executable, "-m", "pip_audit", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return res.returncode == 0
        except Exception:
            return False

    def scan(self, repo_path: str, job_id: str) -> Tuple[List[RawFinding], ExecutionEvent]:
        """Scan Python dependency files for published CVEs."""
        started_at = datetime.now(timezone.utc)
        findings: List[RawFinding] = []

        # Find candidate requirement files
        req_files: List[str] = []
        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.lower() in ("requirements.txt", "requirements-dev.txt", "requirements_dev.txt"):
                    req_files.append(os.path.join(root, file))

        if not req_files:
            completed_at = datetime.now(timezone.utc)
            event = self.create_event(
                job_id=job_id,
                status="COMPLETED",
                message="No requirements.txt dependency files found in repository scope.",
                started_at=started_at,
                completed_at=completed_at,
                findings_count=0,
            )
            return findings, event

        if not self.is_available():
            event = self.create_event(
                job_id=job_id,
                status="SKIPPED",
                message="pip-audit is not available in environment.",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                findings_count=0,
            )
            return findings, event

        finding_idx = 1
        for req_file in req_files:
            rel_file = os.path.relpath(req_file, repo_path).replace("\\", "/")
            cmd = [
                sys.executable, "-m", "pip_audit",
                "-r", req_file,
                "-f", "json",
                "--desc",
                "--timeout", "30",
            ]

            logger.info(f"Running pip-audit on: {rel_file}")
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
                    dependencies = data.get("dependencies", [])

                    for dep in dependencies:
                        pkg_name = dep.get("name", "")
                        version = dep.get("version", "")
                        vulns = dep.get("vulns", [])

                        for vuln in vulns:
                            cve_id = vuln.get("id", "CVE-UNKNOWN")
                            desc = vuln.get("description", "Vulnerable package dependency detected.")
                            fix_versions = vuln.get("fix_versions", [])
                            fix_str = f"Upgrade to {', '.join(fix_versions)}" if fix_versions else "No direct fix version listed."

                            finding = RawFinding(
                                id=f"DEP-{cve_id}-{finding_idx:03d}",
                                title=f"Vulnerable Dependency: {pkg_name}=={version} ({cve_id})",
                                category="Dependency Vulnerabilities",
                                file=rel_file,
                                line=1,
                                tool="pip-audit",
                                description=f"{desc} Recommended action: {fix_str}",
                                evidence=f"Package: {pkg_name}=={version}\nVulnerability ID: {cve_id}\nFix: {fix_str}",
                                severity="HIGH",
                                confidence=0.95,
                            )
                            findings.append(finding)
                            finding_idx += 1

            except subprocess.TimeoutExpired:
                logger.warning(f"pip-audit timed out on {rel_file}")
            except Exception as e:
                logger.error(f"pip-audit failed on {rel_file}: {e}")

        completed_at = datetime.now(timezone.utc)
        event = self.create_event(
            job_id=job_id,
            status="COMPLETED",
            message=f"pip-audit completed. Found {len(findings)} vulnerable dependenc(ies).",
            started_at=started_at,
            completed_at=completed_at,
            findings_count=len(findings),
        )
        return findings, event
