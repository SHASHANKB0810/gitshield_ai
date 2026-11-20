"""Report Generation and Export Service.

Generates structured Markdown and JSON reports from AnalysisReport objects.
"""

import json
from typing import Optional
from backend.api.schemas import AnalysisReport, UnifiedVulnerability
from backend.core.logging import logger


class ReportService:
    """Service formatting security findings into shareable Markdown and JSON artifacts."""

    @staticmethod
    def generate_json_report(report: AnalysisReport) -> str:
        """Serialize complete analysis report to pretty-printed JSON."""
        return report.model_dump_json(indent=2)

    @staticmethod
    def generate_markdown_report(report: AnalysisReport) -> str:
        """Format analysis report into a clean, professional Markdown security document."""
        repo = report.repository
        created_str = report.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")

        md_lines = [
            "# GitShield AI — Security Analysis & Remediation Report",
            f"\n**Target Repository:** [{repo.owner}/{repo.repository_name}]({repo.url})  ",
            f"**Analysis Job ID:** `{report.job_id}`  ",
            f"**Generated At:** {created_str}  ",
            f"**Status:** `{report.status}`  ",
            "\n---\n",
            "## 1. Executive Summary\n",
            f"- **Total Findings Flagged:** {report.total_findings_count}",
            f"- **Confirmed Vulnerabilities:** {report.confirmed_count}",
            f"- **Likely Vulnerabilities:** {report.likely_count}",
            f"- **False Positives Filtered:** {report.false_positive_count}",
            f"- **Requires Manual Review:** {report.manual_review_count}",
            "\n### Severity Distribution\n",
            "| Severity | Count |",
            "|---|---|",
            f"| 🔴 Critical | {report.severity_distribution.get('CRITICAL', 0)} |",
            f"| 🟠 High | {report.severity_distribution.get('HIGH', 0)} |",
            f"| 🟡 Medium | {report.severity_distribution.get('MEDIUM', 0)} |",
            f"| 🔵 Low | {report.severity_distribution.get('LOW', 0)} |",
            f"| ⚪ Informational | {report.severity_distribution.get('INFORMATIONAL', 0)} |",
            "\n### Technology Stack & Scope\n",
            f"- **Primary Languages:** {', '.join(repo.languages) if repo.languages else 'N/A'}",
            f"- **Detected Frameworks:** {', '.join(repo.frameworks) if repo.frameworks else 'None detected'}",
            f"- **Manifest Dependencies:** {repo.dependencies_count}",
            f"- **Files Analyzed:** {repo.total_files_analyzed}",
            "\n---\n",
            "## 2. Security Findings & Remediation Plan\n",
        ]

        if not report.vulnerabilities:
            md_lines.append("_No vulnerabilities or security warnings were detected in this repository._\n")
        else:
            for idx, vuln in enumerate(report.vulnerabilities, start=1):
                sev_emoji = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🔵",
                    "INFORMATIONAL": "⚪",
                }.get(vuln.severity, "⚠️")

                val_badge = {
                    "CONFIRMED": "✅ CONFIRMED",
                    "LIKELY": "⚠️ LIKELY",
                    "FALSE_POSITIVE": "🛡️ FALSE POSITIVE",
                    "NEEDS_MANUAL_REVIEW": "🔍 MANUAL REVIEW",
                }.get(vuln.validation_status, vuln.validation_status)

                md_lines.extend([
                    f"### {idx}. {vuln.title}",
                    f"**Severity:** {sev_emoji} `{vuln.severity}` | **Validation:** `{val_badge}` | **Category:** `{vuln.category}`  ",
                    f"**Location:** `{vuln.file}:{vuln.line or 'N/A'}` | **Detected by:** `{vuln.tool}`  ",
                ])

                if vuln.cwe:
                    md_lines.append(f"**CWE:** `{vuln.cwe}` | **OWASP:** `{vuln.owasp_category or 'N/A'}`  ")

                md_lines.extend([
                    f"\n**Description:**  \n{vuln.description}\n",
                ])

                if vuln.validation_reasoning:
                    md_lines.extend([
                        f"**Validation Reasoning:**  \n{vuln.validation_reasoning}\n",
                    ])

                if vuln.evidence:
                    md_lines.extend([
                        "**Code Context:**",
                        "```python",
                        vuln.evidence.strip(),
                        "```\n",
                    ])

                if vuln.remediation:
                    rem = vuln.remediation
                    v_badge = {
                        "PASSED": "✅ VERIFIED: Rescan Passed",
                        "FAILED": "❌ Rescan Failed",
                        "UNVERIFIABLE": "⚠️ Verification Unverifiable",
                        "SKIPPED": "⏩ Skipped",
                    }.get(rem.verification_status, rem.verification_status)

                    md_lines.extend([
                        f"#### 💡 Recommended Fix (`{v_badge}`)",
                        f"**Strategy:** {rem.recommended_fix}\n",
                        "**Suggested Patched Code:**",
                        "```python",
                        rem.patched_code.strip(),
                        "```\n",
                        f"**Explanation:** {rem.explanation}\n",
                    ])

                    if rem.regression_risks:
                        md_lines.append(f"**Regression Risks:** {', '.join(rem.regression_risks)}\n")

                md_lines.append("---\n")

        md_lines.extend([
            "\n## 3. Execution History & Telemetry\n",
            "| Agent / Tool | Status | Findings | Duration / Timestamp |",
            "|---|---|---|---|",
        ])

        for evt in report.events:
            tool_name = f"{evt.agent} ({evt.tool})" if evt.tool else evt.agent
            cnt_str = str(evt.findings_count) if evt.findings_count is not None else "-"
            time_str = evt.started_at.strftime("%H:%M:%S")
            md_lines.append(f"| {tool_name} | `{evt.status}` | {cnt_str} | {time_str} |")

        md_lines.append("\n\n---\n*Report generated automatically by GitShield AI Security Intelligence Engine.*")
        return "\n".join(md_lines)


# Singleton instance
report_service = ReportService()
