"""Streamlit Finding Card Component.

Renders individual vulnerability cards with compact summaries and expandable details.
"""

from typing import Any, Dict
import streamlit as st
from frontend.components.remediation_view import render_remediation_view


def render_finding_card(vuln: Dict[str, Any], index: int):
    """Render a single vulnerability finding card."""
    vuln_id = vuln.get("id", f"VULN-{index:03d}")
    title = vuln.get("title", "Security Issue")
    category = vuln.get("category", "Insecure Code")
    file_path = vuln.get("file", "unknown")
    line = vuln.get("line")
    loc_str = f"{file_path}:{line}" if line else file_path
    tool = vuln.get("tool", "Scanner")
    sev = vuln.get("severity", "MEDIUM").upper()
    val_status = vuln.get("validation_status", "CONFIRMED").upper()
    desc = vuln.get("description", "")
    evidence = vuln.get("evidence", "")
    reasoning = vuln.get("validation_reasoning")
    cwe = vuln.get("cwe")
    owasp = vuln.get("owasp_category")
    impact = vuln.get("potential_impact")
    confidence = vuln.get("confidence", 0.85)
    remediation = vuln.get("remediation")

    sev_class = {
        "CRITICAL": "badge-critical",
        "HIGH": "badge-high",
        "MEDIUM": "badge-medium",
        "LOW": "badge-low",
        "INFORMATIONAL": "badge-low",
    }.get(sev, "badge-medium")

    val_class = {
        "CONFIRMED": "badge-critical",
        "LIKELY": "badge-high",
        "FALSE_POSITIVE": "badge-low",
        "NEEDS_MANUAL_REVIEW": "badge-medium",
    }.get(val_status, "badge-medium")

    # Card Container
    with st.container():
        # Header Row
        st.markdown(
            f"""
            <div style="background: #162032; border: 1px solid #26354d; border-radius: 8px 8px 0 0; padding: 12px 16px; margin-top: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span style="font-size: 0.95rem; font-weight: 700; color: #ffffff;">{index}. {title}</span>
                    </div>
                    <div style="display: flex; gap: 6px;">
                        <span class="badge {sev_class}">{sev}</span>
                        <span class="badge {val_class}">{val_status}</span>
                        <span class="badge" style="background: #111827; color: #94a3b8; border: 1px solid #26354d;">{tool}</span>
                    </div>
                </div>
                <div style="font-size: 0.78rem; color: #94a3b8; margin-top: 6px;">
                    <b>File:</b> <code style="color: #06b6d4;">{loc_str}</code> | <b>Category:</b> {category} | <b>Confidence:</b> {int(confidence * 100)}% (estimate)
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Expandable Detailed View
        with st.expander("🔍 View Technical Details, Evidence & Suggested Fix", expanded=False):
            st.markdown(f"**Description:** {desc}")

            if reasoning:
                st.markdown(
                    f"""
                    <div style="background: #111827; border-left: 3px solid #06b6d4; padding: 10px; margin: 10px 0; border-radius: 0 6px 6px 0; font-size: 0.82rem;">
                        <b style="color: #06b6d4;">Claude Sonnet 5.5 Validation Reasoning:</b><br>
                        <span style="color: #f3f4f6;">{reasoning}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            # Metadata Strip
            meta_cols = st.columns(3)
            with meta_cols[0]:
                if cwe:
                    st.markdown(f"**CWE:** `{cwe}`")
            with meta_cols[1]:
                if owasp:
                    st.markdown(f"**OWASP Top 10:** `{owasp}`")
            with meta_cols[2]:
                if impact:
                    st.markdown(f"**Potential Impact:** {impact}")

            # Sanitized Code Context
            if evidence:
                st.markdown("<span style='font-size: 0.8rem; font-weight: 600; color: #94a3b8;'>Scanned Code Context:</span>", unsafe_allow_html=True)
                st.code(evidence.strip(), language="python")

            # Remediation & Verification View
            render_remediation_view(remediation)
