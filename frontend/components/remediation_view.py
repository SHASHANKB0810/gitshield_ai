"""Streamlit Remediation & Code Diff Viewer Component.

Renders suggested code patches, before/after diffs, and verification badges.
"""

from typing import Any, Dict, Optional
import streamlit as st


def render_remediation_view(remediation: Optional[Dict[str, Any]]):
    """Render the patch review and verification details for a vulnerability."""
    if not remediation:
        st.markdown(
            """
            <div style="background: #111827; border: 1px dashed #26354d; border-radius: 8px; padding: 12px; font-size: 0.8rem; color: #94a3b8;">
                No automated patch generated for this item.
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    fix_title = remediation.get("recommended_fix", "Recommended Security Fix")
    patched_code = remediation.get("patched_code", "")
    original_code = remediation.get("original_code", "")
    explanation = remediation.get("explanation", "")
    v_status = remediation.get("verification_status", "UNVERIFIABLE")
    v_details = remediation.get("verification_details", [])
    regression_risks = remediation.get("regression_risks", [])

    badge_color = {
        "PASSED": "#10b981",
        "FAILED": "#ef4444",
        "UNVERIFIABLE": "#eab308",
        "SKIPPED": "#64748b",
    }.get(v_status, "#eab308")

    badge_label = {
        "PASSED": "✓ VERIFIED: Local Rescan Passed",
        "FAILED": "✗ VERIFICATION FAILED: Issue Detected in Patch",
        "UNVERIFIABLE": "⚠ UNVERIFIABLE: Manual Check Recommended",
        "SKIPPED": "⊘ Verification Skipped",
    }.get(v_status, v_status)

    st.markdown(
        f"""
        <div style="background: #111827; border: 1px solid #26354d; border-radius: 8px; padding: 14px; margin-top: 10px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="font-size: 0.85rem; font-weight: 700; color: #ffffff;">💡 Remediation Strategy</span>
                <span style="font-size: 0.72rem; font-weight: 700; color: {badge_color}; background: {badge_color}15; padding: 3px 8px; border-radius: 4px; border: 1px solid {badge_color}40;">
                    {badge_label}
                </span>
            </div>
            <p style="font-size: 0.82rem; color: #f3f4f6; margin: 0 0 10px 0;"><b>Plan:</b> {fix_title}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("<span style='font-size: 0.75rem; font-weight: 600; color: #f87171;'>❌ Original Vulnerable Code</span>", unsafe_allow_html=True)
        st.code(original_code.strip() if original_code else "# Original snippet unavailable", language="python")

    with col2:
        st.markdown("<span style='font-size: 0.75rem; font-weight: 600; color: #4ade80;'>✅ Suggested Patched Code</span>", unsafe_allow_html=True)
        st.code(patched_code.strip() if patched_code else "# No patch generated", language="python")

    if explanation:
        st.markdown(f"<div style='font-size: 0.8rem; color: #94a3b8; margin-top: 6px;'><b>Technical Rationale:</b> {explanation}</div>", unsafe_allow_html=True)

    if regression_risks:
        risks_str = ", ".join(regression_risks)
        st.markdown(f"<div style='font-size: 0.75rem; color: #f59e0b; margin-top: 4px;'>⚠️ <b>Potential Regression Risks:</b> {risks_str}</div>", unsafe_allow_html=True)

    if v_details:
        for detail in v_details:
            st.markdown(f"<div style='font-size: 0.72rem; color: #64748b;'>• {detail}</div>", unsafe_allow_html=True)
