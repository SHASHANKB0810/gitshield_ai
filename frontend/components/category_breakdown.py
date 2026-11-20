"""Streamlit Category Breakdown and Filtering Component.

Groups vulnerabilities into dynamic security categories with interactive filters.
"""

from typing import Any, Dict, List
import streamlit as st
from frontend.components.finding_card import render_finding_card


def render_category_breakdown(vulnerabilities: List[Dict[str, Any]]):
    """Render category-wise tabs and filterable vulnerability views."""
    st.markdown(
        """
        <div style="display: flex; justify-content: space-between; align-items: center; margin: 1.5rem 0 1rem 0;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 1.2rem;">📂</span>
                <h3 style="margin: 0; font-size: 1.2rem; font-weight: 700; color: #ffffff;">
                    Security Findings by Category
                </h3>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not vulnerabilities:
        st.markdown(
            """
            <div style="background: #111827; border: 1px dashed #26354d; border-radius: 12px; padding: 2rem; text-align: center;">
                <span style="font-size: 2rem;">🛡️</span>
                <h4 style="color: #10b981; margin: 0.5rem 0 0.25rem 0;">No Security Findings Detected</h4>
                <p style="color: #94a3b8; font-size: 0.85rem; margin: 0;">
                    All deterministic scanners and multi-agent validation passes completed cleanly.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    # Filter Bar
    filter_col1, filter_col2 = st.columns([1, 1])
    with filter_col1:
        sev_filter = st.selectbox(
            "Filter by Severity",
            options=["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
            key="severity_filter_select",
        )
    with filter_col2:
        val_filter = st.selectbox(
            "Filter by Validation Status",
            options=["All Statuses", "CONFIRMED Only", "Hide False Positives", "FALSE POSITIVES Only", "NEEDS MANUAL REVIEW"],
            key="validation_filter_select",
        )

    # Apply Filters
    filtered_vulns = vulnerabilities
    if sev_filter != "All Severities":
        filtered_vulns = [v for v in filtered_vulns if v.get("severity", "").upper() == sev_filter]

    if val_filter == "CONFIRMED Only":
        filtered_vulns = [v for v in filtered_vulns if v.get("validation_status", "").upper() == "CONFIRMED"]
    elif val_filter == "Hide False Positives":
        filtered_vulns = [v for v in filtered_vulns if v.get("validation_status", "").upper() != "FALSE_POSITIVE"]
    elif val_filter == "FALSE POSITIVES Only":
        filtered_vulns = [v for v in filtered_vulns if v.get("validation_status", "").upper() == "FALSE_POSITIVE"]
    elif val_filter == "NEEDS MANUAL REVIEW":
        filtered_vulns = [v for v in filtered_vulns if v.get("validation_status", "").upper() == "NEEDS_MANUAL_REVIEW"]

    # Extract distinct categories from the findings
    categories = sorted(list({v.get("category", "Other") for v in vulnerabilities}))
    tab_titles = ["All Findings"] + [f"{cat} ({sum(1 for v in vulnerabilities if v.get('category') == cat)})" for cat in categories]
    tabs = st.tabs(tab_titles)

    # Tab 1: All Findings
    with tabs[0]:
        st.markdown(f"<div style='font-size: 0.85rem; color: #94a3b8; margin-bottom: 12px;'>Showing <b>{len(filtered_vulns)}</b> of {len(vulnerabilities)} total finding(s)</div>", unsafe_allow_html=True)
        if not filtered_vulns:
            st.info("No findings match the selected filter criteria.")
        else:
            for idx, vuln in enumerate(filtered_vulns, start=1):
                render_finding_card(vuln, idx)

    # Category Tabs
    for idx, cat in enumerate(categories, start=1):
        with tabs[idx]:
            cat_vulns = [v for v in filtered_vulns if v.get("category") == cat]
            st.markdown(f"<div style='font-size: 0.85rem; color: #94a3b8; margin-bottom: 12px;'>Showing <b>{len(cat_vulns)}</b> finding(s) in category <b>{cat}</b></div>", unsafe_allow_html=True)
            if not cat_vulns:
                st.info(f"No findings in '{cat}' match the active filters.")
            else:
                for c_idx, vuln in enumerate(cat_vulns, start=1):
                    render_finding_card(vuln, c_idx)
