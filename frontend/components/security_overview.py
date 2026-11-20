"""Streamlit Security Overview Component.

Renders executive KPI metrics, severity distributions, and repository metadata.
"""

from typing import Any, Dict
import streamlit as st


def render_security_overview(report: Dict[str, Any]):
    """Render executive metrics and target repository information."""
    repo = report.get("repository", {})
    sev_dist = report.get("severity_distribution", {})

    total_findings = report.get("total_findings_count", 0)
    confirmed_cnt = report.get("confirmed_count", 0)
    likely_cnt = report.get("likely_count", 0)
    fp_cnt = report.get("false_positive_count", 0)
    manual_cnt = report.get("manual_review_count", 0)

    crit_cnt = sev_dist.get("CRITICAL", 0)
    high_cnt = sev_dist.get("HIGH", 0)
    med_cnt = sev_dist.get("MEDIUM", 0)
    low_cnt = sev_dist.get("LOW", 0)

    # Repository Overview Banner
    langs_str = ", ".join(repo.get("languages", [])[:4]) or "N/A"
    fws_str = ", ".join(repo.get("frameworks", [])) or "None detected"

    st.markdown(
        f"""
        <div style="background: linear-gradient(135deg, #162032 0%, #111827 100%); border: 1px solid #26354d; border-radius: 12px; padding: 1.25rem; margin-bottom: 1.5rem;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px;">
                <div>
                    <h2 style="margin: 0; font-size: 1.3rem; font-weight: 700; color: #ffffff;">
                        📁 {repo.get('owner', 'Target')}/{repo.get('repository_name', 'Repository')}
                    </h2>
                    <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 4px;">
                        <b>URL:</b> <a href="{repo.get('url', '#')}" target="_blank" style="color: #06b6d4; text-decoration: none;">{repo.get('url', 'N/A')}</a>
                    </div>
                </div>
                <div style="display: flex; gap: 16px; font-size: 0.8rem; color: #94a3b8;">
                    <div><b>Languages:</b> <span style="color: #f3f4f6;">{langs_str}</span></div>
                    <div><b>Frameworks:</b> <span style="color: #f3f4f6;">{fws_str}</span></div>
                    <div><b>Files:</b> <span style="color: #f3f4f6;">{repo.get('total_files_analyzed', 0)}</span></div>
                    <div><b>Dependencies:</b> <span style="color: #f3f4f6;">{repo.get('dependencies_count', 0)}</span></div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Executive Metric Cards
    col1, col2, col3, col4, col5, col6 = st.columns(6)

    with col1:
        st.markdown(
            f"""
            <div class="stat-card">
                <div class="stat-label">Total Findings</div>
                <div class="stat-value" style="color: #ffffff;">{total_findings}</div>
                <div style="font-size: 0.7rem; color: #94a3b8; margin-top: 4px;">Static Alerts</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
            <div class="stat-card" style="border-left: 3px solid #ef4444;">
                <div class="stat-label" style="color: #fca5a5;">Critical</div>
                <div class="stat-value" style="color: #ef4444;">{crit_cnt}</div>
                <div style="font-size: 0.7rem; color: #94a3b8; margin-top: 4px;">Urgent Priority</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            f"""
            <div class="stat-card" style="border-left: 3px solid #f97316;">
                <div class="stat-label" style="color: #fdba74;">High</div>
                <div class="stat-value" style="color: #f97316;">{high_cnt}</div>
                <div style="font-size: 0.7rem; color: #94a3b8; margin-top: 4px;">High Exploitability</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col4:
        st.markdown(
            f"""
            <div class="stat-card" style="border-left: 3px solid #eab308;">
                <div class="stat-label" style="color: #fde047;">Medium</div>
                <div class="stat-value" style="color: #eab308;">{med_cnt}</div>
                <div style="font-size: 0.7rem; color: #94a3b8; margin-top: 4px;">Moderate Risk</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col5:
        st.markdown(
            f"""
            <div class="stat-card" style="border-left: 3px solid #10b981;">
                <div class="stat-label" style="color: #6ee7b7;">Confirmed</div>
                <div class="stat-value" style="color: #10b981;">{confirmed_cnt}</div>
                <div style="font-size: 0.7rem; color: #94a3b8; margin-top: 4px;">AI-Verified</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col6:
        st.markdown(
            f"""
            <div class="stat-card" style="border-left: 3px solid #64748b;">
                <div class="stat-label" style="color: #94a3b8;">False Positives</div>
                <div class="stat-value" style="color: #94a3b8;">{fp_cnt}</div>
                <div style="font-size: 0.7rem; color: #94a3b8; margin-top: 4px;">Filtered by Claude</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)
