"""GitShield AI — Main Security Operations Center Dashboard.

Coordinates real-time polling, multi-agent status tracking, dynamic category
breakdowns, and patch reviews in a modern dark-navy SOC interface.
"""

import os
import time
import streamlit as st

try:
    from streamlit_autorefresh import st_autorefresh
except ImportError:
    def st_autorefresh(interval=2000, limit=None, key=None):
        time.sleep(interval / 1000.0)
        st.rerun()

from frontend.api_client import api_client
from frontend.components.sidebar import render_sidebar
from frontend.components.agent_monitor import render_agent_monitor
from frontend.components.security_overview import render_security_overview
from frontend.components.category_breakdown import render_category_breakdown
from frontend.components.report_download import render_report_download


# Streamlit Page Setup
st.set_page_config(
    page_title="GitShield AI — Repository Security Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# Load Dark Navy Custom CSS
def load_css():
    css_path = os.path.join(os.path.dirname(__file__), "styles", "theme.css")
    if os.path.exists(css_path):
        with open(css_path, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


load_css()

# Render Global Sidebar
render_sidebar()

# Main Application Top Header
st.markdown(
    """
    <div class="gitshield-header">
        <div class="gitshield-brand">
            <span class="brand-icon">🛡️</span>
            <div>
                <h1 class="brand-title">GitShield AI</h1>
                <p class="brand-subtitle">Multi-Agent AI-Powered GitHub Security Analysis & Automated Remediation</p>
            </div>
        </div>
        <div style="display: flex; gap: 8px; align-items: center;">
            <span class="badge badge-critical" style="font-size: 0.75rem;">LLM: Claude Sonnet 5.5</span>
            <span class="badge badge-low" style="font-size: 0.75rem;">IBM Gateway</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Initialize Session State Variables
if "active_job_id" not in st.session_state:
    st.session_state["active_job_id"] = None
if "job_status" not in st.session_state:
    st.session_state["job_status"] = None
if "cached_report" not in st.session_state:
    st.session_state["cached_report"] = None


# Repository Submission Card
with st.container():
    st.markdown(
        """
        <div style="background: #111827; border: 1px solid #26354d; border-radius: 12px; padding: 1.25rem; margin-bottom: 1.5rem;">
            <h3 style="margin: 0 0 0.5rem 0; font-size: 1.15rem; font-weight: 600; color: #ffffff;">
                🔍 Target Repository Analysis
            </h3>
            <p style="margin: 0 0 1rem 0; font-size: 0.85rem; color: #94a3b8;">
                Submit a public or authorized private GitHub repository URL to initiate deterministic security scanning (Semgrep, Bandit, Gitleaks, pip-audit), Claude Sonnet 5.5 false-positive validation, and automated remediation.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2, col3 = st.columns([5, 1, 1])
    with col1:
        repo_url_input = st.text_input(
            "GitHub Repository URL",
            placeholder="https://github.com/owner/repository",
            label_visibility="collapsed",
            key="repo_input_field",
        )
    with col2:
        start_btn = st.button("🚀 Analyze", use_container_width=True, type="primary")
    with col3:
        if st.session_state.get("active_job_id"):
            if st.button("🔄 Reset", use_container_width=True):
                st.session_state["active_job_id"] = None
                st.session_state["job_status"] = None
                st.session_state["cached_report"] = None
                st.rerun()

    # Handle Analysis Initiation
    if start_btn:
        if not repo_url_input:
            st.error("Please enter a valid GitHub repository URL.")
        else:
            with st.spinner("Submitting target repository to GitShield AI backend..."):
                resp = api_client.start_analysis(repo_url_input.strip())
                if "error" in resp:
                    st.error(f"Failed to start analysis: {resp.get('error')}")
                else:
                    st.session_state["active_job_id"] = resp.get("job_id")
                    st.session_state["job_status"] = "QUEUED"
                    st.session_state["cached_report"] = None
                    st.success(f"Analysis dispatched! Tracking Job ID: `{resp.get('job_id')}`")
                    st.rerun()


# Active Job Tracking & Visualization
job_id = st.session_state.get("active_job_id")

if job_id:
    # Query current job status and events from backend
    status_data = api_client.get_job_status(job_id)
    current_status = status_data.get("status", "UNKNOWN")
    st.session_state["job_status"] = current_status
    events = api_client.get_events(job_id)

    # Auto-refresh while job is running or queued
    if current_status in ("QUEUED", "RUNNING"):
        st_autorefresh(interval=2500, limit=120, key="job_monitor_autorefresh")

        st.markdown(
            f"""
            <div style="background: rgba(6, 182, 212, 0.1); border: 1px solid #06b6d4; border-radius: 8px; padding: 12px 16px; margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: center;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 1.2rem;">⚙️</span>
                    <div>
                        <span style="font-weight: 700; color: #06b6d4;">Analysis in Progress</span>
                        <div style="font-size: 0.75rem; color: #94a3b8;">Job ID: <code>{job_id}</code> | Polling execution events...</div>
                    </div>
                </div>
                <span class="badge badge-low">● {current_status}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        render_agent_monitor(events, current_status)

    elif current_status == "COMPLETED":
        # Fetch or retrieve cached report
        if not st.session_state.get("cached_report"):
            st.session_state["cached_report"] = api_client.get_report(job_id)

        report = st.session_state.get("cached_report")
        if report:
            # 1. Executive Security Overview
            render_security_overview(report)

            # 2. Live Agent Monitor
            render_agent_monitor(events, current_status)

            # 3. Categorized Findings & Patch Reviews
            render_category_breakdown(report.get("vulnerabilities", []))

            # 4. Report Downloads
            render_report_download(job_id, report)
        else:
            st.warning("Analysis completed, but report data is currently being formatted. Refreshing...")
            st_autorefresh(interval=2000, limit=5, key="report_load_autorefresh")

    elif current_status == "FAILED":
        err_msg = status_data.get("error", "Unknown pipeline error occurred.")
        st.markdown(
            f"""
            <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid #ef4444; border-radius: 8px; padding: 16px; margin-bottom: 1.5rem;">
                <h4 style="color: #ef4444; margin: 0 0 4px 0;">❌ Analysis Failed</h4>
                <p style="color: #fca5a5; font-size: 0.85rem; margin: 0;">{err_msg}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        render_agent_monitor(events, current_status)

else:
    # Empty State Guide when no analysis is active
    st.markdown(
        """
        <div style="background: #111827; border: 1px dashed #26354d; border-radius: 12px; padding: 2.5rem 1.5rem; text-align: center; margin-top: 1rem;">
            <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">🛡️</div>
            <h3 style="color: #ffffff; font-weight: 700; margin: 0 0 0.5rem 0;">Ready for Repository Security Analysis</h3>
            <p style="color: #94a3b8; font-size: 0.88rem; max-width: 650px; margin: 0 auto 1.5rem auto; line-height: 1.5;">
                Enter a GitHub repository URL above to launch the autonomous security intelligence pipeline.
                Static scanners will detect raw alerts, followed by Claude Sonnet 5.5 taint validation, risk modeling, and verified patch generation.
            </p>
            <div style="display: flex; justify-content: center; gap: 24px; font-size: 0.8rem; color: #06b6d4; flex-wrap: wrap;">
                <span>✓ Zero Scanner Hallucination</span>
                <span>✓ Claude Sonnet 5.5 False-Positive Filtering</span>
                <span>✓ Automated Patch Verification</span>
                <span>✓ Real-time Telemetry Monitor</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
