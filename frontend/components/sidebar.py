"""Streamlit Sidebar Component.

Displays branding, system status, LLM gateway health, and configuration info.
"""

import streamlit as st
from frontend.api_client import api_client
from backend.core.config import settings


def render_sidebar():
    """Render the application sidebar."""
    with st.sidebar:
        # Branding Header
        st.markdown(
            """
            <div style="padding: 10px 0 20px 0; border-bottom: 1px solid #26354d;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 2rem;">🛡️</span>
                    <div>
                        <h2 style="margin: 0; font-size: 1.3rem; font-weight: 700; color: #ffffff;">GitShield AI</h2>
                        <span style="font-size: 0.75rem; color: #06b6d4; font-weight: 600; letter-spacing: 0.05em;">SEC-OPS PLATFORM</span>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("### 📡 System Diagnostics")

        # Backend Health Status
        health_info = api_client.check_health()
        backend_status = health_info.get("status", "unknown").upper()
        if backend_status == "HEALTHY":
            st.markdown(
                """
                <div class="status-pill" style="width: 100%; margin-bottom: 8px;">
                    <div class="status-dot healthy"></div>
                    <span style="color: #10b981; font-weight: 600;">Backend API: Online</span>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f"""
                <div class="status-pill" style="width: 100%; margin-bottom: 8px;">
                    <div class="status-dot error"></div>
                    <span style="color: #ef4444; font-weight: 600;">Backend: {backend_status}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # LLM Gateway Status Check Button
        if st.button("🔄 Test LLM Gateway", use_container_width=True):
            with st.spinner("Pinging IBM Services Essentials..."):
                st.session_state["llm_status"] = api_client.check_llm_status()

        llm_status = st.session_state.get("llm_status")
        if llm_status:
            status_val = llm_status.get("status", "UNKNOWN")
            model_val = llm_status.get("model", settings.LLM_MODEL)
            latency = llm_status.get("latency_ms")

            if status_val == "HEALTHY":
                st.markdown(
                    f"""
                    <div style="background: #162032; border: 1px solid #10b981; border-radius: 8px; padding: 10px; margin-top: 10px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-size: 0.8rem; font-weight: 700; color: #10b981;">✓ LLM CONNECTED</span>
                            <span style="font-size: 0.7rem; color: #94a3b8;">{latency}ms</span>
                        </div>
                        <div style="font-size: 0.75rem; color: #f3f4f6; margin-top: 4px;">
                            <b>Model:</b> {model_val}<br>
                            <b>Gateway:</b> IBM Services
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"""
                    <div style="background: #162032; border: 1px solid #ef4444; border-radius: 8px; padding: 10px; margin-top: 10px;">
                        <div style="font-size: 0.8rem; font-weight: 700; color: #ef4444;">⚠ LLM STATUS: {status_val}</div>
                        <div style="font-size: 0.75rem; color: #f3f4f6; margin-top: 4px;">
                            {llm_status.get('message', 'No details available')}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        st.markdown("<br><hr style='border-color: #26354d;'><br>", unsafe_allow_html=True)

        # Quick Architecture Legend
        st.markdown(
            """
            <div style="font-size: 0.75rem; color: #94a3b8;">
                <p><b>Orchestration:</b> LangGraph Multi-Agent</p>
                <p><b>Reasoning:</b> Claude Sonnet 5.5</p>
                <p><b>Scanners:</b> Semgrep, Bandit, Gitleaks, pip-audit</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
