"""Streamlit Report Export and Download Component."""

from typing import Any, Dict
import streamlit as st
from frontend.api_client import api_client


def render_report_download(job_id: str, report: Dict[str, Any]):
    """Render report export and download action buttons."""
    st.markdown(
        """
        <div style="background: #111827; border: 1px solid #26354d; border-radius: 12px; padding: 1.25rem; margin-top: 2rem;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h3 style="margin: 0; font-size: 1.1rem; font-weight: 600; color: #ffffff;">
                        📥 Export & Download Security Report
                    </h3>
                    <p style="margin: 4px 0 0 0; font-size: 0.8rem; color: #94a3b8;">
                        Download complete security findings, remediation patches, and execution history.
                    </p>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)

    with col1:
        md_content = api_client.get_markdown_report(job_id)
        if md_content:
            st.download_button(
                label="📄 Download Markdown Report (.md)",
                data=md_content,
                file_name=f"gitshield_security_report_{job_id}.md",
                mime="text/markdown",
                use_container_width=True,
            )
        else:
            st.button("📄 Markdown Report Unavailable", disabled=True, use_container_width=True)

    with col2:
        json_content = api_client.get_json_report(job_id)
        if json_content:
            st.download_button(
                label="📊 Download JSON Dataset (.json)",
                data=json_content,
                file_name=f"gitshield_report_{job_id}.json",
                mime="application/json",
                use_container_width=True,
            )
        else:
            st.button("📊 JSON Report Unavailable", disabled=True, use_container_width=True)
