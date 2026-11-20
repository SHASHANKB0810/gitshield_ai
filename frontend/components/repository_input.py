"""Streamlit Repository Input Component.

Provides a clean URL submission form with validation and quick targets.
"""

import streamlit as st
from frontend.api_client import api_client


def render_repository_input():
    """Render the repository submission and validation card."""
    st.markdown(
        """
        <div style="background: #111827; border: 1px solid #26354d; border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem;">
            <h3 style="margin: 0 0 0.5rem 0; font-size: 1.15rem; font-weight: 600; color: #ffffff;">
                🔍 Target Repository Analysis
            </h3>
            <p style="margin: 0 0 1rem 0; font-size: 0.85rem; color: #94a3b8;">
                Submit a public or authorized private GitHub repository URL to initiate multi-agent static security analysis, false-positive validation, and automated remediation.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns([4, 1])
    with col1:
        repo_url = st.text_input(
            "GitHub Repository URL",
            placeholder="https://github.com/owner/repository",
            label_visibility="collapsed",
            key="target_repo_url",
        )
    with col2:
        analyze_btn = st.button("🚀 Analyze", use_container_width=True, type="primary")

    # URL Validation on Submission
    if analyze_btn:
        if not repo_url:
            st.error("Please enter a valid GitHub repository URL.")
            return

        with st.spinner("Validating repository URL format and permissions..."):
            validation_result = api_client.validate_url(repo_url)

        if not validation_result.get("valid"):
            st.error(f"Invalid URL: {validation_result.get('error', 'Unknown format')}")
        else:
            owner = validation_result.get("owner")
            repo = validation_result.get("repo")
            st.success(f"Target validated: `{owner}/{repo}`. Ready for multi-agent security pipeline.")
            st.session_state["validated_target"] = validation_result
