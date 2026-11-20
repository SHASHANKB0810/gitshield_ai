"""Streamlit Live Agent & Tool Execution Monitor Component.

Displays real-time execution status, timestamps, findings count,
and operational progress for all five agents and underlying scanners.
"""

from typing import Any, Dict, List
import streamlit as st


def render_agent_monitor(events: List[Dict[str, Any]], job_status: str):
    """Render the live execution timeline tracking agents and deterministic tools."""
    st.markdown(
        """
        <div style="background: #111827; border: 1px solid #26354d; border-radius: 12px; padding: 1.25rem; margin-bottom: 1.5rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 1.2rem;">⚡</span>
                    <h3 style="margin: 0; font-size: 1.1rem; font-weight: 600; color: #ffffff;">
                        Live Agent & Scanner Execution Monitor
                    </h3>
                </div>
                <span class="status-pill">
                    <span style="font-size: 0.75rem; color: #94a3b8;">Job State: <b>"""
        + job_status
        + """</b></span>
                </span>
            </div>
        """,
        unsafe_allow_html=True,
    )

    # Expected agents and tools map
    pipeline_items = [
        {"agent": "Repository Analysis Agent", "tool": "Git Ingestion Service", "icon": "📂"},
        {"agent": "Security Detection Agent", "tool": "Semgrep", "icon": "🔍"},
        {"agent": "Security Detection Agent", "tool": "Bandit", "icon": "🐍"},
        {"agent": "Security Detection Agent", "tool": "Gitleaks", "icon": "🔑"},
        {"agent": "Security Detection Agent", "tool": "pip-audit", "icon": "📦"},
        {"agent": "Vulnerability Validation Agent", "tool": "Claude Sonnet 5.5", "icon": "🧠"},
        {"agent": "Risk Assessment Agent", "tool": "Claude Sonnet 5.5", "icon": "⚖️"},
        {"agent": "Remediation and Verification Agent", "tool": "Claude Sonnet 5.5 + Rescan Verifier", "icon": "🛡️"},
    ]

    event_map = {}
    for evt in events:
        key = (evt.get("agent"), evt.get("tool"))
        event_map[key] = evt

    cols = st.columns(4)
    for idx, item in enumerate(pipeline_items):
        col = cols[idx % 4]
        agent_name = item["agent"]
        tool_name = item["tool"]
        icon = item["icon"]

        # Match event
        matched_evt = event_map.get((agent_name, tool_name))
        if not matched_evt:
            # Fallback search by agent or tool substring
            for k, evt in event_map.items():
                if tool_name and tool_name.lower() in str(evt.get("tool", "")).lower():
                    matched_evt = evt
                    break
                elif agent_name and agent_name.lower() in str(evt.get("agent", "")).lower():
                    matched_evt = evt
                    break

        status = matched_evt.get("status", "PENDING") if matched_evt else ("RUNNING" if job_status == "RUNNING" and idx == 0 else "PENDING")
        msg = matched_evt.get("message", "Awaiting execution in pipeline...") if matched_evt else "Pending queue..."
        findings_cnt = matched_evt.get("findings_count") if matched_evt else None

        status_color = {
            "COMPLETED": "#10b981",
            "RUNNING": "#06b6d4",
            "FAILED": "#ef4444",
            "SKIPPED": "#64748b",
            "PENDING": "#475569",
        }.get(status, "#475569")

        badge_text = {
            "COMPLETED": "✓ COMPLETED",
            "RUNNING": "● RUNNING",
            "FAILED": "✗ FAILED",
            "SKIPPED": "⊘ SKIPPED",
            "PENDING": "○ PENDING",
        }.get(status, status)

        with col:
            st.markdown(
                f"""
                <div style="background: #162032; border: 1px solid {status_color}40; border-radius: 8px; padding: 12px; margin-bottom: 12px; min-height: 120px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span style="font-size: 1.1rem;">{icon}</span>
                        <span style="font-size: 0.65rem; font-weight: 700; color: {status_color}; background: {status_color}15; padding: 2px 6px; border-radius: 4px; border: 1px solid {status_color}40;">
                            {badge_text}
                        </span>
                    </div>
                    <div style="font-size: 0.82rem; font-weight: 600; color: #f3f4f6; margin-bottom: 2px;">
                        {tool_name or agent_name}
                    </div>
                    <div style="font-size: 0.72rem; color: #94a3b8; line-height: 1.3; overflow: hidden; text-overflow: ellipsis;">
                        {msg[:75]}
                    </div>
                    {f'<div style="font-size: 0.7rem; color: #06b6d4; font-weight: 600; margin-top: 6px;">Findings: {findings_cnt}</div>' if findings_cnt is not None else ''}
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("</div>", unsafe_allow_html=True)
