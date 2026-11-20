"""GitShield AI Frontend API Client.

Handles HTTP communication between Streamlit frontend and FastAPI backend.
"""

from typing import Any, Dict, List, Optional
import requests
from backend.core.config import settings


class APIClient:
    """Synchronous REST client for Streamlit UI interactions."""

    def __init__(self, base_url: Optional[str] = None):
        host = settings.BACKEND_HOST
        port = settings.BACKEND_PORT
        self.base_url = base_url or f"http://{host}:{port}"
        self.timeout = (10.0, 30.0)

    def check_health(self) -> Dict[str, Any]:
        """Query backend health status."""
        try:
            resp = requests.get(f"{self.base_url}/health", timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            return {"status": "unhealthy", "error": f"HTTP {resp.status_code}"}
        except requests.exceptions.RequestException as e:
            return {"status": "unreachable", "error": str(e)}

    def check_llm_status(self) -> Dict[str, Any]:
        """Query IBM Services Essentials LLM gateway connectivity and model status."""
        try:
            resp = requests.get(f"{self.base_url}/api/v1/llm/status", timeout=20.0)
            if resp.status_code == 200:
                return resp.json()
            return {
                "status": "ERROR",
                "message": f"Backend returned HTTP {resp.status_code}",
                "model": settings.LLM_MODEL,
                "provider": settings.LLM_PROVIDER,
            }
        except requests.exceptions.RequestException as e:
            return {
                "status": "UNREACHABLE",
                "message": f"Could not reach backend: {e}",
                "model": settings.LLM_MODEL,
                "provider": settings.LLM_PROVIDER,
            }

    def validate_url(self, repo_url: str) -> Dict[str, Any]:
        """Validate candidate repository URL."""
        try:
            resp = requests.post(
                f"{self.base_url}/api/v1/validate-url",
                json={"url": repo_url},
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                return resp.json()
            return {"valid": False, "error": f"HTTP {resp.status_code}"}
        except requests.exceptions.RequestException as e:
            return {"valid": False, "error": f"Backend unreachable: {e}"}

    def start_analysis(
        self,
        repository_url: str,
        branch: Optional[str] = None,
        enable_validation: bool = True,
        enable_remediation: bool = True,
    ) -> Dict[str, Any]:
        """Submit repository for analysis."""
        try:
            payload = {
                "repository_url": repository_url,
                "branch": branch,
                "enable_validation": enable_validation,
                "enable_remediation": enable_remediation,
            }
            resp = requests.post(f"{self.base_url}/api/v1/analyze", json=payload, timeout=self.timeout)
            if resp.status_code in (200, 202):
                return resp.json()
            return {"error": resp.json().get("detail", f"HTTP {resp.status_code}")}
        except requests.exceptions.RequestException as e:
            return {"error": f"Failed to connect to backend: {e}"}

    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """Retrieve active status of an analysis job."""
        try:
            resp = requests.get(f"{self.base_url}/api/v1/analyze/{job_id}", timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            return {"status": "UNKNOWN", "error": f"HTTP {resp.status_code}"}
        except requests.exceptions.RequestException as e:
            return {"status": "UNREACHABLE", "error": str(e)}

    def get_events(self, job_id: str) -> List[Dict[str, Any]]:
        """Retrieve real-time execution telemetry events."""
        try:
            resp = requests.get(f"{self.base_url}/api/v1/events/{job_id}", timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            return []
        except Exception:
            return []

    def get_report(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve complete analysis report."""
        try:
            resp = requests.get(f"{self.base_url}/api/v1/report/{job_id}", timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception:
            return None

    def get_markdown_report(self, job_id: str) -> Optional[str]:
        """Download Markdown report string."""
        try:
            resp = requests.get(f"{self.base_url}/api/v1/report/{job_id}/markdown", timeout=self.timeout)
            if resp.status_code == 200:
                return resp.text
            return None
        except Exception:
            return None

    def get_json_report(self, job_id: str) -> Optional[str]:
        """Download JSON report string."""
        try:
            resp = requests.get(f"{self.base_url}/api/v1/report/{job_id}/json", timeout=self.timeout)
            if resp.status_code == 200:
                return resp.text
            return None
        except Exception:
            return None


# Global API client instance
api_client = APIClient()
