"""Unit tests for Phase 2: Static Security Scanners & Repository Service."""

import os
from pathlib import Path
import pytest
from backend.services.repository_service import RepositoryService
from backend.scanners.bandit_scanner import BanditScanner
from backend.scanners.semgrep_scanner import SemgrepScanner
from backend.scanners.gitleaks_scanner import GitleaksScanner
from backend.scanners.dependency_scanner import DependencyScanner


@pytest.fixture
def vulnerable_repo(tmp_path) -> str:
    """Create a temporary sandbox repository containing intentional vulnerabilities."""
    repo_dir = tmp_path / "vulnerable_test_repo"
    repo_dir.mkdir()

    # 1. SQL Injection & MD5 (Bandit & Semgrep)
    db_file = repo_dir / "database.py"
    db_file.write_text(
        """
import hashlib
import sqlite3

def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Intentional SQL injection via f-string
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

def hash_password_insecure(password):
    # Insecure MD5 hash
    return hashlib.md5(password.encode()).hexdigest()
""",
        encoding="utf-8",
    )

    # 2. Hardcoded Credentials (Gitleaks / Secret Detector)
    config_file = repo_dir / "config.py"
    config_file.write_text(
        """
AWS_KEY = "AKIA1234567890EXAMPLE"
GITHUB_TOKEN = "ghp_123456789012345678901234567890123456"
DATABASE_URL = "postgres://admin:SuperSecretPass123@db.example.com/production"
""",
        encoding="utf-8",
    )

    # 3. Requirements Manifest (pip-audit & Repo Inspector)
    req_file = repo_dir / "requirements.txt"
    req_file.write_text(
        """
fastapi==0.110.0
requests==2.20.0
urllib3==1.24.2
""",
        encoding="utf-8",
    )

    return str(repo_dir)


def test_repository_inspection(vulnerable_repo):
    """Verify repository structure and tech stack inspection."""
    service = RepositoryService()
    overview = service.inspect_repository(
        repo_dir=vulnerable_repo,
        repo_name="vulnerable_test_repo",
        owner="test-owner",
        url="https://github.com/test-owner/vulnerable_test_repo",
    )

    assert "Python" in overview.languages
    assert "FastAPI" in overview.frameworks
    assert overview.total_files_analyzed >= 3
    assert any("database.py" in f for f in overview.important_files)


def test_bandit_scanner(vulnerable_repo):
    """Verify Bandit detects SQL injection (B608) and MD5 hash (B303)."""
    scanner = BanditScanner()
    findings, event = scanner.scan(vulnerable_repo, job_id="test_job_bandit")

    assert event.status in ("COMPLETED", "SKIPPED")
    if scanner.is_available():
        assert len(findings) >= 1
        # Check that MD5 or SQL injection was flagged
        categories = [f.category for f in findings]
        assert "Cryptographic Weakness" in categories or "Injection" in categories


def test_gitleaks_scanner(vulnerable_repo):
    """Verify Secret scanner detects exposed AWS keys, GitHub tokens, and DB credentials."""
    scanner = GitleaksScanner()
    findings, event = scanner.scan(vulnerable_repo, job_id="test_job_secrets")

    assert event.status == "COMPLETED"
    assert len(findings) >= 2
    assert all(f.category == "Secrets & Credentials" for f in findings)
    # Ensure sensitive tokens are redacted in findings
    for finding in findings:
        assert "AKIA1234567890EXAMPLE" not in finding.evidence
        assert "ghp_1234567890" not in finding.evidence


def test_semgrep_scanner(vulnerable_repo):
    """Verify Semgrep / Heuristics engine detects SQL injection and dangerous patterns."""
    scanner = SemgrepScanner()
    findings, event = scanner.scan(vulnerable_repo, job_id="test_job_semgrep")

    assert event.status == "COMPLETED"
    assert len(findings) >= 1
    titles = [f.title for f in findings]
    assert any("SQL Injection" in t for t in titles)
