"""Unit tests for Phase 1 Foundation: Config, LLM Factory & Security Validation."""

import pytest
from backend.core.config import Settings, settings
from backend.core.llm_factory import LLMFactory
from backend.core.security import validate_github_url, sanitize_code_context, is_safe_subpath


def test_settings_initialization():
    """Verify settings defaults and masked API key generation."""
    s = Settings(LLM_API_KEY="test_ibm_key_12345678")
    assert s.LLM_MODEL == "claude-sonnet-5-5"
    assert s.LLM_BASE_URL == "https://api.servicesessentials.ibm.com/v1"
    assert s.get_masked_api_key() == "test...5678"


def test_github_url_validation():
    """Verify GitHub URL parsing, normalization, and attack vector rejection."""
    # Valid URLs
    is_valid, owner, repo, norm = validate_github_url("https://github.com/fastapi/fastapi")
    assert is_valid is True
    assert owner == "fastapi"
    assert repo == "fastapi"
    assert norm == "https://github.com/fastapi/fastapi"

    is_valid, owner, repo, norm = validate_github_url("https://github.com/owner-name/repo.git")
    assert is_valid is True
    assert owner == "owner-name"
    assert repo == "repo"

    # Invalid / Malicious URLs
    is_valid, _, _, _ = validate_github_url("http://github.com/insecure/repo")
    assert is_valid is False

    is_valid, _, _, _ = validate_github_url("https://gitlab.com/other/repo")
    assert is_valid is False

    is_valid, _, _, _ = validate_github_url("file:///etc/passwd")
    assert is_valid is False

    is_valid, _, _, _ = validate_github_url("https://github.com/../evil/repo")
    assert is_valid is False


def test_secret_sanitization():
    """Verify that credentials in code snippets are redacted before external LLM calls."""
    raw_snippet = """
    def connect_db():
        api_key = "sk-live-1234567890abcdef123456"
        password = "SuperSecretPassword123!"
        token = "ghp_123456789012345678901234567890123456"
        return True
    """
    sanitized = sanitize_code_context(raw_snippet)
    assert "sk-live-" not in sanitized
    assert "SuperSecretPassword123!" not in sanitized
    assert "ghp_1234567890" not in sanitized
    assert "[REDACTED" in sanitized


def test_path_traversal_guard(tmp_path):
    """Verify directory traversal prevention."""
    base_dir = str(tmp_path)
    safe_target = str(tmp_path / "subfolder" / "file.py")
    unsafe_target = str(tmp_path / ".." / "outside.py")

    assert is_safe_subpath(base_dir, safe_target) is True
    assert is_safe_subpath(base_dir, unsafe_target) is False


def test_llm_factory_instantiation():
    """Verify ChatOpenAI instantiation targeting IBM Services Essentials gateway."""
    client = LLMFactory.get_chat_model(
        model_name="claude-sonnet-5-5",
    )
    assert client.model_name == "claude-sonnet-5-5"
    assert str(client.openai_api_base).rstrip("/") == settings.LLM_BASE_URL.rstrip("/")
    assert client.temperature == 1.0
