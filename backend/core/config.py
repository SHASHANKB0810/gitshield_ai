"""GitShield AI Configuration Module.

Loads and validates environment configuration using Pydantic Settings.
Secrets are masked to prevent accidental credential leakage in logs.
"""

from typing import Literal
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable loading and validation."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # LLM Gateway Configuration (IBM Services Essentials)
    LLM_API_KEY: str = Field(
        default="",
        description="API key for IBM Services Essentials OpenAI-compatible gateway",
    )
    LLM_BASE_URL: str = Field(
        default="https://api.servicesessentials.ibm.com/v1",
        description="Base URL for LLM completions",
    )
    LLM_MODEL: str = Field(
        default="claude-sonnet-5-5",
        description="Default reasoning model identifier",
    )
    LLM_PROVIDER: str = Field(
        default="ibm",
        description="Provider name for reporting and routing",
    )
    LLM_API_FORMAT: Literal["openai", "anthropic", "custom"] = Field(
        default="openai",
        description="Wire protocol format used by the gateway",
    )
    LLM_TEMPERATURE: float = Field(
        default=1.0,
        ge=0.0,
        le=2.0,
        description="Sampling temperature for reasoning (IBM Claude gateway requires temperature=1.0)",
    )
    LLM_MAX_TOKENS: int = Field(
        default=4096,
        gt=0,
        description="Max token limit for agent completions",
    )
    LLM_TIMEOUT_SECONDS: float = Field(
        default=60.0,
        gt=0.0,
        description="Timeout for LLM API requests in seconds",
    )

    # GitHub Access
    GITHUB_TOKEN: str = Field(
        default="",
        description="Optional personal access token for GitHub API",
    )

    # Server Configuration
    BACKEND_HOST: str = Field(
        default="127.0.0.1",
        description="Backend host bind address",
    )
    BACKEND_PORT: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="Backend HTTP port",
    )
    FRONTEND_PORT: int = Field(
        default=8501,
        ge=1,
        le=65535,
        description="Streamlit frontend port",
    )

    # Environment & Logging
    APP_ENV: Literal["development", "staging", "production", "test"] = Field(
        default="development",
        description="Execution environment",
    )
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Logging level",
    )

    # Storage & Limits
    CLONE_STORAGE_DIR: str = Field(
        default=".temp_repos",
        description="Local directory for temporary repository clones",
    )
    MAX_REPO_SIZE_MB: int = Field(
        default=250,
        gt=0,
        description="Maximum allowed repository download size in megabytes",
    )
    ANALYSIS_TIMEOUT_SECONDS: int = Field(
        default=300,
        gt=0,
        description="Maximum duration allowed for an analysis job",
    )

    @field_validator("LLM_BASE_URL")
    @classmethod
    def validate_base_url(cls, v: str) -> str:
        """Validate and sanitize the LLM Gateway Base URL."""
        v = v.strip().rstrip("/")
        if not v.startswith(("http://", "https://")):
            raise ValueError(f"LLM_BASE_URL must begin with http:// or https://: {v}")
        return v

    def get_masked_api_key(self) -> str:
        """Return a safe masked version of the LLM API key for diagnostics."""
        if not self.LLM_API_KEY:
            return "NOT_CONFIGURED"
        key = self.LLM_API_KEY.strip()
        if len(key) <= 8:
            return "***"
        return f"{key[:4]}...{key[-4:]}"


# Global settings singleton instance
settings = Settings()
