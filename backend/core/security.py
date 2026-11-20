"""Security Validation and Sanitization Module.

Provides input validation for GitHub URLs, path safety checks,
and secret redaction to prevent SSRF and prompt injection risks.
"""

import os
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

# Strict regex matching valid GitHub repository URLs
GITHUB_URL_PATTERN = re.compile(
    r"^https://github\.com/([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+?)(?:\.git)?/?$"
)

# Sensitive patterns to scrub before sending code context to external LLM
SECRET_REPLACEMENT_PATTERNS = [
    (re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"(api[_-]?key\s*[:=]\s*['\"])[^'\"]{8,}(['\"])", re.IGNORECASE), r"\1[REDACTED_API_KEY]\2"),
    (re.compile(r"(secret\s*[:=]\s*['\"])[^'\"]{8,}(['\"])", re.IGNORECASE), r"\1[REDACTED_SECRET]\2"),
    (re.compile(r"(password\s*[:=]\s*['\"])[^'\"]+(['\"])", re.IGNORECASE), r"\1[REDACTED_PASSWORD]\2"),
    (re.compile(r"(ghp_[A-Za-z0-9]{30,})", re.IGNORECASE), r"[REDACTED_GH_TOKEN]"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]{16,}", re.IGNORECASE), r"\1[REDACTED_BEARER_TOKEN]"),
    (re.compile(r"(?:postgres|mysql|mongodb|redis)://([^:]+):([^@]+)@"), r"[REDACTED_DB_URL]"),
    (re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----"), r"[REDACTED_PRIVATE_KEY]"),
]


def validate_github_url(url: str) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """Validate that the input is a legitimate public or authorized GitHub URL.

    Returns:
        (is_valid, owner, repo, normalized_url_or_error)
    """
    if not url or not isinstance(url, str):
        return False, None, None, "URL must be a non-empty string"

    cleaned_url = url.strip()
    parsed = urlparse(cleaned_url)

    # Reject non-https protocols and invalid hosts
    if parsed.scheme.lower() != "https":
        return False, None, None, f"Only HTTPS GitHub URLs are permitted (received {parsed.scheme}://)"

    if parsed.netloc.lower() not in ("github.com", "www.github.com"):
        return False, None, None, f"Host must be github.com (received {parsed.netloc})"

    match = GITHUB_URL_PATTERN.match(cleaned_url)
    if not match:
        return False, None, None, "Invalid GitHub repository URL format. Example: https://github.com/owner/repo"

    owner, repo = match.group(1), match.group(2)
    
    # Check for path traversal or malicious characters in owner/repo
    for component in (owner, repo):
        if ".." in component or "/" in component or "\\" in component:
            return False, None, None, "Invalid characters detected in repository name"

    normalized_url = f"https://github.com/{owner}/{repo}"
    return True, owner, repo, normalized_url


def sanitize_code_context(code: str) -> str:
    """Scrub potential credentials and secrets from code snippets before LLM transmission."""
    if not code:
        return ""
    
    sanitized = code
    for pattern, replacement in SECRET_REPLACEMENT_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def is_safe_subpath(base_dir: str, target_path: str) -> bool:
    """Ensure that target_path resolves strictly within base_dir (prevent path traversal)."""
    base_abs = os.path.abspath(base_dir)
    target_abs = os.path.abspath(target_path)
    return target_abs.startswith(base_abs)
