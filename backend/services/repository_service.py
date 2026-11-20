"""Repository Ingestion and Analysis Service.

Handles secure shallow Git cloning, directory traversal, manifest discovery,
and technology stack identification within an isolated workspace.
"""

import os
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from backend.core.config import settings
from backend.core.logging import logger
from backend.core.security import validate_github_url, is_safe_subpath
from backend.api.schemas import RepositoryOverview


# File extensions mapped to programming languages
LANGUAGE_EXTENSION_MAP = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".c": "C",
    ".cpp": "C++",
    ".h": "C/C++ Header",
    ".cs": "C#",
    ".php": "PHP",
    ".rb": "Ruby",
    ".sh": "Shell",
    ".html": "HTML",
    ".css": "CSS",
    ".sql": "SQL",
}

# Directories and patterns to exclude from analysis
EXCLUDE_DIRS = {
    ".git", ".github", ".venv", "venv", "env", "node_modules",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".tox",
    "dist", "build", "target", "coverage", ".idea", ".vscode"
}

# Key configuration and security-sensitive files
SECURITY_SENSITIVE_FILES = {
    "requirements.txt", "pyproject.toml", "Pipfile", "setup.py",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".env.example", ".env.sample", ".env.template",
    "auth.py", "security.py", "database.py", "db.py", "routes.py",
    "config.py", "settings.py"
}


class RepositoryService:
    """Manages repository cloning, scanning scope, and metadata extraction."""

    def __init__(self, base_storage_dir: Optional[str] = None):
        self.base_storage_dir = Path(base_storage_dir or settings.CLONE_STORAGE_DIR).resolve()
        self.base_storage_dir.mkdir(parents=True, exist_ok=True)

    def clone_repository(
        self,
        repository_url: str,
        job_id: Optional[str] = None,
        branch: Optional[str] = None,
    ) -> Tuple[bool, str, str]:
        """Perform a shallow clone of the target repository into an isolated directory.

        Args:
            repository_url: GitHub HTTPS URL.
            job_id: Unique analysis job identifier.
            branch: Optional branch name.

        Returns:
            Tuple of (success: bool, target_path_or_error: str, repo_name: str)
        """
        is_valid, owner, repo_name, norm_url = validate_github_url(repository_url)
        if not is_valid or not norm_url:
            return False, f"Invalid repository URL: {norm_url}", ""

        job_uuid = job_id or str(uuid.uuid4())
        dest_dir = self.base_storage_dir / f"{job_uuid}_{repo_name}"

        # Ensure directory is empty
        if dest_dir.exists():
            shutil.rmtree(dest_dir, ignore_errors=True)

        # Build git clone command with shallow depth and security options
        git_cmd = [
            "git", "clone",
            "--depth", "1",
            "--single-branch",
        ]
        if branch:
            git_cmd.extend(["--branch", branch])

        # Inject auth token if available (without logging credentials)
        clone_url = norm_url
        if settings.GITHUB_TOKEN:
            token = settings.GITHUB_TOKEN.strip()
            clone_url = f"https://x-access-token:{token}@github.com/{owner}/{repo_name}.git"
        else:
            clone_url = f"{norm_url}.git"

        git_cmd.extend([clone_url, str(dest_dir)])

        logger.info(f"Cloning repository {owner}/{repo_name} into {dest_dir}")
        try:
            result = subprocess.run(
                git_cmd,
                capture_output=True,
                text=True,
                timeout=settings.ANALYSIS_TIMEOUT_SECONDS,
            )
            if result.returncode != 0:
                err_msg = result.stderr.strip() or "Git clone failed."
                logger.error(f"Git clone error: {err_msg}")
                return False, f"Failed to clone repository: {err_msg}", repo_name

            return True, str(dest_dir), repo_name

        except subprocess.TimeoutExpired:
            shutil.rmtree(dest_dir, ignore_errors=True)
            return False, "Repository clone timed out.", repo_name
        except FileNotFoundError:
            return False, "Git executable not found on host system.", repo_name
        except Exception as e:
            shutil.rmtree(dest_dir, ignore_errors=True)
            logger.error(f"Unexpected error cloning repository: {e}")
            return False, f"Clone failed: {type(e).__name__}", repo_name

    def inspect_repository(self, repo_dir: str, repo_name: str, owner: str, url: str) -> RepositoryOverview:
        """Analyze local repository structure, files, dependencies, and frameworks."""
        repo_path = Path(repo_dir)
        languages: Dict[str, int] = {}
        important_files: List[str] = []
        frameworks: List[str] = []
        total_files = 0
        dependencies_count = 0

        for root, dirs, files in os.walk(repo_path):
            # Prune excluded directories
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(repo_path).as_posix()
                ext = file_path.suffix.lower()

                total_files += 1

                # Track programming languages by extension
                if ext in LANGUAGE_EXTENSION_MAP:
                    lang = LANGUAGE_EXTENSION_MAP[ext]
                    languages[lang] = languages.get(lang, 0) + 1

                # Detect important/security-sensitive files
                if file in SECURITY_SENSITIVE_FILES or any(sec in rel_path for sec in ["auth", "security", "api"]):
                    important_files.append(rel_path)

                # Framework heuristics
                if file == "requirements.txt" or file == "pyproject.toml":
                    deps_found, detected_fws = self._parse_python_manifest(file_path)
                    dependencies_count += deps_found
                    frameworks.extend(detected_fws)
                elif file == "package.json":
                    deps_found, detected_fws = self._parse_node_manifest(file_path)
                    dependencies_count += deps_found
                    frameworks.extend(detected_fws)

        sorted_languages = [lang for lang, _ in sorted(languages.items(), key=lambda x: x[1], reverse=True)]
        unique_frameworks = sorted(list(set(frameworks)))

        return RepositoryOverview(
            repository_name=repo_name,
            owner=owner,
            url=url,
            languages=sorted_languages,
            frameworks=unique_frameworks,
            dependencies_count=dependencies_count,
            total_files_analyzed=total_files,
            important_files=sorted(important_files)[:25],
        )

    def _parse_python_manifest(self, file_path: Path) -> Tuple[int, List[str]]:
        """Extract dependency count and frameworks from Python manifests."""
        deps = 0
        frameworks = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore").lower()
            lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
            deps = len(lines)

            if "fastapi" in content:
                frameworks.append("FastAPI")
            if "flask" in content:
                frameworks.append("Flask")
            if "django" in content:
                frameworks.append("Django")
            if "sqlalchemy" in content:
                frameworks.append("SQLAlchemy")
            if "pydantic" in content:
                frameworks.append("Pydantic")
        except Exception as e:
            logger.debug(f"Failed to parse python manifest {file_path}: {e}")

        return deps, frameworks

    def _parse_node_manifest(self, file_path: Path) -> Tuple[int, List[str]]:
        """Extract dependency count and frameworks from package.json."""
        deps = 0
        frameworks = []
        try:
            import json
            data = json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
            all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            deps = len(all_deps)

            dep_keys = [k.lower() for k in all_deps.keys()]
            if "express" in dep_keys:
                frameworks.append("Express.js")
            if "react" in dep_keys:
                frameworks.append("React")
            if "next" in dep_keys:
                frameworks.append("Next.js")
            if "vue" in dep_keys:
                frameworks.append("Vue.js")
        except Exception as e:
            logger.debug(f"Failed to parse node manifest {file_path}: {e}")

        return deps, frameworks

    def cleanup_repository(self, target_path: str) -> bool:
        """Safely remove temporary clone directory."""
        if not target_path or not is_safe_subpath(str(self.base_storage_dir), target_path):
            logger.warning(f"Refusing to delete unsafe or outside path: {target_path}")
            return False

        try:
            if os.path.exists(target_path):
                shutil.rmtree(target_path, ignore_errors=True)
                logger.info(f"Cleaned up repository at {target_path}")
            return True
        except Exception as e:
            logger.error(f"Error cleaning up repository {target_path}: {e}")
            return False


# Global service instance
repository_service = RepositoryService()
