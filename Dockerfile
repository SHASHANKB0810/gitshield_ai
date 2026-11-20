# Multi-Stage Secure Dockerfile for GitShield AI
# Follows security standards: minimal base image, non-root user execution, no hardcoded secrets.

FROM python:3.11-slim as base

# Set environment flags
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

# Install essential system dependencies (git for cloning)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user
RUN useradd -m -u 1001 -s /bin/bash appuser

# Set workspace
WORKDIR /app

# Copy and install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code with proper non-root ownership
COPY --chown=appuser:appuser . .

# Create workspace directory for temporary repository clones
RUN mkdir -p /app/.temp_repos && chown -R appuser:appuser /app/.temp_repos

# Switch to non-root user
USER 1001

# Expose backend API and Streamlit ports
EXPOSE 8000 8501

# Default command starts backend
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
