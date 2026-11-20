# 🛡️ GitShield AI
### Multi-Agent AI-Powered GitHub Repository Security Analysis & Automated Remediation Platform

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Frontend-Streamlit-FF4B4B?logo=streamlit)](https://streamlit.io)
[![LangGraph](https://img.shields.io/badge/Orchestration-LangGraph-blue)](https://github.com/langchain-ai/langgraph)
[![Claude Sonnet 5.5](https://img.shields.io/badge/LLM-Claude%20Sonnet%205.5-orange)](https://anthropic.com)
[![IBM Services Essentials](https://img.shields.io/badge/Gateway-IBM%20Services%20Essentials-052FAD?logo=ibm)](https://ibm.com)

---

## 📖 Overview

**GitShield AI** is a multi-agent application security intelligence platform that combines **deterministic static security tools** (Semgrep, Bandit, Gitleaks, pip-audit) with **specialized AI reasoning agents** orchestrated via **LangGraph** and powered by **Claude Sonnet 5.5** through the **IBM Services Essentials OpenAI-compatible gateway**.

Unlike standard AI chatbots that hallucinate code warnings, GitShield AI strictly separates **evidence-backed static detection** from **probabilistic contextual reasoning**:
1. Deterministic security scanners detect potential code flaws with exact file paths and line numbers.
2. Claude Sonnet 5.5 performs taint analysis to eliminate false positives and verify reachability.
3. Automated local rescan verifiers check suggested patches before marking them as verified.
4. An executive Security Operations Center (SOC) dashboard displays real-time execution telemetry, dynamic category breakdowns, and side-by-side patch diffs.

---

## 🏛️ System Architecture

```text
               USER (GitHub URL)
                       │
                       ▼
         STREAMLIT SECURITY DASHBOARD (Port 8501)
                       │  HTTP REST (Poll / Stream)
                       ▼
             FASTAPI BACKEND (Port 8000)
                       │  Job Dispatch
                       ▼
       ┌───────────────────────────────────────────────┐
       │             LANGGRAPH STATE MACHINE           │
       │                                               │
       │  [Agent 1: Repository Analysis Agent]         │
       │       │                                       │
       │       ▼                                       │
       │  [Agent 2: Security Detection Agent]          │
       │       ├── Semgrep SAST                        │
       │       ├── Bandit AST Python Scanner           │
       │       ├── Gitleaks Secret Detector            │
       │       └── pip-audit Dependency CVEs           │
       │       │                                       │
       │       ▼                                       │
       │  [Agent 3: Vulnerability Validation Agent]    │
       │       │   (Claude Sonnet 5.5 via IBM Gateway) │
       │       ▼                                       │
       │  [Agent 4: Risk Assessment Agent]             │
       │       │   (CWE & OWASP Top 10 Mapping)        │
       │       ▼                                       │
       │  [Agent 5: Remediation & Verification Agent]  │
       │       │   (Patch Diffs + Local Rescan)        │
       │       ▼                                       │
       │  [Report Synthesis & Sandbox Cleanup]         │
       └───────────────────────────────────────────────┘
                       │
                       ▼
         IBM SERVICES ESSENTIALS GATEWAY
       (https://api.servicesessentials.ibm.com/v1)
                       │
                       ▼
               CLUDE SONNET 5.5
```

---

## 🤖 Multi-Agent Responsibilities

| Agent | Module | Primary Responsibility | Engine / Model |
|---|---|---|---|
| **1. Repository Analysis Agent** | `backend/agents/repository_agent.py` | Ingests target repository into an isolated sandbox, detects tech stacks (languages, frameworks), and maps security-critical files. | Git CLI + Manifest Parsers |
| **2. Security Detection Agent** | `backend/agents/detection_agent.py` | Orchestrates static scanners, deduplicates overlapping alerts, and normalizes findings into unified schemas. | Semgrep, Bandit, Gitleaks, pip-audit |
| **3. Vulnerability Validation Agent** | `backend/agents/validation_agent.py` | Performs taint analysis and contextual reachability checks to eliminate false positives. | **Claude Sonnet 5.5** (IBM Gateway) |
| **4. Risk Assessment Agent** | `backend/agents/risk_agent.py` | Evaluates blast radius, attacker privileges, CWE classification, and OWASP Top 10 categories. | **Claude Sonnet 5.5** (IBM Gateway) |
| **5. Remediation & Verification Agent** | `backend/agents/remediation_agent.py` | Authors minimal context-aware patches and runs a local rescan pass to verify flaw elimination. | **Claude Sonnet 5.5** + Local Rescan |

---

## ⚙️ Configuration & Environment

Create a `.env` file from `.env.example`:

```env
LLM_API_KEY=your_api_key_here
LLM_MODEL=claude-sonnet-5-5

# LLM Integration Settings
LLM_PROVIDER=ibm
LLM_API_FORMAT=openai
LLM_TEMPERATURE=0.0
LLM_MAX_TOKENS=4096
LLM_TIMEOUT_SECONDS=60.0

# GitHub Integration (Optional for public repositories; required for private repos)
GITHUB_TOKEN=your_github_token_here

# Backend & Frontend Server
BACKEND_HOST=127.0.0.1
BACKEND_PORT=8000
FRONTEND_PORT=8501

# Application
APP_ENV=development
LOG_LEVEL=INFO
```

---

## 🚀 Getting Started (Windows PowerShell)

### 1. Prerequisites
- Python 3.11+
- Git on PATH

### 2. Environment Setup
```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 3. Run Backend API Server
```powershell
& ".\venv\Scripts\python.exe" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Docs & Swagger UI: `http://127.0.0.1:8000/docs`
- Health Check: `http://127.0.0.1:8000/health`
- LLM Status Check: `http://127.0.0.1:8000/api/v1/llm/status`

### 4. Run Streamlit Security Dashboard
Open a separate PowerShell terminal:
```powershell
.\venv\Scripts\Activate.ps1
& ".\venv\Scripts\python.exe" -m streamlit run frontend/app.py --server.port 8501
```
- Open `http://localhost:8501` in your browser.

---

## 🐳 Docker Deployment

Run the complete platform via Docker Compose (non-root security hardened):

```powershell
docker-compose up --build
```

- Backend API: `http://localhost:8000`
- Streamlit SOC Dashboard: `http://localhost:8501`

---

## 🧪 Testing & Benchmark Validation

Run the complete test suite:

```powershell
& ".\venv\Scripts\pytest.exe" -v
```

Test coverage includes:
- **Phase 1**: Configuration, secrets masking, URL validation, and LLM factory.
- **Phase 2**: Deterministic scanners (Bandit, Semgrep heuristics, Gitleaks secret scrubbers, pip-audit).
- **Phase 3**: 5 Specialized AI agents and system prompt validations.
- **Phase 4**: LangGraph multi-agent stateful workflow transitions.
- **Phase 5**: FastAPI asynchronous REST routes and report downloads.
- **Phase 6**: Streamlit dashboard components and API client.
- **Phase 7**: End-to-end security benchmarks (precision, false-positive elimination, patch rescan).

---

## 🔒 Security & Privacy Commitments

- **No Root Execution**: Containerized environments run strictly as non-root user `appuser` (UID 1001).
- **Automatic Secret Scrubbing**: All source code context sent to external LLMs is scrubbed of AWS keys, GitHub tokens, passwords, and connection strings via [`backend/core/security.py`](backend/core/security.py).
- **Safe Sandboxing**: Repositories are cloned with `--depth 1` into temporary directories and automatically deleted after report generation.
- **Anti-Prompt Injection**: Repository contents and comments are delimited as untrusted XML blocks, preventing prompt injection from subverting agent instructions.
- **Read-Only Inspection**: The MVP operates in read-only mode and does not modify user repositories or create automatic pull requests without authorization.
