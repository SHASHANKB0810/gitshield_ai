"""Centralized LLM Factory Module.

Provides configured LangChain ChatOpenAI instances targeting the
IBM Services Essentials OpenAI-compatible gateway with Claude Sonnet 5.5.
All agents obtain their LLM instances exclusively through this factory.
"""

from typing import Any, Dict, Optional
import httpx
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

from backend.core.config import settings
from backend.core.logging import logger


class LLMFactory:
    """Central factory for instantiating and testing LLM client connections."""

    @staticmethod
    def get_chat_model(
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        model_name: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> ChatOpenAI:
        """Instantiate a ChatOpenAI client targeting the IBM OpenAI-compatible gateway.

        Args:
            temperature: Sampling temperature (defaults to settings.LLM_TEMPERATURE).
            max_tokens: Max output tokens (defaults to settings.LLM_MAX_TOKENS).
            model_name: Model identifier (defaults to settings.LLM_MODEL e.g. claude-sonnet-5-5).
            timeout: Request timeout in seconds (defaults to settings.LLM_TIMEOUT_SECONDS).

        Returns:
            Configured ChatOpenAI instance.
        """
        api_key = settings.LLM_API_KEY.strip() if settings.LLM_API_KEY else "NO_KEY_CONFIGURED"
        selected_model = model_name or settings.LLM_MODEL
        # IBM Services Essentials LiteLLM Claude gateway requires temperature=1.0 or drop_params
        selected_temp = temperature if temperature is not None else settings.LLM_TEMPERATURE
        if "claude" in selected_model.lower() and selected_temp not in (1.0, 1):
            selected_temp = 1.0

        selected_tokens = max_tokens or settings.LLM_MAX_TOKENS
        selected_timeout = timeout or settings.LLM_TIMEOUT_SECONDS

        logger.debug(
            f"Instantiating ChatOpenAI: model={selected_model}, "
            f"base_url={settings.LLM_BASE_URL}, temperature={selected_temp}"
        )

        async_client = httpx.AsyncClient(
            timeout=selected_timeout,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

        return ChatOpenAI(
            model=selected_model,
            openai_api_key=api_key,
            openai_api_base=settings.LLM_BASE_URL,
            temperature=selected_temp,
            max_tokens=selected_tokens,
            timeout=selected_timeout,
            max_retries=2,
            extra_body={"drop_params": True},
            http_async_client=async_client,
        )

    @classmethod
    async def check_connectivity(cls) -> Dict[str, Any]:
        """Safely test connectivity to the IBM Services Essentials gateway.

        Sends a minimal prompt to verify model discovery and reasoning inference.

        Returns:
            Dictionary with status, provider, model, latency_ms, and diagnostic details.
        """
        if not settings.LLM_API_KEY:
            return {
                "status": "UNCONFIGURED",
                "message": "LLM_API_KEY is not set in environment.",
                "provider": settings.LLM_PROVIDER,
                "model": settings.LLM_MODEL,
                "base_url": settings.LLM_BASE_URL,
                "masked_key": settings.get_masked_api_key(),
            }

        client = cls.get_chat_model(temperature=0.0, max_tokens=10, timeout=15.0)

        import time
        start_time = time.time()
        try:
            # Minimal health check prompt
            response = await client.ainvoke([
                SystemMessage(content="You are a system health check assistant. Reply only with 'OK'."),
                HumanMessage(content="Ping")
            ])
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            content = str(response.content).strip()

            return {
                "status": "HEALTHY",
                "message": f"Successfully connected to {settings.LLM_MODEL} via IBM Gateway.",
                "provider": settings.LLM_PROVIDER,
                "model": settings.LLM_MODEL,
                "base_url": settings.LLM_BASE_URL,
                "masked_key": settings.get_masked_api_key(),
                "response_sample": content[:50],
                "latency_ms": elapsed_ms,
            }

        except httpx.HTTPStatusError as e:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            status_code = e.response.status_code if e.response is not None else 500
            logger.error(f"LLM Gateway HTTP Error [{status_code}]: {e}")
            return {
                "status": "ERROR",
                "http_status": status_code,
                "message": f"HTTP {status_code} error from IBM gateway.",
                "provider": settings.LLM_PROVIDER,
                "model": settings.LLM_MODEL,
                "base_url": settings.LLM_BASE_URL,
                "latency_ms": elapsed_ms,
            }
        except httpx.ConnectTimeout:
            return {
                "status": "TIMEOUT",
                "message": "Connection to IBM gateway timed out.",
                "provider": settings.LLM_PROVIDER,
                "model": settings.LLM_MODEL,
                "base_url": settings.LLM_BASE_URL,
            }
        except Exception as e:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            logger.error(f"LLM Connectivity Check Failed: {type(e).__name__} - {e}")
            return {
                "status": "ERROR",
                "message": f"Connection check failed: {type(e).__name__}",
                "provider": settings.LLM_PROVIDER,
                "model": settings.LLM_MODEL,
                "base_url": settings.LLM_BASE_URL,
                "latency_ms": elapsed_ms,
            }


# Export convenient helper function
get_llm = LLMFactory.get_chat_model
