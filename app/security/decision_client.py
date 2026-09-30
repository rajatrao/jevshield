"""HTTP client for Ollama System One decisions (POST /v1/systemone only)."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.core.config import Settings, get_settings
from app.security.models import SystemOneResponse
from app.security.questions import build_systemone_request

logger = logging.getLogger(__name__)


class DecisionClientError(Exception):
    """Base error for decision client failures."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


class ModelNotFoundError(DecisionClientError):
    """Raised when Ollama returns 404 (model missing)."""


class UnsupportedModelError(DecisionClientError):
    """Raised when Ollama returns 400 (unsupported / bad request)."""


class PayloadTooLargeError(DecisionClientError):
    """Raised when Ollama returns 413 (body > 64 KiB)."""


class OllamaDecisionClient:
    """Typed client that classifies content via POST /v1/systemone."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=self.settings.ollama_host.rstrip("/"),
            timeout=httpx.Timeout(self.settings.ollama_timeout),
        )

    async def aclose(self) -> None:
        """Close the underlying httpx client if we own it."""
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> OllamaDecisionClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def decide(
        self,
        content: str,
        source: str = "user",
        *,
        model: str | None = None,
    ) -> tuple[SystemOneResponse, dict[str, Any]]:
        """
        Send one five-question System One request.

        Returns (parsed response, raw JSON body).
        """
        model_name = model or self.settings.ollama_decision_model
        payload = build_systemone_request(
            model=model_name,
            content=content,
            source=source,
        )
        logger.info(
            "systemone.request",
            extra={
                "model": model_name,
                "source": source,
                "content_chars": len(content),
                "question_count": len(payload["questions"]),
            },
        )
        try:
            response = await self._client.post("/v1/systemone", json=payload)
        except httpx.TimeoutException as exc:
            logger.error("systemone.timeout", extra={"error": str(exc)})
            raise DecisionClientError(f"Ollama timeout: {exc}") from exc
        except httpx.HTTPError as exc:
            logger.error("systemone.connection_error", extra={"error": str(exc)})
            raise DecisionClientError(f"Ollama connection error: {exc}") from exc

        return self._parse_response(response)

    def _parse_response(
        self, response: httpx.Response
    ) -> tuple[SystemOneResponse, dict[str, Any]]:
        status = response.status_code
        try:
            body = response.json()
        except ValueError as exc:
            logger.error(
                "systemone.invalid_json",
                extra={"status": status, "text": response.text[:500]},
            )
            raise DecisionClientError(
                f"Invalid JSON from Ollama (HTTP {status})",
                status_code=status,
            ) from exc

        error_msg = ""
        if isinstance(body, dict):
            error_msg = str(body.get("error") or "")

        if status == 404:
            logger.error("systemone.model_missing", extra={"error": error_msg})
            raise ModelNotFoundError(
                error_msg or "model not found",
                status_code=404,
            )
        if status == 400:
            logger.error("systemone.bad_request", extra={"error": error_msg})
            raise UnsupportedModelError(
                error_msg or "unsupported model or bad request",
                status_code=400,
            )
        if status == 413:
            logger.error("systemone.payload_too_large", extra={"error": error_msg})
            raise PayloadTooLargeError(
                error_msg or "request body must not exceed 64 KiB",
                status_code=413,
            )
        if status >= 400:
            logger.error(
                "systemone.http_error",
                extra={"status": status, "error": error_msg},
            )
            raise DecisionClientError(
                error_msg or f"Ollama HTTP {status}",
                status_code=status,
            )

        try:
            parsed = SystemOneResponse.model_validate(body)
        except Exception as exc:
            logger.error("systemone.parse_error", extra={"error": str(exc)})
            raise DecisionClientError(f"Failed to parse System One response: {exc}") from exc

        logger.info(
            "systemone.response",
            extra={
                "model": parsed.model,
                "input_tokens": parsed.usage.input_tokens,
                "output_tokens": parsed.usage.output_tokens,
                "answer_keys": list(parsed.answers.keys()),
            },
        )
        return parsed, body if isinstance(body, dict) else {"raw": body}

    async def health(self) -> dict[str, Any]:
        """
        Check Ollama reachability and list tags via GET /api/tags.

        Classification never uses this endpoint.
        """
        try:
            version_resp = await self._client.get("/api/version")
            tags_resp = await self._client.get("/api/tags")
        except httpx.HTTPError as exc:
            return {
                "ollama_reachable": False,
                "error": str(exc),
                "version": None,
                "models": [],
                "decision_model_present": False,
            }

        version = None
        if version_resp.status_code == 200:
            try:
                version = version_resp.json().get("version")
            except ValueError:
                version = None

        models: list[str] = []
        if tags_resp.status_code == 200:
            try:
                tags_body = tags_resp.json()
                models = [m.get("name", "") for m in tags_body.get("models", [])]
            except ValueError:
                models = []

        decision = self.settings.ollama_decision_model
        present = any(
            name == decision or name.startswith(f"{decision}:") for name in models
        )
        return {
            "ollama_reachable": version_resp.status_code == 200,
            "version": version,
            "models": models,
            "decision_model": decision,
            "decision_model_present": present,
            "error": None,
        }
