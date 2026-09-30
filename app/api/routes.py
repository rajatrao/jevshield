"""FastAPI route handlers."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from app.core.config import get_settings
from app.security.models import (
    AnalyzeRequest,
    AuthorizeToolRequest,
    SecurityResult,
    ToolAuthorizationResult,
)
from app.security.tool_guard import ToolGuard

router = APIRouter()


def _firewall(request: Request):
    return request.app.state.firewall


def _tool_guard(request: Request) -> ToolGuard:
    return request.app.state.tool_guard


@router.get("/health")
async def health(request: Request) -> dict[str, Any]:
    """Process up, Ollama reachability, model present via GET /api/tags."""
    settings = get_settings()
    client_health = await _firewall(request).client.health()
    return {
        "status": "ok",
        "service": "jevshield",
        "ollama": client_health,
        "thresholds": {
            "block": settings.jevshield_block_threshold,
            "review": settings.jevshield_review_threshold,
        },
        "fail_closed": settings.fail_closed,
    }


@router.get("/model")
async def model_info(request: Request) -> dict[str, Any]:
    """Configured decision model and whether that tag exists."""
    settings = get_settings()
    client_health = await _firewall(request).client.health()
    return {
        "decision_model": settings.ollama_decision_model,
        "ollama_host": settings.ollama_host,
        "present": client_health.get("decision_model_present", False),
        "version": client_health.get("version"),
        "models": client_health.get("models", []),
    }


@router.post("/analyze", response_model=SecurityResult)
async def analyze(body: AnalyzeRequest, request: Request) -> SecurityResult:
    """Classify text; include raw /v1/systemone body for the dashboard."""
    return await _firewall(request).analyze(
        body.content,
        source=body.source,
        include_raw=True,
    )


@router.post("/check-content", response_model=SecurityResult)
async def check_content(body: AnalyzeRequest, request: Request) -> SecurityResult:
    """Classify text for ingestion; returns security result and taint flags."""
    return await _firewall(request).analyze(
        body.content,
        source=body.source,
        include_raw=False,
    )


@router.post("/authorize-tool", response_model=ToolAuthorizationResult)
async def authorize_tool(
    body: AuthorizeToolRequest,
    request: Request,
) -> ToolAuthorizationResult:
    """Tool guard result, execution flag, and simulated tool payload."""
    return await _tool_guard(request).authorize(
        tool_name=body.tool_name,
        arguments=body.arguments,
        context=body.context,
        source=body.source,
    )
