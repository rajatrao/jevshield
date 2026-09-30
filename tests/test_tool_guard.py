"""Tests for tool guard execution gates."""

from __future__ import annotations

import pytest

from app.security.firewall import Firewall
from app.security.models import Decision
from app.security.tool_guard import ToolGuard
from tests.conftest import MockDecisionClient, make_settings, systemone_response


@pytest.mark.asyncio
async def test_allow_executes_simulated_tool():
    client = MockDecisionClient(systemone_response(threat="safe"))
    fw = Firewall(client=client, settings=make_settings())  # type: ignore[arg-type]
    guard = ToolGuard(firewall=fw, settings=make_settings())
    result = await guard.authorize(
        "calculator",
        arguments={"expression": "2+2"},
        context="sum",
    )
    assert result.decision == Decision.ALLOW
    assert result.authorized is True
    assert result.executed is True
    assert result.approval_required is False
    assert result.tool_result is not None
    assert result.tool_result["status"] == "simulated"
    assert result.tool_result["sent"] is False
    assert result.tool_result.get("result") == 4.0


@pytest.mark.asyncio
async def test_review_does_not_execute():
    client = MockDecisionClient(
        systemone_response(
            threat="injection",
            injection_probs={"0": 0.0, "1": 0.0, "2": 1.0, "3": 0.0, "4": 0.0},
            # risk = 2/4 = 0.5 → REVIEW
        )
    )
    fw = Firewall(client=client, settings=make_settings())  # type: ignore[arg-type]
    guard = ToolGuard(firewall=fw, settings=make_settings())
    result = await guard.authorize(
        "email",
        arguments={"to": "a@b.c", "subject": "x", "body": "y"},
    )
    assert result.decision == Decision.REVIEW
    assert result.executed is False
    assert result.approval_required is True
    assert result.tool_result is None


@pytest.mark.asyncio
async def test_block_does_not_execute():
    client = MockDecisionClient(
        systemone_response(
            threat="tool_manipulation",
            tool=0.95,
            injection_probs={"0": 1.0, "1": 0.0, "2": 0.0, "3": 0.0, "4": 0.0},
        )
    )
    fw = Firewall(client=client, settings=make_settings())  # type: ignore[arg-type]
    guard = ToolGuard(firewall=fw, settings=make_settings())
    result = await guard.authorize(
        "file_operation",
        arguments={"operation": "delete", "path": "/tmp/x"},
    )
    assert result.decision == Decision.BLOCK
    assert result.executed is False
    assert result.approval_required is False
    assert result.tool_result is None


@pytest.mark.asyncio
async def test_email_simulation_never_sends():
    client = MockDecisionClient(systemone_response())
    fw = Firewall(client=client, settings=make_settings())  # type: ignore[arg-type]
    guard = ToolGuard(firewall=fw, settings=make_settings())
    result = await guard.authorize(
        "email",
        arguments={"to": "x@y.z", "subject": "hi", "body": "hello"},
    )
    assert result.executed is True
    assert result.tool_result["sent"] is False
