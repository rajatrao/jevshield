"""Tests for firewall fail-closed behavior and choice mapping."""

from __future__ import annotations

import httpx
import pytest

from app.security.decision_client import DecisionClientError
from app.security.firewall import Firewall
from app.security.models import Decision, ThreatType
from tests.conftest import MockDecisionClient, make_settings, systemone_response


@pytest.mark.asyncio
async def test_firewall_maps_safe_to_allow():
    client = MockDecisionClient(systemone_response(threat="safe"))
    fw = Firewall(client=client, settings=make_settings())  # type: ignore[arg-type]
    result = await fw.analyze("hello", source="user")
    assert result.decision == Decision.ALLOW
    assert result.threat_type == ThreatType.SAFE
    assert result.evaluator_status == "ok"
    assert result.tainted is False


@pytest.mark.asyncio
async def test_firewall_blocks_high_injection():
    client = MockDecisionClient(
        systemone_response(
            threat="injection",
            injection_probs={"0": 0.0, "1": 0.0, "2": 0.0, "3": 0.1, "4": 0.9},
            exfil=0.1,
            tool=0.1,
        )
    )
    fw = Firewall(client=client, settings=make_settings())  # type: ignore[arg-type]
    result = await fw.analyze("ignore previous", source="user")
    assert result.decision == Decision.BLOCK
    assert result.threat_type == ThreatType.INJECTION
    assert result.injection_risk is not None and result.injection_risk >= 0.85


@pytest.mark.asyncio
async def test_fail_closed_on_timeout():
    client = MockDecisionClient(error=DecisionClientError("Ollama timeout: timed out"))
    fw = Firewall(client=client, settings=make_settings(fail_closed=True))  # type: ignore[arg-type]
    result = await fw.analyze("x", source="user")
    assert result.decision == Decision.BLOCK
    assert result.evaluator_status == "unavailable"
    assert result.error is not None
    assert "timeout" in result.error.lower() or "Timeout" in result.error or "timed" in result.error.lower()


@pytest.mark.asyncio
async def test_fail_closed_on_connection_error():
    client = MockDecisionClient(
        error=DecisionClientError("Ollama connection error: connect failed")
    )
    fw = Firewall(client=client, settings=make_settings())  # type: ignore[arg-type]
    result = await fw.analyze("x", source="web")
    assert result.decision == Decision.BLOCK
    assert result.evaluator_status == "unavailable"


@pytest.mark.asyncio
async def test_fail_closed_on_invalid_response():
    client = MockDecisionClient(error=DecisionClientError("Invalid JSON from Ollama"))
    fw = Firewall(client=client, settings=make_settings())  # type: ignore[arg-type]
    result = await fw.analyze("x")
    assert result.decision == Decision.BLOCK
    assert result.evaluator_status == "unavailable"


@pytest.mark.asyncio
async def test_fail_closed_on_bad_probabilities():
    """RiskNormalizationError also fail-closes."""
    bad = systemone_response()
    # Corrupt injection probabilities sum
    bad.answers["injection_strength"].probabilities = {
        "0": 0.1,
        "1": 0.1,
        "2": 0.0,
        "3": 0.0,
        "4": 0.0,
    }
    bad.answers["injection_strength"].score = 0.1
    client = MockDecisionClient(bad)
    fw = Firewall(client=client, settings=make_settings())  # type: ignore[arg-type]
    result = await fw.analyze("x")
    assert result.decision == Decision.BLOCK
    assert result.evaluator_status == "unavailable"


@pytest.mark.asyncio
async def test_include_raw_systemone():
    resp = systemone_response()
    client = MockDecisionClient(resp, raw={"model": "nimble", "answers": {}})
    fw = Firewall(client=client, settings=make_settings())  # type: ignore[arg-type]
    result = await fw.analyze("hi", include_raw=True)
    assert result.raw_systemone is not None
    assert result.raw_systemone["model"] == "nimble"
