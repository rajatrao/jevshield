"""Tests for OllamaDecisionClient HTTP error mapping (httpx mock transport)."""

from __future__ import annotations

import json

import httpx
import pytest

from app.security.decision_client import (
    DecisionClientError,
    ModelNotFoundError,
    OllamaDecisionClient,
    PayloadTooLargeError,
    UnsupportedModelError,
)
from tests.conftest import make_settings, systemone_response


def _handler(status: int, body: dict):
    def _h(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=body, request=request)

    return _h


@pytest.mark.asyncio
async def test_404_model_missing():
    transport = httpx.MockTransport(_handler(404, {"error": "model not found"}))
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as http:
        client = OllamaDecisionClient(make_settings(), client=http)
        with pytest.raises(ModelNotFoundError):
            await client.decide("hi")


@pytest.mark.asyncio
async def test_400_unsupported():
    transport = httpx.MockTransport(
        _handler(400, {"error": "unsupported model"})
    )
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as http:
        client = OllamaDecisionClient(make_settings(), client=http)
        with pytest.raises(UnsupportedModelError):
            await client.decide("hi")


@pytest.mark.asyncio
async def test_413_too_large():
    transport = httpx.MockTransport(
        _handler(413, {"error": "request body must not exceed 64 KiB"})
    )
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as http:
        client = OllamaDecisionClient(make_settings(), client=http)
        with pytest.raises(PayloadTooLargeError):
            await client.decide("hi")


@pytest.mark.asyncio
async def test_success_parses_response():
    payload = systemone_response(threat="safe").model_dump()
    transport = httpx.MockTransport(_handler(200, payload))
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as http:
        client = OllamaDecisionClient(make_settings(), client=http)
        parsed, raw = await client.decide("hello world", source="user")
        assert parsed.model == "nimble"
        assert "threat_type" in parsed.answers
        assert raw["model"] == "nimble"


@pytest.mark.asyncio
async def test_invalid_json_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not-json", request=request)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as http:
        client = OllamaDecisionClient(make_settings(), client=http)
        with pytest.raises(DecisionClientError, match="Invalid JSON"):
            await client.decide("hi")


@pytest.mark.asyncio
async def test_questions_module_has_five():
    from app.security.questions import SECURITY_QUESTIONS, build_systemone_request

    assert len(SECURITY_QUESTIONS) == 5
    req = build_systemone_request(model="nimble", content="x", source="web")
    assert req["model"] == "nimble"
    assert "<UNTRUSTED_CONTENT>" in req["state"]["content"]
    assert set(req["questions"]) == {
        "threat_type",
        "injection_strength",
        "jailbreak_strength",
        "exfiltration",
        "tool_manipulation",
    }
