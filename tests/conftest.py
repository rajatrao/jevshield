"""Shared fixtures and helpers for unit tests (mocked System One client)."""

from __future__ import annotations

from typing import Any

import pytest

from app.core.config import Settings
from app.security.models import (
    ChoiceAnswer,
    NoulAnswer,
    ScoreAnswer,
    SystemOneResponse,
    SystemOneUsage,
)


def make_settings(**overrides: Any) -> Settings:
    base = {
        "ollama_host": "http://localhost:11434",
        "ollama_decision_model": "nimble",
        "ollama_timeout": 5.0,
        "jevshield_block_threshold": 0.85,
        "jevshield_review_threshold": 0.50,
        "fail_closed": True,
        "jevshield_trust_user": False,
        "jevshield_api_url": "http://127.0.0.1:8000",
    }
    base.update(overrides)
    return Settings(**base)


def score_answer(
    *,
    probabilities: dict[str, float],
    confidence: float = 0.9,
    legend: dict[str, str] | None = None,
) -> ScoreAnswer:
    """Build a ScoreAnswer with score = expected index from probabilities."""
    expected = sum(int(k) * v for k, v in probabilities.items())
    if legend is None:
        labels = ["none", "weak", "moderate", "strong", "very strong"]
        legend = {str(i): labels[i] for i in range(len(labels))}
    return ScoreAnswer(
        type="score",
        score=expected,
        legend=legend,
        probabilities=probabilities,
        confidence=confidence,
    )


def choice_answer(
    choice: str,
    probabilities: dict[str, float] | None = None,
    confidence: float = 0.9,
) -> ChoiceAnswer:
    if probabilities is None:
        keys = ["safe", "injection", "jailbreak", "exfiltration", "tool_manipulation"]
        probabilities = {k: (0.9 if k == choice else 0.025) for k in keys}
        # renormalize slightly if choice not in keys
        total = sum(probabilities.values())
        probabilities = {k: v / total for k, v in probabilities.items()}
    return ChoiceAnswer(
        type="choice",
        choice=choice,
        probabilities=probabilities,
        confidence=confidence,
    )


def noul_answer(p_true: float) -> NoulAnswer:
    return NoulAnswer(type="noul", noul=p_true)


def systemone_response(
    *,
    threat: str = "safe",
    injection_probs: dict[str, float] | None = None,
    jailbreak_probs: dict[str, float] | None = None,
    exfil: float = 0.05,
    tool: float = 0.05,
    choice_confidence: float = 0.9,
    score_confidence: float = 0.9,
) -> SystemOneResponse:
    if injection_probs is None:
        injection_probs = {"0": 0.8, "1": 0.1, "2": 0.05, "3": 0.03, "4": 0.02}
    if jailbreak_probs is None:
        jailbreak_probs = {"0": 0.85, "1": 0.1, "2": 0.03, "3": 0.01, "4": 0.01}
    return SystemOneResponse(
        model="nimble",
        answers={
            "threat_type": choice_answer(threat, confidence=choice_confidence),
            "injection_strength": score_answer(
                probabilities=injection_probs, confidence=score_confidence
            ),
            "jailbreak_strength": score_answer(
                probabilities=jailbreak_probs, confidence=score_confidence
            ),
            "exfiltration": noul_answer(exfil),
            "tool_manipulation": noul_answer(tool),
        },
        usage=SystemOneUsage(input_tokens=100, output_tokens=5),
    )


class MockDecisionClient:
    """Drop-in async mock for OllamaDecisionClient.decide / health."""

    def __init__(
        self,
        response: SystemOneResponse | None = None,
        *,
        error: Exception | None = None,
        raw: dict[str, Any] | None = None,
    ) -> None:
        self.response = response or systemone_response()
        self.error = error
        self.raw = raw
        self.calls: list[tuple[str, str]] = []

    async def decide(
        self, content: str, source: str = "user", *, model: str | None = None
    ):
        self.calls.append((content, source))
        if self.error is not None:
            raise self.error
        raw = self.raw if self.raw is not None else self.response.model_dump()
        return self.response, raw

    async def health(self) -> dict[str, Any]:
        return {
            "ollama_reachable": True,
            "version": "0.35.0",
            "models": ["nimble:latest"],
            "decision_model": "nimble",
            "decision_model_present": True,
            "error": None,
        }

    async def aclose(self) -> None:
        return None


@pytest.fixture
def settings() -> Settings:
    return make_settings()
