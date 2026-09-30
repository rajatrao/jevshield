"""Tests for score expected-value normalization and noul-as-probability."""

from __future__ import annotations

import pytest

from app.security.models import ScoreAnswer
from app.security.risk import (
    RiskNormalizationError,
    assess_risk,
    normalize_score_risk,
    noul_as_probability,
)
from tests.conftest import noul_answer, score_answer, systemone_response


def test_normalize_score_example_from_plan():
    """probabilities {0:0.1,1:0.1,2:0.2,3:0.4,4:0.2} → risk 0.625; raw score 2.5."""
    probs = {"0": 0.1, "1": 0.1, "2": 0.2, "3": 0.4, "4": 0.2}
    answer = score_answer(probabilities=probs)
    assert abs(answer.score - 2.5) < 1e-9
    risk, raw = normalize_score_risk(answer)
    assert abs(raw - 2.5) < 1e-9
    assert abs(risk - 0.625) < 1e-9


def test_score_is_not_treated_as_probability():
    """A score of 0.8 on a 0–4 scale is NOT 80% risk."""
    # Mass on index 0 and 1 such that expected index ≈ 0.8
    probs = {"0": 0.2, "1": 0.8, "2": 0.0, "3": 0.0, "4": 0.0}
    answer = score_answer(probabilities=probs)
    assert abs(answer.score - 0.8) < 1e-9
    risk, _ = normalize_score_risk(answer)
    assert abs(risk - 0.2) < 1e-9  # (0/4)*0.2 + (1/4)*0.8 = 0.2
    assert risk != pytest.approx(0.8)


def test_score_crosscheck_fails_closed():
    answer = ScoreAnswer(
        type="score",
        score=3.0,  # wrong vs probabilities
        legend={str(i): str(i) for i in range(5)},
        probabilities={"0": 1.0, "1": 0.0, "2": 0.0, "3": 0.0, "4": 0.0},
        confidence=0.9,
    )
    with pytest.raises(RiskNormalizationError, match="cross-check"):
        normalize_score_risk(answer)


def test_probabilities_must_sum_near_one():
    answer = score_answer(probabilities={"0": 0.5, "1": 0.1, "2": 0.0, "3": 0.0, "4": 0.0})
    with pytest.raises(RiskNormalizationError, match="sum"):
        normalize_score_risk(answer)


def test_probability_out_of_range():
    answer = ScoreAnswer(
        type="score",
        score=0.0,
        legend={"0": "a", "1": "b"},
        probabilities={"0": 1.5, "1": -0.5},
        confidence=0.5,
    )
    with pytest.raises(RiskNormalizationError, match="out of"):
        normalize_score_risk(answer)


def test_noul_is_probability_directly():
    assert noul_as_probability(noul_answer(0.73)) == pytest.approx(0.73)
    assert noul_as_probability(noul_answer(0.0)) == 0.0
    assert noul_as_probability(noul_answer(1.0)) == 1.0


def test_assess_risk_uses_min_confidence_excluding_noul():
    resp = systemone_response(
        threat="injection",
        injection_probs={"0": 0.0, "1": 0.0, "2": 0.0, "3": 0.2, "4": 0.8},
        jailbreak_probs={"0": 1.0, "1": 0.0, "2": 0.0, "3": 0.0, "4": 0.0},
        exfil=0.9,
        tool=0.1,
        choice_confidence=0.7,
        score_confidence=0.5,
    )
    # Patch jailbreak confidence lower via reconstruct — score_answer uses same conf.
    # choice=0.7, scores=0.5 → min = 0.5; noul has no confidence
    risk = assess_risk(resp, review_threshold=0.5)
    assert risk.confidence == pytest.approx(0.5)
    assert risk.exfiltration_risk == pytest.approx(0.9)
    assert "unauthorized_disclosure" in risk.signals
    assert "instruction_override" in risk.signals
