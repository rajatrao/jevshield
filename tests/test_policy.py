"""Tests for deterministic policy boundaries."""

from __future__ import annotations

from app.security.models import RiskAssessment, ThreatType
from app.security.policy import apply_policy
from app.security.models import Decision


def _risk(**kwargs) -> RiskAssessment:
    defaults = dict(
        threat_type=ThreatType.SAFE,
        threat_probabilities={"safe": 1.0},
        injection_risk=0.0,
        jailbreak_risk=0.0,
        exfiltration_risk=0.0,
        tool_risk=0.0,
        confidence=0.9,
        signals=[],
        reasoning="",
    )
    defaults.update(kwargs)
    return RiskAssessment(**defaults)


def test_allow_below_review():
    assert apply_policy(_risk(injection_risk=0.49)) == Decision.ALLOW


def test_review_at_exactly_050():
    assert apply_policy(_risk(injection_risk=0.50)) == Decision.REVIEW


def test_review_between_thresholds():
    assert apply_policy(_risk(jailbreak_risk=0.70)) == Decision.REVIEW


def test_block_at_exactly_085():
    assert apply_policy(_risk(exfiltration_risk=0.85)) == Decision.BLOCK


def test_block_above_threshold():
    assert apply_policy(_risk(tool_risk=0.99)) == Decision.BLOCK


def test_highest_of_four_risks_wins():
    risk = _risk(
        injection_risk=0.2,
        jailbreak_risk=0.3,
        exfiltration_risk=0.9,
        tool_risk=0.1,
    )
    assert apply_policy(risk) == Decision.BLOCK


def test_threat_type_does_not_choose_decision():
    """choice sets threat_type only; policy uses normalized risks."""
    risk = _risk(
        threat_type=ThreatType.INJECTION,
        injection_risk=0.1,
        jailbreak_risk=0.1,
        exfiltration_risk=0.1,
        tool_risk=0.1,
    )
    assert apply_policy(risk) == Decision.ALLOW
