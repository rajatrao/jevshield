"""Tests for taint tracking."""

from __future__ import annotations

from app.security.models import ContentSource, RiskAssessment, ThreatType
from app.security.taint import is_tainted, is_trusted_source


def _risk(**kwargs) -> RiskAssessment:
    defaults = dict(
        threat_type=ThreatType.SAFE,
        threat_probabilities={"safe": 1.0},
        injection_risk=0.0,
        jailbreak_risk=0.0,
        exfiltration_risk=0.0,
        tool_risk=0.0,
        confidence=0.9,
    )
    defaults.update(kwargs)
    return RiskAssessment(**defaults)


def test_system_and_developer_trusted():
    assert is_trusted_source(ContentSource.SYSTEM) is True
    assert is_trusted_source(ContentSource.DEVELOPER) is True


def test_untrusted_sources():
    for src in (
        ContentSource.WEB,
        ContentSource.DOCUMENT,
        ContentSource.EMAIL,
        ContentSource.DATABASE,
        ContentSource.RETRIEVAL,
        ContentSource.TOOL,
        ContentSource.USER,
    ):
        assert is_trusted_source(src) is False


def test_user_trusted_when_flag_set():
    assert is_trusted_source(ContentSource.USER, trust_user=True) is True


def test_tainted_when_threat_not_safe():
    assert is_tainted(_risk(threat_type=ThreatType.INJECTION)) is True


def test_tainted_when_risk_at_review():
    assert is_tainted(_risk(injection_risk=0.50)) is True


def test_not_tainted_when_safe_and_low_risk():
    assert is_tainted(_risk(injection_risk=0.1)) is False
