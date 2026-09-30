"""Taint tracking for untrusted content sources."""

from __future__ import annotations

from app.security.models import ContentSource, RiskAssessment, ThreatType

TRUSTED_SOURCES: frozenset[str] = frozenset(
    {
        ContentSource.SYSTEM.value,
        ContentSource.DEVELOPER.value,
    }
)

UNTRUSTED_SOURCES: frozenset[str] = frozenset(
    {
        ContentSource.WEB.value,
        ContentSource.DOCUMENT.value,
        ContentSource.EMAIL.value,
        ContentSource.DATABASE.value,
        ContentSource.RETRIEVAL.value,
        ContentSource.TOOL.value,
        ContentSource.USER.value,
    }
)


def is_trusted_source(source: ContentSource | str, *, trust_user: bool = False) -> bool:
    """
    system and developer are trusted.
    web, document, email, database, retrieval, and tool are untrusted.
    user is untrusted unless trust_user is True.
    """
    value = source.value if isinstance(source, ContentSource) else str(source)
    if value in TRUSTED_SOURCES:
        return True
    if value == ContentSource.USER.value and trust_user:
        return True
    return False


def is_tainted(
    risk: RiskAssessment,
    *,
    review_threshold: float = 0.50,
) -> bool:
    """
    Tainted when threat_type != safe OR any normalized risk >= review threshold.

    Tainted text must never be passed to a tool as instructions.
    """
    if risk.threat_type != ThreatType.SAFE:
        return True
    return max(
        risk.injection_risk,
        risk.jailbreak_risk,
        risk.exfiltration_risk,
        risk.tool_risk,
    ) >= review_threshold
