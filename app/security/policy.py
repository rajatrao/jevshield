"""Deterministic ALLOW / REVIEW / BLOCK policy."""

from __future__ import annotations

from app.security.models import Decision, RiskAssessment


def apply_policy(
    risk: RiskAssessment,
    *,
    block_threshold: float = 0.85,
    review_threshold: float = 0.50,
) -> Decision:
    """
    Map normalized risks to a decision.

    highest = max(injection, jailbreak, exfiltration, tool)
    highest >= block_threshold  → BLOCK
    highest >= review_threshold → REVIEW
    else                        → ALLOW

    Comparisons use >= so 0.50 is REVIEW and 0.85 is BLOCK.
    Nimble's choice sets threat_type only; it does not choose the decision.
    """
    highest = max(
        risk.injection_risk,
        risk.jailbreak_risk,
        risk.exfiltration_risk,
        risk.tool_risk,
    )
    if highest >= block_threshold:
        return Decision.BLOCK
    if highest >= review_threshold:
        return Decision.REVIEW
    return Decision.ALLOW
