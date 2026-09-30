"""Risk normalization from System One typed answers.

Score answers return an expected INDEX (0..N-1), NOT a probability.
Normalize risk as: sum((index / (N - 1)) * P(index) for index in 0..N-1).

Noul answers: `noul` IS already P(true) in [0, 1] — use directly.
"""

from __future__ import annotations

from app.security.models import (
    ChoiceAnswer,
    NoulAnswer,
    RiskAssessment,
    ScoreAnswer,
    SystemOneResponse,
    ThreatType,
)

PROB_SUM_TOLERANCE = 1e-2
SCORE_CROSSCHECK_TOLERANCE = 1e-2


class RiskNormalizationError(Exception):
    """Raised when probabilities are missing, invalid, or fail closed checks."""


def _parse_probabilities(probabilities: dict[str, float]) -> dict[int, float]:
    """Parse string-keyed index probabilities into int keys."""
    if not probabilities:
        raise RiskNormalizationError("score probabilities are missing")

    parsed: dict[int, float] = {}
    for key, value in probabilities.items():
        try:
            idx = int(key)
        except (TypeError, ValueError) as exc:
            raise RiskNormalizationError(
                f"score probability key is not an index: {key!r}"
            ) from exc
        if not isinstance(value, (int, float)) or value < 0.0 or value > 1.0:
            raise RiskNormalizationError(
                f"probability out of [0, 1] for index {idx}: {value}"
            )
        parsed[idx] = float(value)

    total = sum(parsed.values())
    if abs(total - 1.0) > PROB_SUM_TOLERANCE:
        raise RiskNormalizationError(
            f"probabilities must sum to 1 (±{PROB_SUM_TOLERANCE}), got {total}"
        )
    return parsed


def normalize_score_risk(answer: ScoreAnswer) -> tuple[float, float]:
    """
    Convert a score answer into a [0, 1] risk.

    Returns (normalized_risk, raw_expected_index).
    Cross-checks that answer.score ≈ sum(index * P(index)).
    """
    probs = _parse_probabilities(answer.probabilities)
    n = len(probs)
    if n < 2:
        # Prefer legend length when available for N
        n = max(n, len(answer.legend))
    if n < 2:
        raise RiskNormalizationError("score requires at least 2 levels")

    # Use max index + 1 as N when indices are 0..N-1
    max_index = max(probs.keys())
    n_levels = max(max_index + 1, len(answer.legend), 2)
    denom = n_levels - 1

    expected_index = sum(idx * p for idx, p in probs.items())
    if abs(expected_index - answer.score) > SCORE_CROSSCHECK_TOLERANCE:
        raise RiskNormalizationError(
            f"score cross-check failed: reported {answer.score}, "
            f"expected from probs {expected_index}"
        )

    risk = sum((idx / denom) * p for idx, p in probs.items())
    # Clamp floating-point drift into [0, 1]
    risk = max(0.0, min(1.0, risk))
    return risk, answer.score


def noul_as_probability(answer: NoulAnswer) -> float:
    """Return noul directly as P(true). No probabilities object exists."""
    value = float(answer.noul)
    if value < 0.0 or value > 1.0:
        raise RiskNormalizationError(f"noul out of [0, 1]: {value}")
    return value


def _require_answer(answers: dict, name: str, expected_type: type):
    if name not in answers:
        raise RiskNormalizationError(f"missing answer: {name}")
    answer = answers[name]
    if not isinstance(answer, expected_type):
        raise RiskNormalizationError(
            f"answer {name!r} expected {expected_type.__name__}, "
            f"got {type(answer).__name__}"
        )
    return answer


def derive_signals(
    *,
    threat_type: ThreatType,
    injection_risk: float,
    jailbreak_risk: float,
    exfiltration_risk: float,
    tool_risk: float,
    review_threshold: float,
) -> list[str]:
    """Labels from distributions that cross the review threshold (no keyword scanner)."""
    signals: list[str] = []
    if injection_risk >= review_threshold or threat_type == ThreatType.INJECTION:
        signals.append("instruction_override")
    if jailbreak_risk >= review_threshold or threat_type == ThreatType.JAILBREAK:
        signals.append("safeguard_bypass")
    if exfiltration_risk >= review_threshold or threat_type == ThreatType.EXFILTRATION:
        signals.append("unauthorized_disclosure")
    if tool_risk >= review_threshold or threat_type == ThreatType.TOOL_MANIPULATION:
        signals.append("unauthorized_tool_action")
    return signals


def build_reasoning(
    *,
    threat_type: ThreatType,
    injection_risk: float,
    jailbreak_risk: float,
    exfiltration_risk: float,
    tool_risk: float,
    confidence: float,
) -> str:
    """Deterministic summary of structured answers (not model prose)."""
    return (
        f"threat_type={threat_type.value}; "
        f"injection_risk={injection_risk:.4f}; "
        f"jailbreak_risk={jailbreak_risk:.4f}; "
        f"exfiltration_risk={exfiltration_risk:.4f}; "
        f"tool_risk={tool_risk:.4f}; "
        f"confidence={confidence:.4f}"
    )


def assess_risk(
    response: SystemOneResponse,
    *,
    review_threshold: float = 0.50,
) -> RiskAssessment:
    """Normalize System One answers into a RiskAssessment. Fail closed on bad data."""
    answers = response.answers

    choice = _require_answer(answers, "threat_type", ChoiceAnswer)
    injection = _require_answer(answers, "injection_strength", ScoreAnswer)
    jailbreak = _require_answer(answers, "jailbreak_strength", ScoreAnswer)
    exfil = _require_answer(answers, "exfiltration", NoulAnswer)
    tool = _require_answer(answers, "tool_manipulation", NoulAnswer)

    try:
        threat_type = ThreatType(choice.choice)
    except ValueError as exc:
        raise RiskNormalizationError(
            f"unknown threat_type choice: {choice.choice!r}"
        ) from exc

    # Validate choice probabilities
    if not choice.probabilities:
        raise RiskNormalizationError("choice probabilities are missing")
    for key, value in choice.probabilities.items():
        if value < 0.0 or value > 1.0:
            raise RiskNormalizationError(
                f"choice probability out of [0, 1] for {key}: {value}"
            )
    choice_sum = sum(choice.probabilities.values())
    if abs(choice_sum - 1.0) > PROB_SUM_TOLERANCE:
        raise RiskNormalizationError(
            f"choice probabilities must sum to 1, got {choice_sum}"
        )

    injection_risk, raw_inj = normalize_score_risk(injection)
    jailbreak_risk, raw_jb = normalize_score_risk(jailbreak)
    exfiltration_risk = noul_as_probability(exfil)
    tool_risk = noul_as_probability(tool)

    # Overall confidence = min of choice + two score confidences (noul has none)
    confidence = min(choice.confidence, injection.confidence, jailbreak.confidence)
    confidence = max(0.0, min(1.0, confidence))

    signals = derive_signals(
        threat_type=threat_type,
        injection_risk=injection_risk,
        jailbreak_risk=jailbreak_risk,
        exfiltration_risk=exfiltration_risk,
        tool_risk=tool_risk,
        review_threshold=review_threshold,
    )
    reasoning = build_reasoning(
        threat_type=threat_type,
        injection_risk=injection_risk,
        jailbreak_risk=jailbreak_risk,
        exfiltration_risk=exfiltration_risk,
        tool_risk=tool_risk,
        confidence=confidence,
    )

    return RiskAssessment(
        threat_type=threat_type,
        threat_probabilities=dict(choice.probabilities),
        injection_risk=injection_risk,
        jailbreak_risk=jailbreak_risk,
        exfiltration_risk=exfiltration_risk,
        tool_risk=tool_risk,
        confidence=confidence,
        signals=signals,
        reasoning=reasoning,
        raw_score_injection=raw_inj,
        raw_score_jailbreak=raw_jb,
    )
