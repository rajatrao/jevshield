"""Synthetic attack corpora package."""

from __future__ import annotations

from attacks.benign import BENIGN_SAMPLES
from attacks.direct import DIRECT_INJECTIONS
from attacks.exfiltration import EXFILTRATION_SAMPLES
from attacks.indirect import INDIRECT_INJECTIONS
from attacks.jailbreaks import JAILBREAK_SAMPLES
from attacks.tool_attacks import TOOL_ATTACK_SAMPLES


def all_samples() -> list[dict]:
    """Return all corpus samples with expected_label and category."""
    return (
        list(DIRECT_INJECTIONS)
        + list(INDIRECT_INJECTIONS)
        + list(JAILBREAK_SAMPLES)
        + list(EXFILTRATION_SAMPLES)
        + list(TOOL_ATTACK_SAMPLES)
        + list(BENIGN_SAMPLES)
    )


def attack_samples() -> list[dict]:
    """Positive class: should not ALLOW."""
    return [s for s in all_samples() if s["expected"] != "ALLOW"]


def benign_samples() -> list[dict]:
    """Negative class: should ALLOW."""
    return [s for s in all_samples() if s["expected"] == "ALLOW"]
