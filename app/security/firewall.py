"""Firewall orchestrator: decide → normalize → policy → taint."""

from __future__ import annotations

import logging
from typing import Any

from app.core.config import Settings, get_settings
from app.security.decision_client import DecisionClientError, OllamaDecisionClient
from app.security.models import (
    ContentSource,
    Decision,
    SecurityResult,
    ThreatType,
)
from app.security.policy import apply_policy
from app.security.risk import RiskNormalizationError, assess_risk
from app.security.taint import is_tainted, is_trusted_source

logger = logging.getLogger(__name__)


class Firewall:
    """End-to-end content classification through Nimble System One."""

    def __init__(
        self,
        client: OllamaDecisionClient | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.client = client or OllamaDecisionClient(self.settings)

    async def analyze(
        self,
        content: str,
        source: ContentSource | str = ContentSource.USER,
        *,
        include_raw: bool = False,
    ) -> SecurityResult:
        """Classify content and return a SecurityResult."""
        source_value = source.value if isinstance(source, ContentSource) else str(source)
        trusted = is_trusted_source(
            source_value,
            trust_user=self.settings.jevshield_trust_user,
        )

        try:
            parsed, raw = await self.client.decide(content, source=source_value)
            risk = assess_risk(
                parsed,
                review_threshold=self.settings.jevshield_review_threshold,
            )
            decision = apply_policy(
                risk,
                block_threshold=self.settings.jevshield_block_threshold,
                review_threshold=self.settings.jevshield_review_threshold,
            )
            tainted = is_tainted(
                risk,
                review_threshold=self.settings.jevshield_review_threshold,
            )
            return SecurityResult(
                decision=decision,
                threat_type=risk.threat_type,
                injection_risk=risk.injection_risk,
                jailbreak_risk=risk.jailbreak_risk,
                exfiltration_risk=risk.exfiltration_risk,
                tool_risk=risk.tool_risk,
                confidence=risk.confidence,
                signals=list(risk.signals),
                reasoning=risk.reasoning,
                source=source_value,
                tainted=tainted,
                trusted_source=trusted,
                evaluator_status="ok",
                error=None,
                risk=risk,
                raw_systemone=raw if include_raw else None,
            )
        except (DecisionClientError, RiskNormalizationError) as exc:
            return self._fail_closed(exc, source_value=source_value, trusted=trusted)
        except Exception as exc:  # noqa: BLE001 — fail closed on unexpected errors
            logger.exception("firewall.unexpected_error")
            return self._fail_closed(exc, source_value=source_value, trusted=trusted)

    def _fail_closed(
        self,
        exc: BaseException,
        *,
        source_value: str,
        trusted: bool,
    ) -> SecurityResult:
        message = str(exc) or exc.__class__.__name__
        if self.settings.fail_closed:
            logger.warning("firewall.fail_closed", extra={"error": message})
            return SecurityResult(
                decision=Decision.BLOCK,
                threat_type=None,
                source=source_value,
                tainted=True,
                trusted_source=trusted,
                evaluator_status="unavailable",
                error=message,
                reasoning=f"evaluator unavailable: {message}",
            )
        logger.warning("firewall.fail_open", extra={"error": message})
        return SecurityResult(
            decision=Decision.ALLOW,
            threat_type=ThreatType.SAFE,
            injection_risk=0.0,
            jailbreak_risk=0.0,
            exfiltration_risk=0.0,
            tool_risk=0.0,
            confidence=0.0,
            source=source_value,
            tainted=False,
            trusted_source=trusted,
            evaluator_status="unavailable",
            error=message,
            reasoning=f"evaluator unavailable (fail-open): {message}",
        )

    async def aclose(self) -> None:
        await self.client.aclose()
