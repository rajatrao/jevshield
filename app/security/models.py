"""Pydantic models for JevShield security decisions and System One responses."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Decision(str, Enum):
    """Policy decision outcome."""

    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class ThreatType(str, Enum):
    """Choice labels from the threat_type question."""

    SAFE = "safe"
    INJECTION = "injection"
    JAILBREAK = "jailbreak"
    EXFILTRATION = "exfiltration"
    TOOL_MANIPULATION = "tool_manipulation"


class ContentSource(str, Enum):
    """Provenance of content entering the firewall."""

    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    WEB = "web"
    DOCUMENT = "document"
    EMAIL = "email"
    DATABASE = "database"
    RETRIEVAL = "retrieval"
    TOOL = "tool"


class ChoiceAnswer(BaseModel):
    """System One choice answer."""

    type: Literal["choice"] = "choice"
    choice: str
    probabilities: dict[str, float]
    confidence: float


class ScoreAnswer(BaseModel):
    """System One score answer. `score` is expected INDEX 0..N-1, not a probability."""

    type: Literal["score"] = "score"
    score: float
    legend: dict[str, str]
    probabilities: dict[str, float]
    confidence: float


class NoulAnswer(BaseModel):
    """System One noul answer. `noul` IS P(true) in [0, 1]."""

    type: Literal["noul"] = "noul"
    noul: float = Field(ge=0.0, le=1.0)


class SystemOneUsage(BaseModel):
    """Token usage from System One."""

    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)


class SystemOneResponse(BaseModel):
    """Top-level System One response body."""

    model: str
    answers: dict[str, ChoiceAnswer | ScoreAnswer | NoulAnswer]
    usage: SystemOneUsage


class RiskAssessment(BaseModel):
    """Normalized risk signals derived from typed answers."""

    threat_type: ThreatType
    threat_probabilities: dict[str, float]
    injection_risk: float = Field(ge=0.0, le=1.0)
    jailbreak_risk: float = Field(ge=0.0, le=1.0)
    exfiltration_risk: float = Field(ge=0.0, le=1.0)
    tool_risk: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    signals: list[str] = Field(default_factory=list)
    reasoning: str = ""
    raw_score_injection: float | None = None
    raw_score_jailbreak: float | None = None


class SecurityResult(BaseModel):
    """Final firewall result for a piece of content."""

    decision: Decision
    threat_type: ThreatType | None = None
    injection_risk: float | None = None
    jailbreak_risk: float | None = None
    exfiltration_risk: float | None = None
    tool_risk: float | None = None
    confidence: float | None = None
    signals: list[str] = Field(default_factory=list)
    reasoning: str = ""
    source: ContentSource | str | None = None
    tainted: bool = False
    trusted_source: bool = False
    evaluator_status: Literal["ok", "unavailable"] = "ok"
    error: str | None = None
    risk: RiskAssessment | None = None
    raw_systemone: dict[str, Any] | None = None


class AnalyzeRequest(BaseModel):
    """Request body for /analyze and /check-content."""

    content: str
    source: ContentSource | str = ContentSource.USER


class AuthorizeToolRequest(BaseModel):
    """Request body for /authorize-tool."""

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    context: str = ""
    source: ContentSource | str = ContentSource.TOOL


class ToolAuthorizationResult(BaseModel):
    """Result of tool authorization and optional simulated execution."""

    authorized: bool
    executed: bool = False
    approval_required: bool = False
    decision: Decision
    security: SecurityResult
    tool_result: dict[str, Any] | None = None
