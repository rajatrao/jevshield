"""Tool authorization guard — simulated tools only."""

from __future__ import annotations

import json
from typing import Any, Callable, Awaitable

from app.core.config import Settings, get_settings
from app.security.firewall import Firewall
from app.security.models import (
    ContentSource,
    Decision,
    SecurityResult,
    ToolAuthorizationResult,
)
from app.tools import calculator, email, file_operation, search

ToolHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]] | dict[str, Any]]

SIMULATED_TOOLS: dict[str, ToolHandler] = {
    "calculator": calculator.run,
    "search": search.run,
    "email": email.run,
    "file_operation": file_operation.run,
}


class ToolGuard:
    """Classify tool name + arguments + context; execute only on ALLOW."""

    def __init__(
        self,
        firewall: Firewall | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.firewall = firewall or Firewall(settings=self.settings)

    async def authorize(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        context: str = "",
        source: ContentSource | str = ContentSource.TOOL,
    ) -> ToolAuthorizationResult:
        """
        Run the five-question classifier on the tool invocation payload.

        execute() runs a simulated tool only when decision is ALLOW.
        REVIEW sets approval_required and does not execute.
        BLOCK does not execute.
        """
        arguments = arguments or {}
        payload = {
            "tool_name": tool_name,
            "arguments": arguments,
            "context": context,
        }
        content = json.dumps(payload, ensure_ascii=False, default=str)
        security = await self.firewall.analyze(
            content,
            source=source,
            include_raw=False,
        )

        if security.tainted and security.decision != Decision.ALLOW:
            # Tainted text is never passed to a tool as instructions.
            return self._result(
                security=security,
                authorized=False,
                executed=False,
                approval_required=security.decision == Decision.REVIEW,
                tool_result=None,
            )

        if security.decision == Decision.ALLOW:
            tool_result = await self.execute(tool_name, arguments)
            return self._result(
                security=security,
                authorized=True,
                executed=True,
                approval_required=False,
                tool_result=tool_result,
            )

        if security.decision == Decision.REVIEW:
            return self._result(
                security=security,
                authorized=False,
                executed=False,
                approval_required=True,
                tool_result=None,
            )

        return self._result(
            security=security,
            authorized=False,
            executed=False,
            approval_required=False,
            tool_result=None,
        )

    async def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Run a simulated tool. Never performs real email/FS/shell actions."""
        handler = SIMULATED_TOOLS.get(tool_name)
        if handler is None:
            return {
                "status": "simulated",
                "error": f"unknown tool: {tool_name}",
                "sent": False,
            }
        result = handler(arguments)
        if hasattr(result, "__await__"):
            result = await result  # type: ignore[misc]
        return result  # type: ignore[return-value]

    @staticmethod
    def _result(
        *,
        security: SecurityResult,
        authorized: bool,
        executed: bool,
        approval_required: bool,
        tool_result: dict[str, Any] | None,
    ) -> ToolAuthorizationResult:
        return ToolAuthorizationResult(
            authorized=authorized,
            executed=executed,
            approval_required=approval_required,
            decision=security.decision,
            security=security,
            tool_result=tool_result,
        )
