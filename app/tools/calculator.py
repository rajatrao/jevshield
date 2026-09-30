"""Simulated calculator tool."""

from __future__ import annotations

from typing import Any


def run(arguments: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a simple arithmetic expression in a sandbox-safe way (simulated)."""
    expression = str(arguments.get("expression", ""))
    # Only allow digits and basic operators — still simulated, no eval of arbitrary code.
    allowed = set("0123456789+-*/().% ")
    if expression and all(ch in allowed for ch in expression):
        try:
            value = float(eval(expression, {"__builtins__": {}}, {}))  # noqa: S307
            return {
                "status": "simulated",
                "sent": False,
                "expression": expression,
                "result": value,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "status": "simulated",
                "sent": False,
                "expression": expression,
                "error": str(exc),
            }
    return {
        "status": "simulated",
        "sent": False,
        "expression": expression,
        "error": "expression rejected; only basic arithmetic is simulated",
    }
