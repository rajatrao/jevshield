"""Simulated file operation tool — never deletes or writes real files."""

from __future__ import annotations

from typing import Any


def run(arguments: dict[str, Any]) -> dict[str, Any]:
    operation = str(arguments.get("operation", "read"))
    path = str(arguments.get("path", ""))
    return {
        "status": "simulated",
        "sent": False,
        "operation": operation,
        "path": path,
        "deleted": False,
        "written": False,
        "message": (
            f"File operation '{operation}' on '{path}' was NOT performed. "
            "This is a simulation only."
        ),
    }
