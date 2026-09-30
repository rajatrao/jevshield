"""Simulated email tool — never sends mail."""

from __future__ import annotations

from typing import Any


def run(arguments: dict[str, Any]) -> dict[str, Any]:
    to = str(arguments.get("to", ""))
    subject = str(arguments.get("subject", ""))
    body = str(arguments.get("body", ""))
    return {
        "status": "simulated",
        "sent": False,
        "to": to,
        "subject": subject,
        "body_preview": body[:200],
        "message": "Email was NOT sent. This is a simulation only.",
    }
