"""Simulated web search tool — no network calls."""

from __future__ import annotations

from typing import Any


def run(arguments: dict[str, Any]) -> dict[str, Any]:
    query = str(arguments.get("query", ""))
    return {
        "status": "simulated",
        "sent": False,
        "query": query,
        "results": [
            {
                "title": f"[simulated] Result for: {query[:80]}",
                "url": "https://example.invalid/simulated",
                "snippet": "This is a simulated search result. No network request was made.",
            }
        ],
    }
