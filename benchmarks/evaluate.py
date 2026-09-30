"""Live benchmark against Ollama System One. Never fabricates metrics."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import asdict, dataclass
from typing import Any

from app.core.config import get_settings
from app.security.decision_client import (
    DecisionClientError,
    ModelNotFoundError,
    OllamaDecisionClient,
    UnsupportedModelError,
)
from app.security.models import Decision
from app.security.policy import apply_policy
from app.security.risk import assess_risk
from attacks import all_samples


@dataclass
class SampleResult:
    id: str
    category: str
    expected: str
    predicted: str
    correct: bool
    threat_type: str | None
    injection_risk: float | None
    latency_total_ms: float
    evaluator_status: str
    error: str | None


def _is_positive(label: str) -> bool:
    """Positive class = should not ALLOW (attacks)."""
    return label != Decision.ALLOW.value


def _binary_match(expected: str, predicted: str) -> bool:
    """Match on attack-vs-benign polarity (not exact ALLOW/REVIEW/BLOCK)."""
    return _is_positive(expected) == _is_positive(predicted)


async def run_benchmark(model: str) -> dict[str, Any]:
    settings = get_settings()
    client = OllamaDecisionClient(settings)

    health = await client.health()
    if not health.get("ollama_reachable"):
        await client.aclose()
        raise SystemExit(
            f"ERROR: Ollama unreachable at {settings.ollama_host}: {health.get('error')}"
        )

    samples = all_samples()
    results: list[SampleResult] = []
    t0 = time.perf_counter()

    try:
        for sample in samples:
            st = time.perf_counter()
            try:
                parsed, _raw = await client.decide(
                    sample["content"],
                    source=sample.get("source", "user"),
                    model=model,
                )
                risk = assess_risk(
                    parsed,
                    review_threshold=settings.jevshield_review_threshold,
                )
                decision = apply_policy(
                    risk,
                    block_threshold=settings.jevshield_block_threshold,
                    review_threshold=settings.jevshield_review_threshold,
                )
                predicted = decision.value
                elapsed = (time.perf_counter() - st) * 1000
                results.append(
                    SampleResult(
                        id=sample["id"],
                        category=sample["category"],
                        expected=sample["expected"],
                        predicted=predicted,
                        correct=_binary_match(sample["expected"], predicted),
                        threat_type=risk.threat_type.value,
                        injection_risk=risk.injection_risk,
                        latency_total_ms=elapsed,
                        evaluator_status="ok",
                        error=None,
                    )
                )
            except (ModelNotFoundError, UnsupportedModelError) as exc:
                await client.aclose()
                raise SystemExit(
                    f"ERROR: model '{model}' unsupported or missing: {exc}"
                ) from exc
            except DecisionClientError as exc:
                elapsed = (time.perf_counter() - st) * 1000
                results.append(
                    SampleResult(
                        id=sample["id"],
                        category=sample["category"],
                        expected=sample["expected"],
                        predicted="BLOCK",
                        correct=False,
                        threat_type=None,
                        injection_risk=None,
                        latency_total_ms=elapsed,
                        evaluator_status="unavailable",
                        error=str(exc),
                    )
                )
    finally:
        await client.aclose()

    total_ms = (time.perf_counter() - t0) * 1000

    tp = fp = tn = fn = 0
    exact = 0
    for r in results:
        if r.expected == r.predicted:
            exact += 1
        exp_pos = _is_positive(r.expected)
        pred_pos = _is_positive(r.predicted)
        if exp_pos and pred_pos:
            tp += 1
        elif not exp_pos and pred_pos:
            fp += 1
        elif not exp_pos and not pred_pos:
            tn += 1
        else:
            fn += 1

    n = len(results) or 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (
        2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    )
    accuracy = (tp + tn) / n
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    latencies = [r.latency_total_ms for r in results]
    sorted_lat = sorted(latencies)

    return {
        "model": model,
        "ollama_host": settings.ollama_host,
        "ollama_version": health.get("version"),
        "sample_count": len(results),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "exact_decision_match_rate": exact / n,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "latency_ms": {
            "mean_total": sum(latencies) / len(latencies) if latencies else 0.0,
            "p50_total": sorted_lat[len(sorted_lat) // 2] if sorted_lat else 0.0,
            "wall_total": total_ms,
        },
        "note": (
            "Positive class = should not ALLOW (attacks). "
            "Metrics from live POST /v1/systemone only."
        ),
        "results": [asdict(r) for r in results],
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="JevShield live Nimble benchmark")
    parser.add_argument(
        "--model",
        default=None,
        help="Ollama decision model (default: OLLAMA_DECISION_MODEL)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print full JSON including per-sample results",
    )
    args = parser.parse_args(argv)
    settings = get_settings()
    model = args.model or settings.ollama_decision_model

    try:
        summary = asyncio.run(run_benchmark(model))
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        raise

    if args.json:
        print(json.dumps(summary, indent=2))
        return

    printable = {k: v for k, v in summary.items() if k != "results"}
    print(json.dumps(printable, indent=2))
    print("\nPer-sample:")
    for r in summary["results"]:
        mark = "OK" if r["correct"] else "MISS"
        print(
            f"  [{mark}] {r['id']:16} expected={r['expected']:6} "
            f"predicted={r['predicted']:6} "
            f"latency_ms={r['latency_total_ms']:.0f}"
        )


if __name__ == "__main__":
    main()
