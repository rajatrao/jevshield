"""JevShield Streamlit dashboard."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

# Ensure project root is on sys.path when launched via `streamlit run dashboard/app.py`
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import httpx
import streamlit as st

from attacks.benign import BENIGN_SAMPLES
from attacks.direct import DIRECT_INJECTIONS
from attacks.exfiltration import EXFILTRATION_SAMPLES
from attacks.indirect import INDIRECT_INJECTIONS
from attacks.jailbreaks import JAILBREAK_SAMPLES
from attacks.tool_attacks import TOOL_ATTACK_SAMPLES

API_URL = os.getenv("JEVSHIELD_API_URL", "http://127.0.0.1:8000")

DECISION_COLORS = {
    "ALLOW": "#1b7f4e",
    "REVIEW": "#c48a00",
    "BLOCK": "#c62828",
}


def api_post(path: str, payload: dict[str, Any], timeout: float = 180.0) -> dict[str, Any]:
    with httpx.Client(base_url=API_URL, timeout=timeout) as client:
        resp = client.post(path, json=payload)
        resp.raise_for_status()
        return resp.json()


def api_get(path: str, timeout: float = 30.0) -> dict[str, Any]:
    with httpx.Client(base_url=API_URL, timeout=timeout) as client:
        resp = client.get(path)
        resp.raise_for_status()
        return resp.json()


def render_decision_badge(decision: str) -> None:
    color = DECISION_COLORS.get(decision, "#444")
    st.markdown(
        f'<div style="display:inline-block;padding:0.4rem 1rem;border-radius:6px;'
        f'background:{color};color:white;font-weight:700;letter-spacing:0.04em;">'
        f"{decision}</div>",
        unsafe_allow_html=True,
    )


def render_pipeline(result: dict[str, Any]) -> None:
    """Walk input → raw answers → distributions → risk → policy → decision."""
    st.subheader("Decision pipeline")
    cols = st.columns(5)
    steps = [
        "1. Input",
        "2. Typed answers",
        "3. Distributions",
        "4. Normalized risk",
        "5. Policy",
    ]
    for col, label in zip(cols, steps):
        col.markdown(f"**{label}**")

    decision = result.get("decision", "?")
    render_decision_badge(decision)
    st.write("")

    risk = result.get("risk") or {}
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Threat", result.get("threat_type") or "—")
    m2.metric("Injection", f"{(result.get('injection_risk') or 0):.3f}")
    m3.metric("Jailbreak", f"{(result.get('jailbreak_risk') or 0):.3f}")
    m4.metric("Exfiltration", f"{(result.get('exfiltration_risk') or 0):.3f}")
    m5.metric("Tool risk", f"{(result.get('tool_risk') or 0):.3f}")

    st.caption(
        f"confidence={result.get('confidence')} · "
        f"tainted={result.get('tainted')} · "
        f"evaluator={result.get('evaluator_status')} · "
        f"signals={result.get('signals')}"
    )
    st.write(result.get("reasoning") or "")

    if risk.get("threat_probabilities"):
        st.markdown("**Threat-type probabilities**")
        st.bar_chart(risk["threat_probabilities"])

    raw = result.get("raw_systemone")
    with st.expander("Raw Nimble Decision", expanded=False):
        if raw:
            st.json(raw)
        else:
            st.info("No raw System One payload in this response.")


def page_analyzer() -> None:
    st.header("Analyzer")
    st.write("Classify arbitrary text through Nimble System One + JevShield policy.")
    if "analyzer_content" not in st.session_state:
        st.session_state.analyzer_content = ""
    if "analyzer_source" not in st.session_state:
        st.session_state.analyzer_source = "user"

    def _load_direct() -> None:
        st.session_state.analyzer_content = DIRECT_INJECTIONS[0]["content"]
        st.session_state.analyzer_source = DIRECT_INJECTIONS[0]["source"]

    def _load_indirect() -> None:
        st.session_state.analyzer_content = INDIRECT_INJECTIONS[0]["content"]
        st.session_state.analyzer_source = INDIRECT_INJECTIONS[0]["source"]

    def _load_benign() -> None:
        st.session_state.analyzer_content = BENIGN_SAMPLES[0]["content"]
        st.session_state.analyzer_source = BENIGN_SAMPLES[0]["source"]

    c1, c2, c3 = st.columns(3)
    with c1:
        st.button("Load direct injection", key="load_direct", on_click=_load_direct)
    with c2:
        st.button("Load indirect injection", key="load_indirect", on_click=_load_indirect)
    with c3:
        st.button("Load benign", key="load_benign", on_click=_load_benign)

    content = st.text_area(
        "Content",
        height=180,
        placeholder="Paste text to analyze…",
        key="analyzer_content",
    )
    source = st.selectbox(
        "Source",
        [
            "user",
            "web",
            "document",
            "email",
            "database",
            "retrieval",
            "tool",
            "system",
            "developer",
        ],
        key="analyzer_source",
    )
    if st.button("Analyze", type="primary", key="analyze_btn"):
        if not str(content).strip():
            st.warning("Enter some content.")
            return
        with st.spinner("Calling /analyze…"):
            try:
                result = api_post("/analyze", {"content": content, "source": source})
            except Exception as exc:  # noqa: BLE001
                st.error(f"API error: {exc}")
                return
        render_pipeline(result)


def page_attack_simulator() -> None:
    st.header("Attack Simulator")
    st.write(
        "Walk a synthetic sample through typed answers → distributions → "
        "normalized risk → policy."
    )
    catalog = {
        "Direct injection": DIRECT_INJECTIONS,
        "Indirect injection": INDIRECT_INJECTIONS,
        "Jailbreak": JAILBREAK_SAMPLES,
        "Exfiltration": EXFILTRATION_SAMPLES,
        "Tool manipulation": TOOL_ATTACK_SAMPLES,
        "Benign": BENIGN_SAMPLES,
    }
    category = st.radio("Category", list(catalog.keys()), horizontal=True)
    samples = catalog[category]
    labels = [f"{s['id']}: {s['content'][:60]}…" for s in samples]
    idx = st.selectbox("Sample", range(len(samples)), format_func=lambda i: labels[i])
    sample = samples[idx]
    st.code(sample["content"], language=None)
    st.caption(f"source={sample['source']} · corpus expected={sample['expected']}")

    if st.button("Run simulation", type="primary", key="sim_btn"):
        with st.spinner("Calling /analyze…"):
            try:
                result = api_post(
                    "/analyze",
                    {"content": sample["content"], "source": sample["source"]},
                )
            except Exception as exc:  # noqa: BLE001
                st.error(f"API error: {exc}")
                return
        render_pipeline(result)


def page_tool_security() -> None:
    st.header("Tool Security")
    st.write("Authorize a simulated tool call. Dangerous tools never perform real side effects.")
    tool_name = st.selectbox(
        "Tool",
        ["calculator", "search", "email", "file_operation"],
    )
    arguments_text = st.text_area(
        "Arguments (JSON)",
        value=json.dumps(
            {
                "calculator": {"expression": "2+2"},
                "search": {"query": "local weather"},
                "email": {
                    "to": "user@example.com",
                    "subject": "hello",
                    "body": "test",
                },
                "file_operation": {"operation": "read", "path": "/tmp/demo.txt"},
            }[tool_name],
            indent=2,
        ),
        height=140,
    )
    context = st.text_input("Context", value="")
    if st.button("Authorize tool", type="primary", key="tool_btn"):
        try:
            arguments = json.loads(arguments_text)
        except json.JSONDecodeError as exc:
            st.error(f"Invalid JSON: {exc}")
            return
        with st.spinner("Calling /authorize-tool…"):
            try:
                result = api_post(
                    "/authorize-tool",
                    {
                        "tool_name": tool_name,
                        "arguments": arguments,
                        "context": context,
                        "source": "tool",
                    },
                )
            except Exception as exc:  # noqa: BLE001
                st.error(f"API error: {exc}")
                return
        render_decision_badge(result.get("decision", "?"))
        st.write(
            f"authorized={result.get('authorized')} · "
            f"executed={result.get('executed')} · "
            f"approval_required={result.get('approval_required')}"
        )
        if result.get("tool_result"):
            st.subheader("Simulated tool result")
            st.json(result["tool_result"])
        if result.get("security"):
            with st.expander("Security result"):
                st.json(result["security"])


def page_benchmark() -> None:
    st.header("Benchmark")
    st.write(
        "Runs or displays `python -m benchmarks.evaluate` output. "
        "Does **not** invent metrics. Requires live Docker Ollama + nimble."
    )
    model = st.text_input("Model", value="nimble")
    if st.button("Run live benchmark", type="primary", key="bench_btn"):
        import subprocess
        import sys

        with st.spinner(
            "Running live benchmark (CPU Nimble can be slow)…"
        ):
            proc = subprocess.run(
                [sys.executable, "-m", "benchmarks.evaluate", "--model", model, "--json"],
                capture_output=True,
                text=True,
                cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
            )
        if proc.returncode != 0:
            st.error("Benchmark failed (no fabricated metrics).")
            st.code(proc.stderr or proc.stdout or f"exit {proc.returncode}")
            return
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            st.error("Could not parse benchmark JSON.")
            st.code(proc.stdout)
            return
        metrics = {k: v for k, v in data.items() if k != "results"}
        st.json(metrics)
        if data.get("results"):
            st.dataframe(data["results"])


def page_architecture() -> None:
    st.header("Architecture")
    st.markdown(
        """
JevShield is a **local prompt-injection firewall**. Untrusted text is classified
with a single typed `POST /v1/systemone` request to **Nimble** in Docker Ollama
(0.35+). Python normalizes probability distributions and applies a deterministic
ALLOW / REVIEW / BLOCK policy.

```
Application → JevShield → Docker Ollama POST /v1/systemone → Nimble
    → choice / score / noul answers → risk normalization → policy → decision
```

**Why typed decisions (not chat JSON)?**
- Choice, score, and noul return calibrated *distributions*, not free-form text.
- Score returns an expected **index** (0..N-1), not a probability — JevShield
  converts it with `sum((index/(N-1))*P(index))`.
- Noul returns `noul = P(true)` directly.
- Policy is pure Python, so thresholds are auditable and fail-closed.

**Security limitations**
- Detection is imperfect; treat this as defense in depth, not a sandbox.
- No claim of 100% security or perfect prompt-injection prevention.
- Dangerous tools in this demo are **simulated only**.
"""
    )
    try:
        health = api_get("/health")
        st.subheader("Live health")
        st.json(health)
    except Exception as exc:  # noqa: BLE001
        st.warning(f"API not reachable at {API_URL}: {exc}")


def main() -> None:
    st.set_page_config(page_title="JevShield", page_icon="🛡️", layout="wide")
    st.title("JevShield")
    st.caption(f"API: `{API_URL}` · Nimble System One firewall")

    tab_a, tab_b, tab_c, tab_d, tab_e = st.tabs(
        ["Analyzer", "Attack Simulator", "Tool Security", "Benchmark", "Architecture"]
    )
    with tab_a:
        page_analyzer()
    with tab_b:
        page_attack_simulator()
    with tab_c:
        page_tool_security()
    with tab_d:
        page_benchmark()
    with tab_e:
        page_architecture()


if __name__ == "__main__":
    main()
