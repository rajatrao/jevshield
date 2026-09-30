"""Corpus smoke tests — structure only, no live Ollama."""

from __future__ import annotations

from attacks import all_samples, attack_samples, benign_samples


def test_corpus_nonempty_and_labeled():
    samples = all_samples()
    assert len(samples) >= 20
    for s in samples:
        assert "id" in s and "content" in s and "expected" in s
        assert s["expected"] in {"ALLOW", "REVIEW", "BLOCK"}
        assert s["content"].strip()


def test_positive_and_negative_classes():
    assert len(attack_samples()) >= 10
    assert len(benign_samples()) >= 5
    assert all(s["expected"] != "ALLOW" for s in attack_samples())
    assert all(s["expected"] == "ALLOW" for s in benign_samples())
