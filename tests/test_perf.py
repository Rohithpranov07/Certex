"""Performance guard (T6.2): mean analysis time at m ~ 60 must stay within the PRD target."""

import time

import pytest

import certex
from certex.bench.experiments import e4_patterns

pytestmark = pytest.mark.slow

LIMIT_MS = 50.0

REALISTIC_LIN = [
    r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.(com|org|net|edu|gov)$",
    r"^(\d{1,3}\.){3}\d{1,3}:[0-9]{1,5}/[a-z]+(-[a-z]+)*\?id=[0-9]+&x=[a-f0-9]{8}$",
    r"(ab|cd|ef|gh|ij)+x(kl|mn|op|qr)+y[0-9]+z[a-f]+w",
    "a?b?c?d?e?f?g?h?i?j?k?l?m?n?o?p?q?r?s?t?u?v?w?x?y?z?",
]


def _mean_ms(patterns: list[str], reps: int = 3) -> float:
    samples = []
    for p in patterns:
        for _ in range(reps):
            t0 = time.perf_counter()
            certex.compile(p)
            samples.append(time.perf_counter() - t0)
    return 1000 * sum(samples) / len(samples)


def test_mean_analysis_time_at_m60():
    patterns = e4_patterns(60)
    assert len(patterns) == 5
    mean = _mean_ms(patterns)
    print(f"m~60 seeded patterns: mean {mean:.2f} ms (limit {LIMIT_MS} ms)")
    assert mean <= LIMIT_MS


def test_mean_analysis_time_realistic_lin():
    mean = _mean_ms(REALISTIC_LIN)
    print(f"realistic LIN patterns (m 28-79): mean {mean:.2f} ms (limit {LIMIT_MS} ms)")
    assert mean <= LIMIT_MS
