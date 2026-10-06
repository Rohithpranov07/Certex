"""Baseline detectors the paper compares against (TRD v1.1 §12, Build task T5.3).

(a) the base paper's timing classifier: time one ``grep -E`` run and bucket the elapsed time;
(b) star height >= 2 (the ``safe-regex`` heuristic).
"""

from __future__ import annotations

import os
import random
import statistics
import subprocess
import tempfile
import time
from collections import Counter

from certex.frontend.ir import PLUS, REPEAT, STAR, Node
from certex.frontend.parser import ParseError, parse

# elapsed / (m * n) thresholds from the base paper's tool
BUCKETS = ((5e-7, "O(n+m)"), (5e-6, "O(nlogn)"), (1e-4, "O(mn)"))
TOP_BUCKET = ">O(mn)"
TIMING_POSITIVE = ("O(mn)", TOP_BUCKET)       # labels the baseline treats as "vulnerable"
GREP_TIMEOUT = 10.0


def bucket(ratio: float) -> str:
    for threshold, label in BUCKETS:
        if ratio < threshold:
            return label
    return TOP_BUCKET


def baseline_text(pattern: str, n: int, seed: int) -> str:
    """A fixed benign line of ``n`` characters drawn from the pattern's own alphanumerics."""
    rng = random.Random(f"{seed}:{pattern}")
    alphabet = sorted({c for c in pattern if c.isalnum()}) or ["a"]
    return "".join(rng.choice([*alphabet, " "]) for _ in range(n))


def timing_label(pattern: str, runs: int = 10, n: int = 1000,
                 seed: int = 7) -> tuple[str, float]:
    """(modal bucket over ``runs`` timings of ``grep -E``, median elapsed/(m*n))."""
    m = max(len(pattern), 1)
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(baseline_text(pattern, n, seed) + "\n")
        path = f.name
    labels: list[str] = []
    ratios: list[float] = []
    try:
        for _ in range(runs):
            t0 = time.perf_counter()
            try:
                subprocess.run(["grep", "-E", "-c", "--", pattern, path], capture_output=True,
                               timeout=GREP_TIMEOUT, check=False)
                elapsed = time.perf_counter() - t0
            except subprocess.TimeoutExpired:
                elapsed = GREP_TIMEOUT
            ratio = elapsed / (m * n)
            ratios.append(ratio)
            labels.append(bucket(ratio))
    finally:
        os.unlink(path)
    return Counter(labels).most_common(1)[0][0], statistics.median(ratios)


def star_height(n: Node) -> int:
    inner = max((star_height(k) for k in n.kids), default=0)
    unbounded = n.op in (STAR, PLUS) or (n.op == REPEAT and (n.hi is None or n.hi > 1))
    return inner + (1 if unbounded else 0)


def star_height_flag(pattern: str) -> bool | None:
    """True if star height >= 2; None if the pattern is outside the v1 subset."""
    try:
        return star_height(parse(pattern).tree) >= 2
    except ParseError:
        return None
