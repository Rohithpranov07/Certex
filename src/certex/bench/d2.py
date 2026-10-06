"""D2: generated homogeneous patterns, 84 types x 3 patterns (TRD v1.1 §B.4)."""

from __future__ import annotations

import itertools
import random

from certex.analysis.types import classify_type, simplify

OPS = "o|*+"
LEAVES = "abcd"


def _build(t: str, depth: int, rng: random.Random) -> str:
    if depth == len(t):
        return rng.choice(LEAVES)
    op = t[depth]
    if op in "o|":
        kids = [_build(t, depth + 1, rng) for _ in range(rng.randint(2, 3))]
        if op == "o":
            return "".join(kids)
        return "(?:" + "|".join(kids) + ")"
    inner = _build(t, depth + 1, rng)
    if len(inner) == 1 or (inner.startswith("(?:") and inner.endswith(")")
                           and _balanced_single(inner)):
        return inner + op
    return "(?:" + inner + ")" + op


def _balanced_single(s: str) -> bool:
    """True if the leading '(' of ``s`` closes at its last character."""
    depth = 0
    for i, c in enumerate(s):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i == len(s) - 1
    return False


def generate(seed: int = 11) -> list[tuple[str, str]]:
    """Return ``(pattern, expected_class)`` for every type of length 1-3 over ``o | * +``."""
    rng = random.Random(seed)
    out: list[tuple[str, str]] = []
    for length in (1, 2, 3):
        for chars in itertools.product(OPS, repeat=length):
            t = "".join(chars)
            expected = classify_type(simplify(t))
            for _ in range(3):
                out.append((_build(t, 0, rng), expected))
    return out
