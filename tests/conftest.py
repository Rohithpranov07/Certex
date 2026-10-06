import csv
from pathlib import Path

import pytest

from certex.frontend.desugar import desugar
from certex.frontend.ir import Node, strip_groups
from certex.frontend.parser import parse
from certex.profiles import get_profile

ROOT = Path(__file__).resolve().parent.parent


def load_d1() -> list[dict[str, str]]:
    with open(ROOT / "datasets" / "d1_redos.csv", newline="") as f:
        return list(csv.DictReader(f))


def load_d5() -> list[str]:
    with open(ROOT / "datasets" / "d5_base_paper.csv", newline="") as f:
        return [r["pattern"] for r in csv.DictReader(f)]


@pytest.fixture(scope="session")
def d1() -> list[dict[str, str]]:
    return load_d1()


@pytest.fixture(scope="session")
def d5() -> list[str]:
    return load_d5()


def core_of(p: str, profile: str = "cpython") -> Node:
    return strip_groups(desugar(get_profile(profile)(parse(p).tree)))


# ---- differential oracle (T3.2) -----------------------------------------------------------
import random
import re
from collections.abc import Callable

ALPHABET = "abcdx0123 .@-_!,=;<>/\n\tyz"
MODES = ("full", "match", "search")
_FLAGS = {"full": (False, False), "match": (False, True), "search": (True, True)}
_RE = {"full": re.fullmatch, "match": re.match, "search": re.search}

EXTRA_PATTERNS = [
    "abc|def|ghi", "(ab|cd)+", "(ab|cd|a)*", "(?:abc|d)*", "", "a|", "(a|)+", "[^ab]+c", ".x.",
    "abc$",
]


def all_patterns() -> list[str]:
    return [r["pattern"] for r in load_d1()] + load_d5() + EXTRA_PATTERNS


def kernel_matcher(make: Callable[[Node], object], profile: str = "cpython") -> Callable[[str], Callable[[str, str], bool]]:
    """Wrap a core->Kernel factory into pattern -> match(text, mode), applying anchors and the
    Python ``$`` rule exactly as the governor does (T4.7)."""
    def factory(p: str) -> Callable[[str, str], bool]:
        parsed = parse(p)
        kernel = make(core_of(p, profile))

        def match(text: str, mode: str) -> bool:
            start_any, end_any = _FLAGS[mode]
            if parsed.anchored_start:
                start_any = False
            if parsed.anchored_end:
                end_any = False
            ok, _ = kernel.run(text, start_any, end_any)  # type: ignore[attr-defined]
            if not ok and mode != "full" and parsed.anchored_end and text.endswith("\n"):
                ok, _ = kernel.run(text[:-1], start_any, end_any)  # type: ignore[attr-defined]
            return bool(ok)
        return match
    return factory


def random_strings(rng: random.Random, p: str, n: int = 300) -> list[str]:
    own = "".join(c for c in p if c.isalnum()) or "a"
    out = []
    for _ in range(n):
        pool = ALPHABET if rng.random() < 0.7 else own
        out.append("".join(rng.choice(pool) for _ in range(rng.randint(0, 10))))
    return out


def differential_run(factory: Callable[[str], Callable[[str, str], bool]],
                     patterns: list[str], verbose: bool = True) -> tuple[int, int]:
    rng = random.Random(1)
    cases = bad = 0
    for p in patterns:
        match = factory(p)
        for s in random_strings(rng, p):
            for mode in MODES:
                cases += 1
                expected = _RE[mode](p, s, re.ASCII) is not None
                got = match(s, mode)
                if got != expected:
                    bad += 1
                    if verbose and bad <= 10:
                        print(f"MISMATCH {p!r} {s!r} {mode}: expected {expected} got {got}")
    print(f"{cases} cases, {bad} disagreements")
    return cases, bad


@pytest.fixture
def differential() -> Callable[..., tuple[int, int]]:
    return differential_run
