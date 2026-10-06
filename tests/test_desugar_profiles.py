import random
import re

from certex.frontend.desugar import desugar, is_core
from certex.frontend.ir import to_pattern
from certex.frontend.parser import parse

DESUGAR_PATTERNS = [
    "a?", "ab?c", "(ab)?c", "a{2}", "a{2,4}", "a{0,2}", "a{1,}", "a{,3}", "(a|b){2,3}",
    "(ab){1,2}c", "a?b?c?", "(a?)?", "(a{2})?", "x{0}y", "(a|b)?c", "[ab]{2,3}c", "a{0,}b",
    "(?:ab|c){0,2}d", "a{1}", "(a?){2}", "(a+)?b", "(a*)?", ".{1,3}x", r"\d{2,3}-?", r"\w?\s?",
    "(a|)?b", "((a)|b)?c", "a{3}b{1,2}", "(ab?){2}", "a?b{2,}",
]


def _strings(rng: random.Random, p: str, n: int) -> list[str]:
    alpha = "abcdxy01 -\n" + "".join(c for c in p if c.isalnum())
    return ["".join(rng.choice(alpha) for _ in range(rng.randint(0, 8))) for _ in range(n)]


def test_desugar_language_preserved():
    rng = random.Random(3)
    bad = 0
    for p in DESUGAR_PATTERNS:
        tree = desugar(parse(p).tree)
        assert is_core(tree)
        q = to_pattern(tree)
        for s in _strings(rng, p, 200):
            a = re.fullmatch(p, s, re.ASCII) is not None
            b = re.fullmatch(q, s, re.ASCII) is not None
            bad += a != b
    print(f"{bad} disagreements")
    assert bad == 0


def test_desugar_shapes():
    assert to_pattern(desugar(parse("a?").tree)) == "a|"
    assert to_pattern(desugar(parse("a{2,}").tree)) == "aaa*"
    assert to_pattern(desugar(parse("ab?").tree)) == "a(?:b|)"
    assert to_pattern(desugar(parse("a{1,3}").tree)) == "a(?:a|)(?:a|)"
    assert to_pattern(desugar(parse("a{0}").tree)) == ""


# ---- engine profiles ------------------------------------------------------------------
import pytest

from certex.profiles import get_profile

from .conftest import load_d1, load_d5


def _prof(p: str, name: str = "cpython") -> str:
    return to_pattern(get_profile(name)(parse(p).tree))


def test_profile_rewrites():
    assert _prof("(0|[0-9])+") == "([0123456789])+"
    assert _prof("(a|a)*") == "(a(?:|))*"
    assert _prof("(ab|ac)") == "(a[bc])"
    assert _prof("(.|a)") == "(.|a)"
    assert _prof("([^a]|b)") == "([^a]|b)"
    assert _prof("(?:a|b)c") == "[ab]c"
    assert _prof("(0|[0-9])+", "none") == "(0|[0123456789])+"


def test_profile_registry():
    assert get_profile("pcre2")(parse("a|b").tree) == parse("a|b").tree
    assert get_profile("java")(parse("a|b").tree) == parse("a|b").tree
    with pytest.raises(ValueError, match="cpython"):
        get_profile("nope")


def test_profile_preserves_language_on_d1():
    rng = random.Random(5)
    bad = 0
    for p in [r["pattern"] for r in load_d1()] + load_d5():
        q = _prof(p)
        for s in _strings(rng, p, 200):
            bad += (re.fullmatch(p, s, re.ASCII) is None) != (re.fullmatch(q, s, re.ASCII) is None)
    assert bad == 0
