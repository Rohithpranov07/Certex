import pytest

from certex.analysis.types import (
    EASY,
    GENERAL,
    HARD,
    WORDBREAK,
    classify_type,
    infer_type,
    simplify,
)
from certex.bench.d2 import generate
from certex.frontend.desugar import desugar
from certex.frontend.ir import strip_groups
from certex.frontend.parser import parse


def core_of(p: str):
    return strip_groups(desugar(parse(p).tree))


def test_d2_all_classified():
    cases = generate(seed=11)
    assert len(cases) == 252
    ok = 0
    for pat, expected in cases:
        v = infer_type(core_of(pat))
        ok += v.cls == expected
        assert v.cls == expected, (pat, v)
    print(f"{ok}/{len(cases)}")
    assert ok == 252


def test_d2_deterministic():
    assert generate(11) == generate(11)
    assert generate(11) != generate(12)


@pytest.mark.parametrize("pat,raw,norm,cls,core", [
    ("(a+)+$", "++", "+", EASY, None),
    ("(x+x+)+y", "o+o+", "o+o+", HARD, None),
    ("(ab|cd)+e", "o+|o", "o+|o", HARD, None),
    ("((ab)|(cd))+", "+|o", "+|o", WORDBREAK, None),
    ("abc|def|ghi", "|o", "|o", EASY, None),
    ("a*", "*", "+", EASY, None),
    ("(abc)*d", "o*o", "o*o", HARD, None),
])
def test_known_types(pat, raw, norm, cls, core):
    v = infer_type(core_of(pat))
    assert (v.homogeneous, v.raw_type, v.normalised, v.cls, v.hard_core) == (
        True, raw, norm, cls, core)


def test_general_and_hard_core():
    v = infer_type(core_of("a*b*|x+"))
    assert (v.homogeneous, v.cls, v.bound, v.hard_core) == (False, GENERAL, "O(nm)", "o*")
    v = infer_type(core_of("^([a-z0-9]+[-_.]?)*[a-z0-9]+@"))
    assert v.cls == GENERAL and v.hard_core is None


def test_simplify_rules():
    assert simplify("++") == "+"
    assert simplify("+|+") == "+|"
    assert simplify("|*") == "|+"
    assert simplify("o*") == "o*"
    assert classify_type("") == EASY
