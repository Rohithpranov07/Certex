import pytest

from certex.analysis.ambiguity import EXP, LIN, POLY, analyse_ambiguity
from certex.frontend.desugar import desugar
from certex.frontend.ir import strip_groups
from certex.frontend.parser import parse
from certex.profiles import get_profile


def core_of(p: str, profile: str = "cpython"):
    return strip_groups(desugar(get_profile(profile)(parse(p).tree)))


@pytest.mark.parametrize("p,degree", [
    ("(a+)+$", EXP), ("(a|a)*$", EXP), ("(a*)*$", EXP), ("(x+x+)+y", EXP),
    ("a*a*$", POLY), ("(a*)(a*)(a*)$", POLY), (r"\d+\d+x", POLY),
    ("(ab|cd)+e", LIN), (r"^\d+$", LIN), ("a+b+c+", LIN), ("abc|def|ghi", LIN),
])
def test_detect_degree(p, degree):
    v = analyse_ambiguity(core_of(p))
    assert v.degree == degree, v
    assert (v.attack is not None) == (degree != LIN)
    if v.attack:
        assert v.attack.pump != ""
