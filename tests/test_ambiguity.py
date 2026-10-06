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


def test_d1_labels():
    from .conftest import load_d1
    rows = load_d1()
    ok = 0
    for r in rows:
        v = analyse_ambiguity(core_of(r["pattern"]))
        ok += v.degree == r["label"]
        assert v.degree == r["label"], (r, v)
    print(f"{ok}/{len(rows)}")
    assert ok == len(rows) == 43


def test_d1_profile_none_single_false_positive():
    from .conftest import load_d1
    wrong = [r["pattern"] for r in load_d1()
             if (analyse_ambiguity(core_of(r["pattern"], "none")).degree != "LIN")
             != (r["label"] != "LIN")]
    assert wrong == ["(0|[0-9])+$"]


def test_unexploitable():
    v = analyse_ambiguity(core_of(r"[\s\S]*x*"))
    assert v.degree == LIN and v.unexploitable and v.attack is None


def test_attack_shapes():
    v = analyse_ambiguity(core_of("(a+)+$"))
    assert (v.attack.prefix, v.attack.pump, v.attack.suffix) == ("a", "a", "b")
    v = analyse_ambiguity(core_of(r"x*.*x*$"))
    assert v.degree == POLY and v.attack.suffix == "\n"
    v = analyse_ambiguity(core_of(r"^([a-z0-9]+[-_.]?)*[a-z0-9]+@"))
    assert v.degree == EXP and v.attack.suffix == ""


def test_attack_is_confirmed_by_python_re():
    import re
    import time
    for p in ["(a+)+$", "(x+x+)+y", r"^([a-z0-9]+[-_.]?)*[a-z0-9]+@"]:
        v = analyse_ambiguity(core_of(p))
        k = 1
        while len(v.attack.build(k)) < 22:
            k += 1
        t0 = time.perf_counter()
        re.match(p, v.attack.build(k))
        assert time.perf_counter() - t0 > 0.02, p
