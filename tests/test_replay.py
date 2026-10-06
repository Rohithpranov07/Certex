import pytest

import certex
from certex.engines.replay import BoundAttack, confirm, time_inputs

from .conftest import load_d1

pytestmark = pytest.mark.slow

VULNERABLE = [r["pattern"] for r in load_d1() if r["label"] in ("EXP", "POLY")]


def test_time_inputs_cpython_basic():
    r = time_inputs("cpython", r"(a+)+$", ["a" * 5 + "b", "a" * 10 + "b"])
    assert len(r.points) == 2 and not r.hung and r.error is None


def test_time_inputs_wall_clock_kills_hang():
    r = time_inputs("cpython", r"(a+)+$", ["a" * 60 + "b"], per_input_limit=1.0, wall=2.0)
    assert r.hung


def test_bad_engine_and_pattern():
    with pytest.raises(ValueError):
        time_inputs("nope", "a", ["a"])
    assert time_inputs("cpython", "(", ["a"]).error


@pytest.mark.parametrize("p", VULNERABLE)
def test_cpython_confirms_attack(p):
    c = certex.compile(p)
    assert c.ambiguity is not None and c.ambiguity.attack is not None
    a = c.ambiguity.attack
    res = confirm(c.degree, BoundAttack(p, a.prefix, a.pump, a.suffix), "cpython")
    print(f"{p!r} {c.degree} attack=({a.prefix!r},{a.pump!r},{a.suffix!r}): "
          f"{res['evidence']} confirmed={res['confirmed']}")
    assert res["confirmed"], res


def test_pcre2_engine_limit_counts_as_blowup():
    pytest.importorskip("pcre2")
    res = confirm("EXP", BoundAttack(r"(a+)+$", "a", "a", "b"), "pcre2")
    print(res)
    assert res["confirmed"]


def test_java_replay_runs():
    import shutil
    if shutil.which("javac") is None:
        pytest.skip("no JDK")
    r = time_inputs("java", r"(a+)+$", ["a" * 3 + "b", "a\n" + "b"], wall=60)
    assert r.error is None and len(r.points) == 2
    # Whether Java reproduces an attack is established by calibration (T5.2), not asserted here.
