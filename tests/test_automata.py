import random
import re

import pytest

from certex.analysis.automata import START, Glushkov
from certex.frontend.desugar import desugar
from certex.frontend.ir import strip_groups
from certex.frontend.parser import parse
from certex.profiles import get_profile

from .conftest import load_d1, load_d5

ALPHA = "abcdx0123 .@-_!,=;<>/\n\tyz"


def core_of(p: str, profile: str = "cpython"):
    return strip_groups(desugar(get_profile(profile)(parse(p).tree)))


def accepts(g: Glushkov, s: str) -> bool:
    states: frozenset[int] = frozenset({START})
    for c in s:
        states = g.step(states, c)
        if not states:
            return False
    return bool(states & g.accept)


def rand_strings(rng: random.Random, p: str, n: int) -> list[str]:
    own = "".join(c for c in p if c.isalnum()) or "a"
    out = []
    for _ in range(n):
        pool = ALPHA if rng.random() < 0.7 else own
        out.append("".join(rng.choice(pool) for _ in range(rng.randint(0, 10))))
    return out


def test_glushkov_matches_re():
    rng = random.Random(1)
    bad = total = 0
    pats = [r["pattern"] for r in load_d1()] + load_d5() + ["", "a|", "(a|)+", "[^ab]+c", ".x."]
    for p in pats:
        g = Glushkov(core_of(p))
        for s in rand_strings(rng, p, 300):
            total += 1
            bad += accepts(g, s) != (re.fullmatch(p, s, re.ASCII) is not None)
    print(f"{total} cases, {bad} disagreements")
    assert bad == 0


def test_glushkov_structure():
    g = Glushkov(core_of("(a+)+"))
    assert len(g.pos) == 1 and g.follow[0] == {0} and g.accept == {0}
    g = Glushkov(core_of("a*"))
    assert START in g.accept and g.succ(START) == {0}
    g = Glushkov(core_of("[ab]x"))
    assert set(g.alphabet_reps()) >= {"a", "b", "x"} and len(g.alphabet_reps()) == 4
    assert g.alphabet_reps()[-1] not in "abx"


@pytest.mark.parametrize("p", ["(a)\\1", "a?"])
def test_bref_and_opt_build(p):
    Glushkov(core_of(p))
