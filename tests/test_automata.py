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


def _edges_on(core_pattern: str):
    from certex.analysis.automata import Thompson, path_preserving
    ppn = path_preserving(Thompson(core_of(core_pattern)))
    return ppn


def test_path_preserving_plus_plus_has_two_edges():
    ppn = _edges_on("(a+)+")
    loop_edges = [e for es in ppn.edges.values() for e in es]
    dup = [es for es in ppn.edges.values()
           if len(es) >= 2 and len({(cs, tgt) for cs, tgt, _ in es}) < len(es)]
    assert dup, loop_edges
    assert any(len(es) == 2 and es[0][1] == es[1][1] and es[0][2] != es[1][2]
               for es in ppn.edges.values())


def test_path_preserving_alt_star_has_no_duplicate_labels():
    ppn = _edges_on("(a|b)*")
    for es in ppn.edges.values():
        keys = [(cs, tgt) for cs, tgt, _ in es]
        assert len(keys) == len(set(keys))


def test_path_limit():
    from certex.analysis.automata import PathLimitExceeded, Thompson, path_preserving
    t = Thompson(core_of("((a|b)(c|d)|e)*" + "(a|b|c)*" * 6))
    with pytest.raises(PathLimitExceeded):
        path_preserving(t, max_paths=3)


def test_thompson_language_via_path_preserving():
    from certex.analysis.automata import Thompson, path_preserving
    rng = random.Random(2)
    bad = 0
    for p in [r["pattern"] for r in load_d1()]:
        ppn = path_preserving(Thompson(core_of(p)))
        for s in rand_strings(rng, p, 100):
            cur = {ppn.start}
            for c in s:
                cur = {tgt for q in cur for cs, tgt, _ in ppn.edges[q] if cs.contains(c)}
            bad += bool(cur & ppn.accept) != (re.fullmatch(p, s, re.ASCII) is not None)
    assert bad == 0
