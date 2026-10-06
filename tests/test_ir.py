import itertools

from certex.frontend.ir import (
    ANY,
    DIGITS,
    WORD,
    Alt,
    Bref,
    Cat,
    CharSet,
    Eps,
    Group,
    Lit,
    Plus,
    Repeat,
    Star,
    has_bref,
    strip_groups,
    to_pattern,
)

A = CharSet(frozenset("ab"))
B = CharSet(frozenset("bc"))
NA = CharSet(frozenset("ab"), True)
NB = CharSet(frozenset("bc"), True)
SETS = [A, B, NA, NB]
PROBE = "abcdz\n"


def test_intersect_union_all_cases():
    for x, y in itertools.product(SETS, SETS):
        i, u = x.intersect(y), x.union(y)
        for c in PROBE:
            assert i.contains(c) == (x.contains(c) and y.contains(c))
            assert u.contains(c) == (x.contains(c) or y.contains(c))


def test_any_and_witness():
    assert ANY.contains("\n") is False
    assert ANY.contains("a") is True
    assert CharSet(frozenset("ab"), True).witness() not in "ab"
    assert CharSet().witness() is None
    assert CharSet(frozenset("xy")).witness() == "x"
    assert A.intersect(CharSet(frozenset("z"))).is_empty()


def test_smart_constructors():
    a = Lit(CharSet(frozenset("a")))
    assert Cat([Cat([a, a]), Eps(), a]).kids == (a, a, a)
    assert Cat([Eps()]) == Eps()
    assert Alt([a]) == a


def test_to_pattern():
    a = Lit(CharSet(frozenset("a")))
    b = Lit(CharSet(frozenset("b")))
    assert to_pattern(Star(Group(Plus(a), 1))) == "(a+)*"
    assert to_pattern(Cat([Alt([a, b]), a])) == "(?:a|b)a"
    assert to_pattern(Plus(Cat([a, b]))) == "(?:ab)+"
    assert to_pattern(Repeat(a, 0, 3)) == "a{0,3}"
    assert to_pattern(Lit(CharSet(frozenset("{")))) == "\\{"
    assert to_pattern(Group(Cat([a, Bref(1)]), 1)) == "(a\\1)"
    assert to_pattern(Cat([Bref(1), Lit(CharSet(frozenset("0")))])) == "(?:\\1)0"
    assert to_pattern(Lit(DIGITS)) == "[0123456789]"
    assert to_pattern(Lit(ANY)) == "."
    assert to_pattern(Plus(Plus(a))) == "(?:a+)+"


def test_strip_and_bref():
    a = Lit(CharSet(frozenset("a")))
    t = Cat([Group(Cat([a, a]), 1), Bref(1)])
    assert has_bref(t)
    assert strip_groups(t).kids == (a, a, Bref(1))
    assert WORD.contains("_")
    assert t.size() == 6
