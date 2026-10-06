import pytest

from certex.frontend.ir import ALT, ANY, BREF, GROUP, PLUS, REPEAT, CharSet, to_pattern
from certex.frontend.parser import ParseError, UnsupportedSyntax, parse

from .conftest import load_d1, load_d5


def test_dataset_patterns_parse():
    for p in [r["pattern"] for r in load_d1()] + load_d5():
        parse(p)


def test_anchors():
    r = parse("^(?:ab|cd)$")
    assert r.anchored_start and r.anchored_end
    r = parse("abc")
    assert not r.anchored_start and not r.anchored_end


@pytest.mark.parametrize("p", ["^ab|cd", "ab|cd$", "a^b", "a$b"])
def test_anchor_rejections(p):
    with pytest.raises(UnsupportedSyntax):
        parse(p)


def test_literal_brace_and_repeat_forms():
    assert to_pattern(parse(r"a{,3}b{").tree) == "a{0,3}b\\{"
    assert to_pattern(parse("a{2,}").tree) == "a{2,}"
    assert to_pattern(parse("a{}").tree) == "a\\{\\}"
    assert to_pattern(parse("a{,}").tree) == "a\\{,\\}"
    assert parse("a{2}").tree.op == REPEAT


@pytest.mark.parametrize("p,off", [
    ("a*?", 2), ("a++", 2), ("a{2}?", 4), ("(?=a)", 0), ("(?!a)", 0), ("(?<=a)", 0),
    ("(?>a)", 0), ("(?i)a", 0), (r"\bfoo", 0), (r"\Aa", 0), (r"\Za", 0), (r"a\q", 1),
    ("a{1001}", 1), ("(?P<n>a)(?P=n)", 8),
])
def test_unsupported(p, off):
    with pytest.raises(UnsupportedSyntax) as e:
        parse(p)
    assert e.value.offset == off


@pytest.mark.parametrize("p", [
    "a{3,2}", "(a", "a)", "*a", "a**", r"\1", r"(a\1)", r"\x4", "[a", "[z-a]", "(?P<n>a)(?P<n>b)",
    "^*",
])
def test_parse_errors(p):
    with pytest.raises(ParseError) as e:
        parse(p)
    assert not isinstance(e.value, UnsupportedSyntax)
    assert isinstance(e.value.offset, int)


def test_groups_and_backrefs():
    r = parse(r"(a)(?:b)(?P<x>c)\2")
    assert r.ngroups == 2
    assert r.tree.kids[0].op == GROUP and r.tree.kids[0].group == 1
    assert r.tree.kids[-1].op == BREF and r.tree.kids[-1].group == 2
    r = parse(r"(a)\10")          # only one group: \1 then literal 0
    assert [k.op for k in r.tree.kids] == [GROUP, BREF, "lit"]


def test_classes():
    t = parse(r"[^\n]").tree
    assert t.cs == ANY
    assert parse(r"[a-c\d-]").tree.cs == CharSet(frozenset("abc0123456789-"))
    assert parse(r"[]a]").tree.cs == CharSet(frozenset("]a"))
    assert parse(r"[\W]").tree.cs.negated
    assert parse(r"\x41").tree.cs == CharSet(frozenset("A"))


def test_structure():
    assert parse("a|b").tree.op == ALT
    assert parse("(a+)+").tree.op == GROUP or parse("(a+)+").tree.op == PLUS
    assert parse("").tree.op == "eps"
