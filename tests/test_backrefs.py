import pytest

from certex.analysis.backrefs import analyse_backrefs
from certex.frontend.desugar import desugar
from certex.frontend.parser import parse


def verdict(p: str):
    return analyse_backrefs(desugar(parse(p).tree))


@pytest.mark.parametrize("p,vars_,k,redefined,md", [
    (r"(a+)\1", (1,), 1, (), True),
    (r"(\w+)\s\1", (1,), 1, (), True),
    (r"<(\w+)>.*</\1>", (1,), 1, (), True),
    (r"(x+)(y+)\1\2", (1, 2), 2, (), True),
    (r"((a)b)*\2", (2,), 1, (2,), False),
    (r"(a){2}\1", (1,), 1, (1,), False),
])
def test_table_iv(p, vars_, k, redefined, md):
    v = verdict(p)
    assert (v.vars, v.k, v.redefined, v.md_candidate) == (vars_, k, redefined, md)
    assert v.bound == f"|a|*n^O({k})"


def test_none_without_backrefs():
    assert verdict(r"(a+)+$") is None
