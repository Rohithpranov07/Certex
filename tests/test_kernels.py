import re

import pytest

from certex.backend.kernels import BitParallelGlushkov, BudgetExceeded

from .conftest import core_of


def test_glushkov_kernel_basic():
    k = BitParallelGlushkov(core_of("(a|b)*c"))
    assert k.name == "shift-and"
    assert k.run("abac")[0] and not k.run("abab")[0]
    assert k.run("abacz", end_any=True)[0] and not k.run("abacz")[0]
    assert k.run("zzabc", start_any=True, end_any=True)[0]
    assert not k.run("zzab", start_any=True, end_any=True)[0]


def test_glushkov_kernel_names_and_budget():
    assert BitParallelGlushkov(core_of("a{70}")).name == "bitparallel-glushkov"
    k = BitParallelGlushkov(core_of("(a+)+$"))
    with pytest.raises(BudgetExceeded) as e:
        k.run("a" * 50 + "b", budget=10)
    assert e.value.kernel == "shift-and" and e.value.budget == 10 and e.value.steps > 10


def test_empty_pattern():
    k = BitParallelGlushkov(core_of(""))
    assert k.run("")[0] and not k.run("a")[0] and k.run("a", end_any=True)[0]
    assert re.fullmatch("", "")
