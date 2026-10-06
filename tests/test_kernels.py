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


from .conftest import all_patterns, differential_run, kernel_matcher


def test_differential_glushkov():
    cases, bad = differential_run(kernel_matcher(BitParallelGlushkov), all_patterns())
    assert cases >= 50000
    assert bad == 0


from certex.backend.kernels import LazyDFA


def test_differential_lazy():
    cases, bad = differential_run(kernel_matcher(LazyDFA), all_patterns())
    assert cases >= 50000 and bad == 0


def test_lazy_dfa_cache_bounded_and_amortised():
    k = LazyDFA(core_of("(a+)+$"), max_cache=4)
    text = "a" * 2000 + "b"
    assert k.run(text)[0] is False
    assert len(k._cache) <= 4
    k2 = LazyDFA(core_of("(a+)+$"))
    _, cold = k2.run("a" * 500 + "b")
    _, warm = k2.run("a" * 500 + "b")
    assert warm < cold and warm <= 502


import random

from certex.backend.kernels import (
    AhoCorasick,
    WordBreak,
    literal_strings,
    word_break_words,
)

DICT_PATTERNS = ["abc|def|ghi", "a", "abc", "ab|abc|b", "", "a|", "x|yy|yyy", "he|she|his|hers",
                 "^(?:ab|abc)$", "abc$", "^abc", "aa|a"]
WB_PATTERNS = ["(ab|cd)+", "(ab|cd)*", "(abc)*", "(abc)+", "(a|b)+", "(ab|abab)+", "(a|aa)*",
               "(abc|ab|c)+"]


def _aho(core):
    words = literal_strings(core)
    assert words is not None
    return AhoCorasick(words)


def test_differential_aho_corasick():
    cases, bad = differential_run(kernel_matcher(_aho, "none"), DICT_PATTERNS)
    assert bad == 0 and cases > 0


def test_literal_strings_recognition():
    assert literal_strings(core_of("abc|def")) == ["abc", "def"]
    assert literal_strings(core_of("abc")) == ["abc"]
    assert literal_strings(core_of("a|b|c", "none")) == ["a", "b", "c"]
    assert literal_strings(core_of("a+")) is None
    assert literal_strings(core_of("[ab]c")) is None
    assert literal_strings(core_of(".a")) is None


def test_word_break_recognition():
    assert word_break_words(core_of("(ab|cd)+")) == (["ab", "cd"], False)
    assert word_break_words(core_of("(abc)*")) == (["abc"], True)
    assert word_break_words(core_of("(a|)+")) is None
    assert word_break_words(core_of("ab+")) is None


def test_differential_word_break():
    rng = random.Random(7)
    bad = total = 0
    for p in WB_PATTERNS:
        core = core_of(p, "none")
        wb = word_break_words(core)
        assert wb is not None, p
        kernel = WordBreak(*wb)
        alpha = "".join(sorted({c for c in p if c.isalpha()}))
        strings = ["", *("".join(rng.choice(alpha) for _ in range(rng.randint(0, 12)))
                         for _ in range(400))]
        for s in strings:
            total += 1
            bad += kernel.run(s)[0] != (re.fullmatch(p, s, re.ASCII) is not None)
    print(f"{total} cases, {bad} disagreements")
    assert bad == 0
    with pytest.raises(NotImplementedError):
        WordBreak(["a"], False).run("a", end_any=True)
