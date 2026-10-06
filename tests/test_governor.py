import copy

import pytest

import certex
from certex.backend.kernels import BudgetExceeded
from certex.runtime.governor import CertificateInvalid, MatchResult, run


@pytest.fixture(autouse=True)
def _no_key(monkeypatch):
    monkeypatch.delenv("CERTEX_KEY", raising=False)


def test_modes_and_anchors():
    c = certex.compile(r"abc")
    assert run(c, "abc").matched and not run(c, "abcd").matched
    assert run(c, "abcd", "match").matched and not run(c, "xabc", "match").matched
    assert run(c, "xxabcxx", "search").matched
    anchored = certex.compile(r"^abc$")
    assert run(anchored, "abc", "search").matched
    assert not run(anchored, "xabc", "search").matched and not run(anchored, "abcx", "search").matched


def test_dollar_before_final_newline():
    c = certex.compile(r"abc$")
    assert run(c, "abc\n", "match").matched and run(c, "xabc\n", "search").matched
    assert not run(c, "abc\n", "full").matched
    assert not run(c, "abc\n\n", "search").matched


def test_result_fields_and_attack():
    c = certex.compile(r"(a+)+$")
    r = run(c, "a" * 40 + "b", "match")
    assert isinstance(r, MatchResult)
    assert (r.matched, r.kernel, r.fell_back) == (False, "lazy-dfa", False)
    assert r.steps < 200


def test_wordbreak_search_uses_fallback_kernel():
    c = certex.compile(r"((ab)|(cd))+")
    assert c.choice.kernel.name == "word-break"
    assert run(c, "abcd").kernel == "word-break"
    r = run(c, "xxabcdxx", "search")
    assert r.matched and r.kernel == "shift-and" and not r.fell_back


def test_tampered_certificate():
    c = certex.compile(r"(a+)+$")
    c.certificate["budget"]["c"] = 10**9
    with pytest.raises(CertificateInvalid):
        run(c, "aaab")
    c2 = certex.compile(r"abc|def")
    c2.certificate = copy.deepcopy(c2.certificate)
    c2.certificate["signature"] = "hmac-sha256:" + "0" * 64
    with pytest.raises(CertificateInvalid):
        run(c2, "abc")


def test_bad_arguments():
    c = certex.compile("a")
    with pytest.raises(ValueError):
        run(c, "a", "nope")
    with pytest.raises(ValueError):
        run(c, "a", on_overrun="nope")


def test_overrun_fallback_and_reject():
    c = certex.compile(r"(a+)+$")
    r = run(c, "a" * 30 + "b", budget_override=5)
    assert r.fell_back and r.kernel == "shift-and" and not r.matched
    with pytest.raises(BudgetExceeded):
        run(c, "a" * 30 + "b", on_overrun="reject", budget_override=5)
    pike = certex.compile(r"(a+)\1")
    with pytest.raises(BudgetExceeded):          # no fallback for backreference kernels
        run(pike, "a" * 30, budget_override=5)


def test_backreference_matching():
    c = certex.compile(r"(\w+)\s\1")
    assert run(c, "hello hello").matched and not run(c, "hello world").matched
    assert run(c, "say hello hello x", "search").matched
