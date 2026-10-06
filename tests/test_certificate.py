import copy

import pytest

from certex.backend.certificate import budget_for, pattern_hash, sign, verify

BODY = {
    "pattern_sha256": pattern_hash("(a+)+$"), "profile": "cpython", "m": 3,
    "type": {"homogeneous": True, "raw_type": "++", "normalised": "+", "cls": "EASY",
             "bound": "O~(n)+O(m)", "hard_core": None},
    "ambiguity": {"degree": "EXP", "unexploitable": False, "reason": "",
                  "attack": {"prefix": "a", "pump": "a", "suffix": "b"}},
    "backrefs": None, "kernel": "lazy-dfa", "fallback": "shift-and",
    "rule": "EASY -> near-linear lazy DFA", "bound": "O(n) amortised",
    "budget": {"c": 8, "m": 1, "power": 1},
}


@pytest.fixture(autouse=True)
def _no_key(monkeypatch):
    monkeypatch.delenv("CERTEX_KEY", raising=False)


def test_sign_and_verify():
    cert = sign(BODY)
    assert cert["schema"] == "certex/1" and cert["dev_key"] is True
    assert cert["signature"].startswith("hmac-sha256:")
    assert verify(cert)
    assert "signature" not in BODY


def test_any_edit_fails():
    cert = sign(BODY)
    for path in [("kernel",), ("budget", "c"), ("ambiguity", "attack", "pump"), ("m",),
                 ("type", "cls"), ("dev_key",)]:
        bad = copy.deepcopy(cert)
        node = bad
        for p in path[:-1]:
            node = node[p]
        v = node[path[-1]]
        node[path[-1]] = (not v) if isinstance(v, bool) else (v + 1 if isinstance(v, int) else v + "x")
        assert not verify(bad), path
    extra = dict(cert, extra=1)
    assert not verify(extra)
    assert not verify({k: v for k, v in cert.items() if k != "signature"})


def test_different_key_fails(monkeypatch):
    cert = sign(BODY)
    monkeypatch.setenv("CERTEX_KEY", "secret-one")
    assert not verify(cert)
    cert2 = sign(BODY)
    assert cert2["dev_key"] is False and verify(cert2)
    monkeypatch.setenv("CERTEX_KEY", "secret-two")
    assert not verify(cert2)


def test_budget():
    assert budget_for(sign(BODY), 25) == 8 * 2 * 26 + 64
    cert = {"budget": {"c": 8, "m": 4, "power": 3}}
    assert budget_for(cert, 1) == 8 * 5 * 8 + 64
