import json

import pytest

import certex
from certex.backend.certificate import verify
from certex.frontend.parser import ParseError, UnsupportedSyntax


@pytest.fixture(autouse=True)
def _no_key(monkeypatch):
    monkeypatch.delenv("CERTEX_KEY", raising=False)
    monkeypatch.delenv("CERTEX_PROFILE", raising=False)


def test_exp_pattern():
    c = certex.compile(r"(a+)+$")
    assert (c.degree, c.choice.kernel.name, c.types.cls) == ("EXP", "lazy-dfa", "EASY")
    assert c.vulnerable
    cert = c.certificate
    assert verify(cert) and cert["kernel"] == "lazy-dfa" and cert["fallback"] == "shift-and"
    assert cert["m"] == 3 and cert["budget"] == {"c": 8, "m": 1, "power": 1}
    assert cert["ambiguity"]["attack"] == {"prefix": "a", "pump": "a", "suffix": "b"}
    json.dumps(cert)


def test_profile_effect():
    assert certex.compile(r"(0|[0-9])+$").degree == "LIN"
    assert certex.compile(r"(0|[0-9])+$", profile="none").degree == "EXP"
    assert certex.compile(r"(a|a)*$").degree == "EXP"


def test_backrefs():
    c = certex.compile(r"(\w+)\s\1")
    assert c.degree == "N/A" and not c.vulnerable and c.ambiguity is None
    assert c.certificate["ambiguity"] is None and c.certificate["backrefs"]["k"] == 1
    assert c.certificate["fallback"] is None


def test_lin_and_errors():
    c = certex.compile(r"^\d+$")
    assert c.degree == "LIN" and not c.vulnerable and c.certificate["ambiguity"]["attack"] is None
    with pytest.raises(UnsupportedSyntax):
        certex.compile("(?=a)")
    with pytest.raises(ParseError):
        certex.compile("(a")
    with pytest.raises(ValueError, match="valid profiles"):
        certex.compile("a", profile="nope")


def test_env_defaults(monkeypatch):
    monkeypatch.setenv("CERTEX_PROFILE", "none")
    assert certex.compile(r"(0|[0-9])+$").profile == "none"
