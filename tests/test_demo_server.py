import importlib.util
import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from types import ModuleType

import pytest

from .conftest import ROOT


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("certex_demo_server",
                                                  ROOT / "demo" / "server.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


demo = _load()


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("CERTEX_KEY", raising=False)
    monkeypatch.delenv("CERTEX_PROFILE", raising=False)


def test_compile_vulnerable_reports_attack_and_certificate():
    r = demo.api_compile({"pattern": "(a+)+$"})
    assert r["ok"] and r["degree"] == "EXP" and r["vulnerable"]
    atk = r["ambiguity"]["attack"]
    assert atk["example"] == atk["prefix"] + atk["pump"] * 20 + atk["suffix"]
    assert r["kernel"]["name"] == r["certificate"]["kernel"] == "lazy-dfa"
    assert r["signature_ok"] and r["dev_key"]


def test_compile_profile_changes_verdict():
    assert demo.api_compile({"pattern": "(0|[0-9])+$", "profile": "none"})["degree"] == "EXP"
    assert demo.api_compile({"pattern": "(0|[0-9])+$", "profile": "cpython"})["degree"] == "LIN"


def test_compile_errors_carry_offset():
    r = demo.api_compile({"pattern": "a*?"})
    assert r == {"ok": False, "error": {"kind": "UnsupportedSyntax",
                                        "message": "lazy/possessive quantifier", "offset": 2}}


def test_compile_backreference_goes_to_gate():
    r = demo.api_compile({"pattern": r"(\w+)\s\1"})
    assert r["degree"] == "N/A" and r["ambiguity"] is None
    assert r["backrefs"]["vars"] == [1] and r["kernel"]["fallback"] is None


@pytest.mark.parametrize("body", [{}, {"pattern": 3}, {"pattern": "a", "profile": "perl"},
                                  {"pattern": "a" * 501}])
def test_compile_rejects_bad_requests(body):
    with pytest.raises(demo.BadRequest):
        demo.api_compile(body)


def test_match_runs_through_governor():
    r = demo.api_match({"pattern": r"(\w+)\s\1", "text": "hello hello"})
    assert r["ok"] and r["matched"] and r["kernel"] == "pike-vm-mfa"
    assert 0 < r["steps"] <= r["budget"]
    r = demo.api_match({"pattern": "ab", "text": "xaby", "mode": "search"})
    assert r["matched"]
    with pytest.raises(demo.BadRequest):
        demo.api_match({"pattern": "a", "text": "a", "mode": "fuzzy"})


def test_race_needs_an_attack():
    r = demo.api_race({"pattern": r"^\d+$"})
    assert not r["ok"] and r["error"]["kind"] == "NoAttack"
    for k in (0, demo.MAX_PUMP + 1, True, "3"):
        with pytest.raises(demo.BadRequest):
            demo.api_race({"pattern": "(a+)+$", "k": k})


def test_race_small_k_both_engines_finish():
    r = demo.api_race({"pattern": "(a+)+$", "k": 4})
    assert r["ok"] and r["length"] == 6
    assert r["certex"]["kernel"] == "lazy-dfa" and not r["certex"]["matched"]
    assert r["certex"]["steps"] <= r["certex"]["budget"]
    assert not r["cpython"]["killed"] and r["cpython"]["seconds"] is not None


def test_evidence_is_read_from_results_files():
    ev = demo.api_evidence()
    e1 = json.loads((ROOT / "results" / "e1_detection.json").read_text())
    e5 = json.loads((ROOT / "results" / "e5_differential.json").read_text())
    assert ev["d1"]["certex_cpython"] == e1["summary"]["certex_cpython"]
    assert ev["differential"]["cases"] == e5["summary"]["cases"]


@pytest.fixture
def base_url() -> Iterator[str]:
    srv = demo.make_server(port=0, quiet=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        host, port = srv.server_address[:2]
        yield f"http://{host}:{port}"
    finally:
        srv.shutdown()
        srv.server_close()


def _post(url: str, body: bytes) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            return res.status, json.loads(res.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_http_routes(base_url):
    with urllib.request.urlopen(base_url + "/", timeout=10) as res:
        assert res.status == 200 and b"CERTEX" in res.read()
    with urllib.request.urlopen(base_url + "/api/evidence", timeout=10) as res:
        assert json.loads(res.read())["ok"]
    status, body = _post(base_url + "/api/compile", b'{"pattern": "(a|a)*$"}')
    assert status == 200 and body["degree"] == "EXP"
    status, body = _post(base_url + "/api/compile", b"[1]")
    assert status == 400 and body["error"]["kind"] == "BadRequest"
    status, body = _post(base_url + "/api/nope", b"{}")
    assert status == 404


def test_http_static_cannot_escape_web_dir(base_url):
    for path in ("/../server.py", "/%2e%2e/server.py", "/../../pyproject.toml"):
        req = urllib.request.Request(base_url + path)
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req, timeout=10)
        assert exc.value.code == 404
