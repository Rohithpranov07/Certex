import json

import pytest

from certex.bench.extract import extract_patterns
from certex.cli import main


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("CERTEX_KEY", raising=False)
    monkeypatch.delenv("CERTEX_PROFILE", raising=False)


def test_compile_vulnerable(capsys, tmp_path):
    out = tmp_path / "cert.json"
    assert main(["compile", "(a+)+$", "-o", str(out)]) == 1
    text = capsys.readouterr().out
    assert "EXP" in text and "attack" in text and "lazy-dfa" in text and "DEVELOPMENT KEY" in text
    assert json.loads(out.read_text())["kernel"] == "lazy-dfa"


def test_compile_safe_and_kernel(capsys):
    assert main(["compile", r"^\d+$"]) == 0
    assert "LIN" in capsys.readouterr().out
    assert main(["compile", "abc|def"]) == 0
    assert "aho-corasick" in capsys.readouterr().out


def test_compile_errors(capsys):
    assert main(["compile", "a*?"]) == 2
    assert "UnsupportedSyntax: lazy/possessive quantifier at offset 2" in capsys.readouterr().err
    assert main(["compile", "(a", "--profile", "nope"]) == 2


def test_compile_json_and_profiles(capsys):
    assert main(["compile", "(0|[0-9])+$", "--profile", "none", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["profile"] == "none"
    assert main(["compile", "(0|[0-9])+$", "--profile", "cpython"]) == 0


def test_check_exit_codes(capsys, tmp_path):
    f = tmp_path / "p.txt"
    f.write_text("^\\d+$\n(a+)+$\n")
    assert main(["check", str(f)]) == 1
    out = capsys.readouterr().out
    assert out.count("EXP") == 1 and "ok (LIN)" in out
    f.write_text("^\\d+$\nabc\n")
    assert main(["check", str(f)]) == 0
    f.write_text("^\\d+$\n(?=a)\n")
    assert main(["check", str(f)]) == 2
    f.write_text("(a+)+$\n(?=a)\n")
    assert main(["check", str(f)]) == 2
    capsys.readouterr()
    f.write_text("(a+)+$\nabc\n")
    assert main(["check", str(f), "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 2 and all(d["certificate"]["schema"] == "certex/1" for d in data)


def test_match(capsys):
    assert main(["match", "a+b", "aaab"]) == 0
    assert "matched=True" in capsys.readouterr().out
    assert main(["match", "a+b", "xaab", "--mode", "search"]) == 0
    assert main(["match", "a+b", "xaab"]) == 1


def test_bench_requires_choice(capsys):
    assert main(["bench"]) == 2


def test_extract_python_and_js(tmp_path):
    py = tmp_path / "x.py"
    py.write_text('import re\nre.compile(r"(a+)+$")\nx = re.match("a.b", s)\nre.sub(p, "", s)\n')
    assert extract_patterns(py) == [(2, "(a+)+$"), (3, "a.b")]
    bad = tmp_path / "y.py"
    bad.write_text("import re\nre.search('x+y'\n")
    assert extract_patterns(bad) == [(2, "x+y")]
    js = tmp_path / "z.js"
    js.write_text('const a = new RegExp("\\\\d+x");\nconst b = /(a+)+$/g;\nlet c = 10 / 2 / 5;\n')
    pats = [p for _, p in extract_patterns(js)]
    assert r"\d+x" in pats and "(a+)+$" in pats and len(pats) == 2


def test_check_python_source(capsys, tmp_path):
    f = tmp_path / "v.py"
    f.write_text('import re\nre.match(r"^([a-z0-9]+[-_.]?)*[a-z0-9]+@", s)\n')
    assert main(["check", str(f)]) == 1
