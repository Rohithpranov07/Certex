"""Extract regex patterns from files for ``certex check``.

* Plain files (any extension other than ``.py`` / ``.js``): one pattern per non-blank line.
* ``.py``: the ``ast`` module finds calls ``re.compile|match|search|fullmatch|findall|sub(...)``
  whose first argument is a string literal. If the file does not parse, this regex is used
  instead (``PY_CALL_RE``).
* ``.js``: string literals passed to ``new RegExp(...)`` (``JS_NEW_REGEXP_RE``, with JS string
  escapes resolved) and ``/.../flags`` literals (``JS_LITERAL_RE``, a heuristic that requires a
  preceding ``= ( : , ; ! & | ? { } [`` , ``return`` or line start). Flags are ignored.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

PY_FUNCS = ("compile", "match", "search", "fullmatch", "findall", "sub")
PY_CALL_RE = re.compile(
    r"""\bre\.(?:compile|match|search|fullmatch|findall|sub)\(\s*[rRuU]*"""
    r"""(?:'''(?P<t1>.*?)'''|\"\"\"(?P<t2>.*?)\"\"\"|'(?P<s1>(?:\\.|[^'\\\n])*)'"""
    r"""|"(?P<s2>(?:\\.|[^"\\\n])*)")""", re.DOTALL)
JS_NEW_REGEXP_RE = re.compile(
    r"""new\s+RegExp\(\s*(?P<q>["'`])(?P<body>(?:\\.|(?!(?P=q)).)*)(?P=q)""")
JS_LITERAL_RE = re.compile(
    r"""(?:(?<=[=(:,;!&|?{}\[])|(?<=return)|^)\s*"""
    r"""/(?P<body>(?![*/])(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n\[])+)/[gimsuyd]*""",
    re.MULTILINE)
_JS_ESC = {"n": "\n", "t": "\t", "r": "\r", "f": "\f", "v": "\v", "0": "\0"}


def _js_unescape(s: str) -> str:
    return re.sub(r"\\(.)", lambda m: _JS_ESC.get(m.group(1), m.group(1)), s)


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _from_python(text: str) -> list[tuple[int, str]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        out = []
        for m in PY_CALL_RE.finditer(text):
            body = next(g for g in m.groups() if g is not None)
            out.append((_line_of(text, m.start()), body))
        return out
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "re"
                and node.func.attr in PY_FUNCS and node.args
                and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            found.append((node.lineno, node.args[0].value))
    return sorted(found)


def _from_js(text: str) -> list[tuple[int, str]]:
    found = [(_line_of(text, m.start()), _js_unescape(m.group("body")))
             for m in JS_NEW_REGEXP_RE.finditer(text)]
    found += [(_line_of(text, m.start("body")), m.group("body"))
              for m in JS_LITERAL_RE.finditer(text)]
    return sorted(found)


def extract_patterns(path: str | Path) -> list[tuple[int, str]]:
    """``(line number, pattern)`` pairs found in ``path``."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix == ".py":
        return _from_python(text)
    if p.suffix == ".js":
        return _from_js(text)
    return [(i, line) for i, line in enumerate(text.splitlines(), 1) if line.strip()]
