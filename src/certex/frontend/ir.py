"""Regex intermediate representation (TRD v1.1 §B.2.2).

``CharSet`` is symbolic: a finite set of characters, optionally negated, so that "any
character except ``\\n``" is exact rather than approximated over a fixed alphabet.
"""

from __future__ import annotations

import dataclasses
import string
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CharSet:
    chars: frozenset[str] = frozenset()
    negated: bool = False

    def contains(self, c: str) -> bool:
        return (c in self.chars) != self.negated

    def intersect(self, o: CharSet) -> CharSet:
        if not self.negated and not o.negated:
            return CharSet(self.chars & o.chars)
        if not self.negated:
            return CharSet(self.chars - o.chars)
        if not o.negated:
            return CharSet(o.chars - self.chars)
        return CharSet(self.chars | o.chars, True)

    def union(self, o: CharSet) -> CharSet:
        if not self.negated and not o.negated:
            return CharSet(self.chars | o.chars)
        if not self.negated:
            return CharSet(o.chars - self.chars, True)
        if not o.negated:
            return CharSet(self.chars - o.chars, True)
        return CharSet(self.chars & o.chars, True)

    def is_empty(self) -> bool:
        # A negated set excludes finitely many characters, so it is never empty.
        return not self.negated and not self.chars

    def witness(self) -> str | None:
        """Smallest readable member, or None if the set is empty."""
        if self.is_empty():
            return None
        if not self.negated:
            return min(self.chars, key=_readable_key)
        for c in _READABLE_ORDER:
            if c not in self.chars:
                return c
        i = 0
        while chr(i) in self.chars:
            i += 1
        return chr(i)


_READABLE_ORDER = (
    string.ascii_lowercase + string.digits + string.ascii_uppercase
    + "".join(chr(i) for i in range(32, 127) if not chr(i).isalnum())
)


def _readable_key(c: str) -> tuple[int, int]:
    return (0 if 32 <= ord(c) < 127 else 1, ord(c))


# Operators (string constants)
LIT, EPS, CAT, ALT, STAR, PLUS, OPT, REPEAT, GROUP, BREF = (
    "lit", "eps", "cat", "alt", "star", "plus", "opt", "repeat", "group", "bref")


@dataclass(frozen=True)
class Node:
    op: str
    kids: tuple[Node, ...] = ()
    cs: CharSet | None = None
    group: int | None = None      # capture index for GROUP and BREF
    lo: int = 0                      # REPEAT bounds
    hi: int | None = None         # None = unbounded
    span: tuple[int, int] = field(default=(0, 0), compare=False)

    def size(self) -> int:
        return 1 + sum(k.size() for k in self.kids)


DIGITS = CharSet(frozenset(string.digits))
WORD = CharSet(frozenset(string.ascii_letters + string.digits + "_"))
SPACE = CharSet(frozenset(" \t\n\r\f\v"))
ANY = CharSet(frozenset({"\n"}), True)


# ---- smart constructors -------------------------------------------------------------

def Lit(cs: CharSet, span: tuple[int, int] = (0, 0)) -> Node:
    return Node(LIT, cs=cs, span=span)


def Eps() -> Node:
    return Node(EPS)


def Cat(kids: list[Node] | tuple[Node, ...]) -> Node:
    flat: list[Node] = []
    for k in kids:
        if k.op == CAT:
            flat.extend(k.kids)
        elif k.op != EPS:
            flat.append(k)
    if not flat:
        return Eps()
    if len(flat) == 1:
        return flat[0]
    return Node(CAT, tuple(flat))


def Alt(kids: list[Node] | tuple[Node, ...]) -> Node:
    if not kids:
        raise ValueError("Alt requires at least one branch")
    if len(kids) == 1:
        return kids[0]
    return Node(ALT, tuple(kids))


def Star(k: Node) -> Node:
    return Node(STAR, (k,))


def Plus(k: Node) -> Node:
    return Node(PLUS, (k,))


def Opt(k: Node) -> Node:
    return Node(OPT, (k,))


def Repeat(k: Node, lo: int, hi: int | None) -> Node:
    return Node(REPEAT, (k,), lo=lo, hi=hi)


def Group(k: Node, index: int) -> Node:
    return Node(GROUP, (k,), group=index)


def Bref(index: int) -> Node:
    return Node(BREF, group=index)


# ---- helpers ------------------------------------------------------------------------

def strip_groups(n: Node) -> Node:
    """Remove capture groups, keeping their contents (backreferences are left alone)."""
    if n.op == GROUP:
        return strip_groups(n.kids[0])
    if not n.kids:
        return n
    kids = tuple(strip_groups(k) for k in n.kids)
    if n.op == CAT:
        return Cat(kids)
    return dataclasses.replace(n, kids=kids)


def has_bref(n: Node) -> bool:
    return n.op == BREF or any(has_bref(k) for k in n.kids)


_META = set(".^$*+?{}[]\\|()")
_NAMED = {"\n": "\\n", "\t": "\\t", "\r": "\\r", "\f": "\\f", "\v": "\\v", "\a": "\\a"}
_CLASS_META = set("\\]^-[")


def _esc_char(c: str, in_class: bool) -> str:
    if c in _NAMED:
        return _NAMED[c]
    if not (32 <= ord(c) < 127):
        return f"\\x{ord(c):02x}" if ord(c) < 256 else f"\\u{ord(c):04x}"
    if (c in _CLASS_META) if in_class else (c in _META):
        return "\\" + c
    return c


def _charset_str(cs: CharSet) -> str:
    if cs == ANY:
        return "."
    if cs.is_empty():
        return "(?!)"
    if not cs.negated and len(cs.chars) == 1:
        return _esc_char(next(iter(cs.chars)), False)
    if cs.negated and not cs.chars:
        return "[\\s\\S]"
    body = "".join(_esc_char(c, True) for c in sorted(cs.chars))
    return f"[{'^' if cs.negated else ''}{body}]"


_QUANT = (STAR, PLUS, OPT, REPEAT)


def _quant_suffix(n: Node) -> str:
    if n.op == STAR:
        return "*"
    if n.op == PLUS:
        return "+"
    if n.op == OPT:
        return "?"
    hi = "" if n.hi is None else str(n.hi)
    return f"{{{n.lo},{hi}}}"


def _pr(n: Node, ctx: int) -> str:
    """ctx: 0 = alternation branch, 1 = concatenation element, 2 = quantifier operand."""
    if n.op == LIT:
        assert n.cs is not None
        return _charset_str(n.cs)
    if n.op == EPS:
        return "(?:)" if ctx >= 2 else ""
    if n.op == BREF:
        return f"\\{n.group}"
    if n.op == GROUP:
        return "(" + _pr(n.kids[0], 0) + ")"
    if n.op == ALT:
        # a nested alternation keeps its own group, or it would flatten on re-parsing
        s = "|".join(_pr(k, 1) if k.op == ALT else _pr(k, 0) for k in n.kids)
        return f"(?:{s})" if ctx >= 1 else s
    if n.op == CAT:
        parts: list[str] = []
        for k in n.kids:
            parts.append(_pr(k, 1))
        for i in range(len(parts) - 1):
            # "\1" followed by a digit would read as a longer group number.
            if n.kids[i].op == BREF and parts[i + 1][:1].isdigit():
                parts[i] = f"(?:{parts[i]})"
        s = "".join(parts)
        return f"(?:{s})" if ctx >= 2 else s
    if n.op in _QUANT:
        kid = n.kids[0]
        inner = _pr(kid, 2)
        if kid.op in _QUANT:
            inner = f"(?:{inner})"
        return inner + _quant_suffix(n)
    raise ValueError(f"unknown operator {n.op!r}")


def to_pattern(n: Node) -> str:
    """Print the tree as Python regex syntax."""
    return _pr(n, 0)
