"""Recursive-descent parser for the v1 regex subset (TRD v1.1 §B.2.1, §B.2.3).

Grammar: ``alt := cat ('|' cat)*``, ``cat := rep*``, ``rep := atom quantifier*``.
Semantics follow Python ``re`` for the supported subset; everything outside it raises
``UnsupportedSyntax`` with the offset of the offending construct.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass

from certex.frontend.ir import (
    ANY,
    DIGITS,
    SPACE,
    WORD,
    Alt,
    Bref,
    Cat,
    CharSet,
    Eps,
    Group,
    Lit,
    Node,
    Opt,
    Plus,
    Repeat,
    Star,
)


class ParseError(ValueError):
    def __init__(self, msg: str, offset: int) -> None:
        super().__init__(f"{msg} at offset {offset}")
        self.msg = msg
        self.offset = offset


class UnsupportedSyntax(ParseError):
    """A valid regex construct outside the v1 subset."""


@dataclass(frozen=True)
class ParseResult:
    tree: Node
    ngroups: int
    anchored_start: bool
    anchored_end: bool


MAX_BOUND = 1000
_REPEAT_RE = re.compile(r"\{(\d*)(,?)(\d*)\}")
_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "f": "\f", "v": "\v", "a": "\a"}
_CLASS_ESCAPES = {
    "d": DIGITS, "D": CharSet(DIGITS.chars, True),
    "w": WORD, "W": CharSet(WORD.chars, True),
    "s": SPACE, "S": CharSet(SPACE.chars, True),
}
_HEX = set(string.hexdigits)


def _lit(c: str) -> CharSet:
    return CharSet(frozenset(c))


class _Parser:
    def __init__(self, src: str) -> None:
        self.src = src
        self.pos = 0
        self.ngroups = 0
        self.open: set[int] = set()
        self.names: set[str] = set()
        self.anchored_start = False
        self.anchored_end = False
        self.top_alt_offset: int | None = None

    # -- helpers --------------------------------------------------------------------
    def peek(self, k: int = 0) -> str:
        i = self.pos + k
        return self.src[i] if i < len(self.src) else ""

    def err(self, msg: str, offset: int | None = None) -> ParseError:
        return ParseError(msg, self.pos if offset is None else offset)

    def unsupported(self, msg: str, offset: int | None = None) -> UnsupportedSyntax:
        return UnsupportedSyntax(msg, self.pos if offset is None else offset)

    # -- grammar --------------------------------------------------------------------
    def parse(self) -> ParseResult:
        tree = self.parse_alt(0)
        if self.pos < len(self.src):
            raise self.err("unbalanced parenthesis")
        if self.top_alt_offset is not None and (self.anchored_start or self.anchored_end):
            raise self.unsupported("anchor inside a top-level alternation", self.top_alt_offset)
        return ParseResult(tree, self.ngroups, self.anchored_start, self.anchored_end)

    def parse_alt(self, depth: int) -> Node:
        branches = [self.parse_cat(depth)]
        while self.peek() == "|":
            if depth == 0 and self.top_alt_offset is None:
                self.top_alt_offset = self.pos
            self.pos += 1
            branches.append(self.parse_cat(depth))
        return Alt(branches)

    def parse_cat(self, depth: int) -> Node:
        items: list[Node] = []
        while self.pos < len(self.src) and self.peek() not in "|)":
            items.append(self.parse_rep(depth))
        if self.peek() == ")" and depth == 0:
            raise self.err("unbalanced parenthesis")
        return Cat(items)

    def repeat_token(self) -> tuple[int, int | None, int] | None:
        """Match a ``{m,n}`` token at the cursor: (lo, hi, length), or None for a literal."""
        m = _REPEAT_RE.match(self.src, self.pos)
        if m is None:
            return None
        lo_s, comma, hi_s = m.groups()
        if not lo_s and not hi_s:      # "{}" and "{,}" are literals
            return None
        lo = int(lo_s) if lo_s else 0
        if not comma:
            hi: int | None = lo
        else:
            hi = int(hi_s) if hi_s else None
        if lo > MAX_BOUND or (hi is not None and hi > MAX_BOUND):
            raise self.unsupported(f"repeat bound above {MAX_BOUND}")
        if hi is not None and hi < lo:
            raise self.err("min repeat greater than max repeat")
        return lo, hi, m.end() - m.start()

    def parse_rep(self, depth: int) -> Node:
        node = self.parse_atom(depth)
        quantified = False
        while True:
            c = self.peek()
            start = self.pos
            if c in ("*", "+", "?"):
                self.pos += 1
                node = {"*": Star, "+": Plus, "?": Opt}[c](node)
            elif c == "{" and (tok := self.repeat_token()) is not None:
                lo, hi, length = tok
                self.pos += length
                node = Repeat(node, lo, hi)
            else:
                return node
            if quantified:
                raise self.err("multiple repeat", start)
            quantified = True
            if self.peek() in ("?", "+"):
                raise self.unsupported("lazy/possessive quantifier")

    def parse_atom(self, depth: int) -> Node:
        c = self.peek()
        start = self.pos
        if c in ("*", "+", "?") or (c == "{" and self.repeat_token() is not None):
            raise self.err("nothing to repeat")
        if c == "(":
            return self.parse_group(depth)
        if c == "[":
            return self.parse_class()
        if c == "\\":
            return self.parse_escape()
        self.pos += 1
        if c == ".":
            return Lit(ANY, (start, self.pos))
        if c == "^":
            if start != 0:
                raise self.unsupported("anchor not at pattern boundary", start)
            self.anchored_start = True
            return self.after_anchor()
        if c == "$":
            if start != len(self.src) - 1:
                raise self.unsupported("anchor not at pattern boundary", start)
            self.anchored_end = True
            return self.after_anchor()
        return Lit(_lit(c), (start, self.pos))

    def after_anchor(self) -> Node:
        if self.peek() in ("*", "+", "?") or (self.peek() == "{" and self.repeat_token()):
            raise self.err("nothing to repeat")
        return Eps()

    def parse_group(self, depth: int) -> Node:
        start = self.pos
        self.pos += 1                                   # '('
        capture = True
        if self.peek() == "?":
            nxt = self.peek(1)
            if nxt == ":":
                capture = False
                self.pos += 2
            elif nxt == "P" and self.peek(2) == "<":
                end = self.src.find(">", self.pos)
                if end < 0:
                    raise self.err("missing >, unterminated name", self.pos + 3)
                name = self.src[self.pos + 3:end]
                if not (name.isascii() and name.isidentifier()):
                    raise self.err("bad character in group name", self.pos + 3)
                if name in self.names:
                    raise self.err("redefinition of group name", self.pos + 3)
                self.names.add(name)
                self.pos = end + 1
            elif nxt == "P" and self.peek(2) == "=":
                raise self.unsupported("named backreference (?P=name)", start)
            else:
                raise self.unsupported("unsupported group extension (?" + nxt, start)
        idx = 0
        if capture:
            self.ngroups += 1
            idx = self.ngroups
            self.open.add(idx)
        inner = self.parse_alt(depth + 1)
        if self.peek() != ")":
            raise self.err("missing ), unterminated subpattern", start)
        self.pos += 1
        if capture:
            self.open.discard(idx)
            return Group(inner, idx)
        return inner

    def parse_escape(self) -> Node:
        start = self.pos
        self.pos += 1                                   # '\'
        c = self.peek()
        if not c:
            raise self.err("bad escape (end of pattern)", start)
        self.pos += 1
        if c in "123456789":
            num = int(c)
            while self.peek().isdigit() and num * 10 + int(self.peek()) <= min(
                    self.ngroups, 99):
                num = num * 10 + int(self.peek())
                self.pos += 1
            if num > self.ngroups:
                raise self.err("invalid group reference", start)
            if num in self.open:
                raise self.err("cannot refer to an open group", start)
            return Bref(num)
        cs = self.escape_charset(c, start)
        return Lit(cs, (start, self.pos))

    def escape_charset(self, c: str, start: int) -> CharSet:
        """Charset for the escape letter ``c`` (cursor is already past it)."""
        if c in _CLASS_ESCAPES:
            return _CLASS_ESCAPES[c]
        if c in _SIMPLE_ESCAPES:
            return _lit(_SIMPLE_ESCAPES[c])
        if c == "x":
            digits = self.src[self.pos:self.pos + 2]
            if len(digits) != 2 or not set(digits) <= _HEX:
                raise self.err("incomplete escape \\x", start)
            self.pos += 2
            return _lit(chr(int(digits, 16)))
        if c.isascii() and c.isalnum():
            raise self.unsupported(f"unsupported escape \\{c}", start)
        return _lit(c)

    def parse_class(self) -> Node:
        start = self.pos
        self.pos += 1                                   # '['
        negate = self.peek() == "^"
        if negate:
            self.pos += 1
        acc = CharSet()
        first = True
        while True:
            c = self.peek()
            if not c:
                raise self.err("unterminated character set", start)
            if c == "]" and not first:
                self.pos += 1
                break
            first = False
            lo = self.class_item()
            if isinstance(lo, CharSet):                 # \d \w \s ...
                acc = acc.union(lo)
                continue
            if self.peek() == "-" and self.peek(1) not in ("]", ""):
                self.pos += 1
                dash = self.pos - 1
                hi = self.class_item()
                if isinstance(hi, CharSet):
                    raise self.err("bad character range", dash)
                if ord(hi) < ord(lo):
                    raise self.err("bad character range", dash)
                acc = acc.union(CharSet(frozenset(chr(i) for i in range(ord(lo), ord(hi) + 1))))
            else:
                acc = acc.union(_lit(lo))
        if negate:
            acc = CharSet(acc.chars, not acc.negated)
        return Lit(acc, (start, self.pos))

    def class_item(self) -> str | CharSet:
        c = self.peek()
        start = self.pos
        self.pos += 1
        if c != "\\":
            return c
        e = self.peek()
        if not e:
            raise self.err("bad escape (end of pattern)", start)
        self.pos += 1
        if e.isdigit():
            raise self.unsupported(f"unsupported escape \\{e} in character set", start)
        cs = self.escape_charset(e, start)
        if len(cs.chars) == 1 and not cs.negated and e not in _CLASS_ESCAPES:
            return next(iter(cs.chars))
        return cs


def parse(src: str) -> ParseResult:
    return _Parser(src).parse()

