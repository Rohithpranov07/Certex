"""Automata core: Glushkov position automaton (TRD v1.1 §5)."""

from __future__ import annotations

from collections.abc import Iterable

from certex.frontend.ir import (
    ALT,
    BREF,
    CAT,
    EPS,
    GROUP,
    LIT,
    PLUS,
    STAR,
    CharSet,
    Node,
)

START = -1


class Glushkov:
    """ε-free position automaton: one state per character position, plus ``START``.

    BREF is treated as ε, an over-approximation of the language that is only meaningful
    when no backreferences reach M3.
    """

    pos: list[CharSet]
    follow: dict[int, set[int]]
    first: set[int]
    last: set[int]
    nullable: bool
    accept: set[int]

    def __init__(self, core: Node) -> None:
        self.pos = []
        self.follow = {}
        self.nullable, self.first, self.last = self._build(core)
        self.follow[START] = set(self.first)
        self.accept = set(self.last)
        if self.nullable:
            self.accept.add(START)
        self._reps: list[str] | None = None

    def _build(self, n: Node) -> tuple[bool, set[int], set[int]]:
        if n.op == LIT:
            assert n.cs is not None
            p = len(self.pos)
            self.pos.append(n.cs)
            self.follow[p] = set()
            return False, {p}, {p}
        if n.op in (EPS, BREF):
            return True, set(), set()
        if n.op == GROUP:
            return self._build(n.kids[0])
        if n.op == CAT:
            nullable, first, last = True, set[int](), set[int]()
            for k in n.kids:
                kn, kf, kl = self._build(k)
                for q in last:
                    self.follow[q] |= kf
                if nullable:
                    first |= kf
                last = kl | last if kn else kl
                nullable = nullable and kn
            return nullable, first, last
        if n.op == ALT:
            nullable, first, last = False, set[int](), set[int]()
            for k in n.kids:
                kn, kf, kl = self._build(k)
                nullable = nullable or kn
                first |= kf
                last |= kl
            return nullable, first, last
        if n.op in (STAR, PLUS):
            kn, kf, kl = self._build(n.kids[0])
            for q in kl:
                self.follow[q] |= kf
            return (True if n.op == STAR else kn), kf, kl
        raise ValueError(f"not a core operator: {n.op!r}")

    def succ(self, q: int) -> set[int]:
        return self.follow[q]

    def step(self, states: Iterable[int], c: str) -> frozenset[int]:
        out: set[int] = set()
        for q in states:
            for p in self.follow[q]:
                if self.pos[p].contains(c):
                    out.add(p)
        return frozenset(out)

    def alphabet_reps(self) -> list[str]:
        """One representative per class of characters the automaton cannot tell apart."""
        if self._reps is None:
            mentioned = sorted({c for cs in self.pos for c in cs.chars})
            outside = CharSet(frozenset(mentioned), True).witness()
            assert outside is not None
            self._reps = [*mentioned, outside]
        return self._reps
