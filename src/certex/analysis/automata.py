"""Automata core: Glushkov position automaton (TRD v1.1 §5)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from itertools import pairwise

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


class PathLimitExceeded(RuntimeError):
    """More simple ε-paths from one state than the configured cap."""


class Thompson:
    """ε-NFA built exactly as a backtracking engine branches (paper §III-C).

    STAR: split to body or exit; the body end loops to the body start and exits.
    PLUS: the same without the bypass. BREF is ε (language over-approximation).
    """

    eps: dict[int, list[int]]
    char: dict[int, tuple[CharSet, int]]
    start: int
    end: int

    def __init__(self, core: Node) -> None:
        self.eps = {}
        self.char = {}
        self._n = 0
        self.start, self.end = self._build(core)

    def _new(self) -> int:
        s = self._n
        self._n += 1
        self.eps[s] = []
        return s

    def _build(self, n: Node) -> tuple[int, int]:
        if n.op == LIT:
            assert n.cs is not None
            s, e = self._new(), self._new()
            self.char[s] = (n.cs, e)
            return s, e
        if n.op in (EPS, BREF):
            s, e = self._new(), self._new()
            self.eps[s].append(e)
            return s, e
        if n.op == GROUP:
            return self._build(n.kids[0])
        if n.op == CAT:
            frags = [self._build(k) for k in n.kids]
            for (_, e1), (s2, _) in pairwise(frags):
                self.eps[e1].append(s2)
            return frags[0][0], frags[-1][1]
        if n.op == ALT:
            s, e = self._new(), self._new()
            for k in n.kids:
                ks, ke = self._build(k)
                self.eps[s].append(ks)
                self.eps[ke].append(e)
            return s, e
        if n.op in (STAR, PLUS):
            s, e = self._new(), self._new()
            bs, be = self._build(n.kids[0])
            self.eps[s].append(bs)
            if n.op == STAR:
                self.eps[s].append(e)
            self.eps[be].append(bs)
            self.eps[be].append(e)
            return s, e
        raise ValueError(f"not a core operator: {n.op!r}")


@dataclass
class PathPreservingNFA:
    start: int
    edges: dict[int, list[tuple[CharSet, int, tuple[object, ...]]]]   # (charset, target, path_id)
    accept: set[int]


def path_preserving(t: Thompson, max_paths: int = 5000) -> PathPreservingNFA:
    """ε-eliminate ``t`` per simple ε-path, so distinct backtracking paths stay distinct.

    Sources are the start state and every char-transition target. Each simple ε-path from a
    source that ends at a char state becomes its own edge; one that reaches ``t.end`` makes
    the source accepting.
    """
    sources = {t.start} | {target for _, target in t.char.values()}
    edges: dict[int, list[tuple[CharSet, int, tuple[object, ...]]]] = {}
    accept: set[int] = set()
    for src in sorted(sources):
        out: list[tuple[CharSet, int, tuple[object, ...]]] = []
        leaves = 0
        stack: list[tuple[int, tuple[int, ...]]] = [(src, (src,))]
        while stack:
            u, path = stack.pop()
            if u in t.char:
                cs, target = t.char[u]
                out.append((cs, target, (u, path)))
                leaves += 1
            elif u == t.end:
                accept.add(src)
                leaves += 1
            else:
                nexts = [v for v in t.eps[u] if v not in path]
                if len(nexts) < len(t.eps[u]):
                    leaves += 1            # a blocked (non-simple) branch still costs work
                for v in reversed(nexts):
                    stack.append((v, (*path, v)))
            if leaves > max_paths:
                raise PathLimitExceeded(f"more than {max_paths} ε-paths from state {src}")
        edges[src] = out
    return PathPreservingNFA(t.start, edges, accept)
