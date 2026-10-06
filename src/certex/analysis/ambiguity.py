"""M3 ambiguity analysis (paper Algorithm 3): EDA / IDA detection with witnesses.

Works on the path-preserving NFA (distinct backtracking paths are distinct edges).

* EDA (exponential): a state ``q`` with two distinct paths ``q -> q`` on one word, found as a
  cycle through the diagonal pair ``(q, q)`` that uses a *different* pair edge.
* IDA (polynomial): states ``p != q`` with paths ``p -> p``, ``p -> q``, ``q -> q`` on one
  non-empty word, found as triple-product reachability ``(p, p, q) ->w (p, q, q)``. This
  already implies both cycles (TRD v1.1 §B.7 row 7).

All searches share one wall-clock deadline; expiry yields ``UNKNOWN``, never a hang.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass

from certex.analysis.automata import (
    START,
    Glushkov,
    PathLimitExceeded,
    PathPreservingNFA,
    Thompson,
    path_preserving,
)
from certex.frontend.ir import CharSet, Node

EXP, POLY, LIN, UNKNOWN = "EXP", "POLY", "LIN", "UNKNOWN"


@dataclass(frozen=True)
class Attack:
    prefix: str
    pump: str
    suffix: str

    def build(self, k: int) -> str:
        return self.prefix + self.pump * k + self.suffix


@dataclass(frozen=True)
class AmbVerdict:
    degree: str                     # EXP | POLY | LIN | UNKNOWN
    attack: Attack | None = None
    unexploitable: bool = False     # ambiguous, but no rejecting suffix exists
    reason: str = ""


class _Timeout(Exception):
    pass


class _Clock:
    def __init__(self, timeout: float) -> None:
        self.end = time.monotonic() + timeout
        self.n = 0

    def tick(self) -> None:
        self.n += 1
        if self.n & 255 == 0 and time.monotonic() > self.end:
            raise _Timeout


Pair = tuple[int, int]
PairEdge = tuple[str, Pair, bool]      # (witness char, target, edges differ?)


class _PairGraph:
    """Reachable part of the product of the NFA with itself, from ``(start, start)``."""

    def __init__(self, nfa: PathPreservingNFA, clock: _Clock) -> None:
        self.nfa = nfa
        self.start: Pair = (nfa.start, nfa.start)
        self.adj: dict[Pair, list[PairEdge]] = {}
        self.pred: dict[Pair, tuple[Pair, str] | None] = {self.start: None}
        cache: dict[tuple[CharSet, CharSet], str | None] = {}
        queue = deque([self.start])
        while queue:
            node = queue.popleft()
            p, q = node
            out: list[PairEdge] = []
            for i, (cs1, t1, _) in enumerate(nfa.edges[p]):
                for j, (cs2, t2, _) in enumerate(nfa.edges[q]):
                    clock.tick()
                    key = (cs1, cs2)
                    if key not in cache:
                        cache[key] = cs1.intersect(cs2).witness()
                    w = cache[key]
                    if w is None:
                        continue
                    nxt = (t1, t2)
                    out.append((w, nxt, not (p == q and i == j)))
                    if nxt not in self.pred:
                        self.pred[nxt] = (node, w)
                        queue.append(nxt)
            self.adj[node] = out

    def prefix_to(self, node: Pair) -> str:
        word: list[str] = []
        cur = self.pred[node]
        while cur is not None:
            node, w = cur
            word.append(w)
            cur = self.pred[node]
        return "".join(reversed(word))


def _eda_candidates(g: _PairGraph, clock: _Clock) -> Iterator[tuple[str, str]]:
    """Yield ``(prefix, pump)`` for every EDA witness, shortest pumps first per diagonal."""
    radj: dict[Pair, list[tuple[str, Pair]]] = {}
    for node, outs in g.adj.items():
        for w, nxt, _ in outs:
            radj.setdefault(nxt, []).append((w, node))
    seen: set[tuple[str, str]] = set()
    for diag in sorted(n for n in g.adj if n[0] == n[1]):
        # backward BFS: for each node, the word that leads from it back to diag
        back: dict[Pair, tuple[str, Pair] | None] = {diag: None}
        queue = deque([diag])
        while queue:
            v = queue.popleft()
            for w, u in radj.get(v, ()):
                clock.tick()
                if u not in back:
                    back[u] = (w, v)
                    queue.append(u)
        if not any(v in back for _, v, _ in g.adj[diag]):
            continue                       # (q, q) lies on no cycle
        fwd: dict[Pair, tuple[Pair, str] | None] = {diag: None}
        order = deque([diag])
        prefix = g.prefix_to(diag)
        while order:
            u = order.popleft()
            for w, v, different in g.adj[u]:
                clock.tick()
                if different and v in back:
                    pump = _word_fwd(fwd, u) + w + _word_back(back, v)
                    if (prefix, pump) not in seen:
                        seen.add((prefix, pump))
                        yield prefix, pump
                if v not in fwd:
                    fwd[v] = (u, w)
                    order.append(v)


def _word_fwd(fwd: dict[Pair, tuple[Pair, str] | None], node: Pair) -> str:
    word: list[str] = []
    cur = fwd[node]
    while cur is not None:
        node, w = cur
        word.append(w)
        cur = fwd[node]
    return "".join(reversed(word))


def _word_back(back: dict[Pair, tuple[str, Pair] | None], node: Pair) -> str:
    word: list[str] = []
    cur = back[node]
    while cur is not None:
        w, node = cur
        word.append(w)
        cur = back[node]
    return "".join(word)


def _sccs(nfa: PathPreservingNFA) -> dict[int, int]:
    """Strongly connected component id per NFA state (iterative Tarjan)."""
    succ = {s: [t for _, t, _ in es] for s, es in nfa.edges.items()}
    index: dict[int, int] = {}
    low: dict[int, int] = {}
    on: set[int] = set()
    stack: list[int] = []
    comp: dict[int, int] = {}
    counter = 0
    ncomp = 0
    for root, root_succ in succ.items():
        if root in index:
            continue
        work = [(root, iter(root_succ))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on.add(root)
        while work:
            v, it = work[-1]
            advanced = False
            for w in it:
                if w not in index:
                    index[w] = low[w] = counter
                    counter += 1
                    stack.append(w)
                    on.add(w)
                    work.append((w, iter(succ[w])))
                    advanced = True
                    break
                if w in on:
                    low[v] = min(low[v], index[w])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[v])
            if low[v] == index[v]:
                while True:
                    w = stack.pop()
                    on.discard(w)
                    comp[w] = ncomp
                    if w == v:
                        break
                ncomp += 1
    return comp


def _reach(adj: dict[int, list[int]], src: int) -> set[int]:
    seen = {src}
    stack = [src]
    while stack:
        for t in adj.get(stack.pop(), ()):
            if t not in seen:
                seen.add(t)
                stack.append(t)
    return seen


def _ida_candidates(g: _PairGraph, clock: _Clock) -> Iterator[tuple[str, str]]:
    """Yield ``(prefix, pump)`` for IDA witnesses via the triple product."""
    nfa = g.nfa
    comp = _sccs(nfa)
    succ = {s: [t for _, t, _ in es] for s, es in nfa.edges.items()}
    pred_g: dict[int, list[int]] = {}
    for s, ts in succ.items():
        for t in ts:
            pred_g.setdefault(t, []).append(s)
    size: dict[int, int] = {}
    for c in comp.values():
        size[c] = size.get(c, 0) + 1
    cyclic = {s for s in succ if size[comp[s]] > 1 or s in succ[s]}
    cyclic &= {n[0] for n in g.adj if n[0] == n[1]}      # reachable from start
    fwd_reach = {p: _reach(succ, p) for p in cyclic}
    cache: dict[tuple[CharSet, CharSet, CharSet], str | None] = {}
    for p in sorted(cyclic):
        for q in sorted(cyclic):
            if p == q or q not in fwd_reach[p]:
                continue
            mid = fwd_reach[p] & _reach(pred_g, q)
            goal = (p, q, q)
            start = (p, p, q)
            parent: dict[tuple[int, int, int], tuple[tuple[int, int, int], str] | None] = {
                start: None}
            queue = deque([start])
            found = False
            while queue and not found:
                node = queue.popleft()
                x, y, z = node
                for cs1, t1, _ in nfa.edges[x]:
                    if comp[t1] != comp[p]:
                        continue
                    for cs2, t2, _ in nfa.edges[y]:
                        if t2 not in mid:
                            continue
                        c12 = cs1.intersect(cs2)
                        if c12.is_empty():
                            continue
                        for cs3, t3, _ in nfa.edges[z]:
                            clock.tick()
                            if comp[t3] != comp[q]:
                                continue
                            key = (cs1, cs2, cs3)
                            if key not in cache:
                                cache[key] = c12.intersect(cs3).witness()
                            w = cache[key]
                            if w is None:
                                continue
                            nxt = (t1, t2, t3)
                            if nxt in parent:
                                continue
                            parent[nxt] = (node, w)
                            if nxt == goal:
                                found = True
                                break
                            queue.append(nxt)
                        if found:
                            break
                    if found:
                        break
            if found:
                word: list[str] = []
                cur = parent[goal]
                while cur is not None:
                    prev, w = cur
                    word.append(w)
                    cur = parent[prev]
                yield g.prefix_to((p, p)), "".join(reversed(word))


def reject_suffix(g: Glushkov, word: str, cap: int = 20000) -> str | None:
    """Shortest suffix ``s`` such that ``word + s`` is rejected, or None within ``cap`` subsets."""
    states: frozenset[int] = frozenset({START})
    for c in word:
        states = g.step(states, c)
    if not states & g.accept:
        return ""
    seen = {states}
    queue: deque[tuple[frozenset[int], str]] = deque([(states, "")])
    reps = g.alphabet_reps()
    while queue:
        cur, suffix = queue.popleft()
        for c in reps:
            nxt = g.step(cur, c)
            if nxt in seen:
                continue
            if not nxt & g.accept:
                return suffix + c
            if len(seen) >= cap:
                return None
            seen.add(nxt)
            queue.append((nxt, suffix + c))
    return None


def analyse_ambiguity(core: Node, timeout: float = 2.0, pump_reps: int = 8) -> AmbVerdict:
    """Classify ``core`` as EXP / POLY / LIN / UNKNOWN with an attack when exploitable."""
    clock = _Clock(timeout)
    try:
        nfa = path_preserving(Thompson(core))
        g = _PairGraph(nfa, clock)
        glushkov = Glushkov(core)
        ambiguous = False
        for degree, candidates in ((EXP, _eda_candidates(g, clock)),
                                   (POLY, _ida_candidates(g, clock))):
            for prefix, pump in candidates:
                ambiguous = True
                suffix = reject_suffix(glushkov, prefix + pump * pump_reps)
                clock.tick()
                if suffix is not None:
                    return AmbVerdict(degree, Attack(prefix, pump, suffix))
        if ambiguous:
            return AmbVerdict(LIN, unexploitable=True,
                              reason="ambiguous but no rejecting suffix")
        return AmbVerdict(LIN)
    except PathLimitExceeded as e:
        return AmbVerdict(UNKNOWN, reason=f"path limit: {e}")
    except _Timeout:
        return AmbVerdict(UNKNOWN, reason=f"timeout after {timeout}s")
