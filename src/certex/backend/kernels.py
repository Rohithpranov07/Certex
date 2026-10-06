"""Matching kernels: automaton-based, never backtracking (TRD v1.1 §9).

Every kernel implements ``run(text, start_any, end_any, budget) -> (matched, steps)``:
fullmatch = (False, False), ``re.match`` = (False, True), ``re.search`` = (True, True).
Exceeding ``budget`` raises ``BudgetExceeded`` the moment ``steps > budget``.
"""

from __future__ import annotations

from collections import deque

from certex.analysis.automata import START, Glushkov
from certex.frontend.ir import ALT, CAT, EPS, LIT, PLUS, STAR, Node


class BudgetExceeded(RuntimeError):
    def __init__(self, kernel: str, steps: int, budget: int) -> None:
        super().__init__(f"{kernel}: {steps} steps exceeds budget {budget}")
        self.kernel = kernel
        self.steps = steps
        self.budget = budget


class Kernel:
    name: str = "kernel"
    supports_search: bool = True

    def run(self, text: str, start_any: bool = False, end_any: bool = False,
            budget: int | None = None) -> tuple[bool, int]:
        raise NotImplementedError


class BitParallelGlushkov(Kernel):
    """Glushkov states as bits of one Python int (bit 0 = start, bit i+1 = position i).

    One step ORs the follow masks of the set bits and ANDs the character mask (cached per
    character); steps += popcount + 1. Cost is O(n*m) bit operations, O(n) words for m <= 64.
    """

    def __init__(self, core: Node) -> None:
        g = Glushkov(core)
        self.glushkov = g
        self.m = len(g.pos)
        self.name = "shift-and" if self.m <= 64 else "bitparallel-glushkov"
        self._follow = [0] * (self.m + 1)
        for q, ps in g.follow.items():
            self._follow[q + 1] = sum(1 << (p + 1) for p in ps)   # START = -1 -> bit 0
        self._accept = sum(1 << (q + 1) for q in g.accept)
        self._cmask: dict[str, int] = {}

    def _char_mask(self, c: str) -> int:
        mask = self._cmask.get(c)
        if mask is None:
            mask = sum(1 << (i + 1) for i, cs in enumerate(self.glushkov.pos) if cs.contains(c))
            self._cmask[c] = mask
        return mask

    def run(self, text: str, start_any: bool = False, end_any: bool = False,
            budget: int | None = None) -> tuple[bool, int]:
        accept = self._accept
        follow = self._follow
        states = 1
        steps = 0
        if end_any and states & accept:
            return True, steps
        for c in text:
            if start_any:
                states |= 1
            nxt = 0
            s = states
            while s:
                low = s & -s
                nxt |= follow[low.bit_length() - 1]
                s ^= low
                steps += 1
            states = nxt & self._char_mask(c)
            steps += 1
            if budget is not None and steps > budget:
                raise BudgetExceeded(self.name, steps, budget)
            if end_any and states & accept:
                return True, steps
            if not states and not start_any:
                return False, steps
        if start_any:
            states |= 1                  # an empty match may also start at the end of the text
        return bool(states & accept), steps


class LazyDFA(BitParallelGlushkov):
    """Bit-parallel Glushkov with a cache of ``(state_mask, char) -> next_mask`` transitions.

    steps = 1 per character, plus the popcount of the state on a cache miss. The cache is
    cleared when it reaches ``max_cache`` entries, so memory stays bounded; if it thrashes the
    cost degrades to that of the underlying bit-parallel kernel, never worse.
    """

    def __init__(self, core: Node, max_cache: int = 10000) -> None:
        super().__init__(core)
        self.name = "lazy-dfa"
        self.max_cache = max_cache
        self._cache: dict[tuple[int, str], int] = {}

    def run(self, text: str, start_any: bool = False, end_any: bool = False,
            budget: int | None = None) -> tuple[bool, int]:
        accept = self._accept
        follow = self._follow
        cache = self._cache
        states = 1
        steps = 0
        if end_any and states & accept:
            return True, steps
        for c in text:
            if start_any:
                states |= 1
            key = (states, c)
            nxt = cache.get(key)
            if nxt is None:
                nxt = 0
                s = states
                while s:
                    low = s & -s
                    nxt |= follow[low.bit_length() - 1]
                    s ^= low
                    steps += 1
                nxt &= self._char_mask(c)
                if len(cache) >= self.max_cache:
                    cache.clear()
                cache[key] = nxt
            states = nxt
            steps += 1
            if budget is not None and steps > budget:
                raise BudgetExceeded(self.name, steps, budget)
            if end_any and states & accept:
                return True, steps
            if not states and not start_any:
                return False, steps
        if start_any:
            states |= 1
        return bool(states & accept), steps


def _fixed_string(n: Node) -> str | None:
    """The string matched by ``n`` if it is a fixed string of single-char literals."""
    if n.op == EPS:
        return ""
    if n.op == LIT:
        cs = n.cs
        if cs is not None and not cs.negated and len(cs.chars) == 1:
            return next(iter(cs.chars))
        return None
    if n.op == CAT:
        parts = [_fixed_string(k) for k in n.kids]
        if any(p is None for p in parts):
            return None
        return "".join(p for p in parts if p is not None)
    return None


def _strings_of(n: Node) -> list[str] | None:
    if n.op == ALT:
        out: list[str] = []
        for k in n.kids:
            sub = _strings_of(k)
            if sub is None:
                return None
            out.extend(sub)
        return out
    one = _fixed_string(n)
    return None if one is None else [one]


def literal_strings(core: Node) -> list[str] | None:
    """The words of ``core`` if it is an alternation of fixed strings (or one), else None."""
    words = _strings_of(core)
    return None if words is None else list(dict.fromkeys(words))


def word_break_words(core: Node) -> tuple[list[str], bool] | None:
    """``(words, allow_empty)`` if ``core`` is ``(w1|...|wk)+`` or ``*`` of non-empty words."""
    if core.op not in (PLUS, STAR):
        return None
    words = literal_strings(core.kids[0])
    if words is None or "" in words:
        return None
    return words, core.op == STAR


class AhoCorasick(Kernel):
    """Goto/fail automaton over a set of fixed strings: O(n + total word length)."""

    name = "aho-corasick"

    def __init__(self, words: list[str]) -> None:
        self.words = set(words)
        self.has_empty = "" in self.words
        self._goto: list[dict[str, int]] = [{}]
        out = [False]
        for w in self.words:
            node = 0
            for c in w:
                nxt = self._goto[node].get(c)
                if nxt is None:
                    nxt = len(self._goto)
                    self._goto[node][c] = nxt
                    self._goto.append({})
                    out.append(False)
                node = nxt
            out[node] = True
        self._term = list(out)               # a word ends exactly here
        self._fail = [0] * len(self._goto)
        queue = deque(self._goto[0].values())
        while queue:
            u = queue.popleft()
            for c, v in self._goto[u].items():
                f = self._fail[u]
                while f and c not in self._goto[f]:
                    f = self._fail[f]
                self._fail[v] = self._goto[f].get(c, 0)
                out[v] = out[v] or out[self._fail[v]]
                queue.append(v)
        self._out = out                      # a word ends here or at a failure ancestor

    def run(self, text: str, start_any: bool = False, end_any: bool = False,
            budget: int | None = None) -> tuple[bool, int]:
        steps = 0

        def charge(k: int) -> None:
            nonlocal steps
            steps += k
            if budget is not None and steps > budget:
                raise BudgetExceeded(self.name, steps, budget)

        if self.has_empty and (start_any or end_any or text == ""):
            return True, 0
        if not start_any:                     # a word must start at position 0: walk the trie
            node = 0
            if not text:
                return self._term[0], 0
            for c in text:
                charge(1)
                nxt = self._goto[node].get(c)
                if nxt is None:
                    return False, steps
                node = nxt
                if end_any and self._term[node]:
                    return True, steps
            return self._term[node], steps
        node = 0
        for c in text:
            charge(1)
            while node and c not in self._goto[node]:
                node = self._fail[node]
                charge(1)
            node = self._goto[node].get(c, 0)
            if end_any and self._out[node]:
                return True, steps
        return self._out[node], steps


class WordBreak(Kernel):
    """Dynamic programme over positions x distinct word lengths for ``(w1|...|wk)+`` / ``*``.

    O(n * L) dictionary lookups, L = number of distinct word lengths. Full mode only.
    (The O~(n*m^(1/3)) convolution algorithm is a P2 task, T7.3.)
    """

    name = "word-break"
    supports_search = False

    def __init__(self, words: list[str], allow_empty: bool) -> None:
        self.words = set(words)
        self.lengths = sorted({len(w) for w in words})
        self.allow_empty = allow_empty

    def run(self, text: str, start_any: bool = False, end_any: bool = False,
            budget: int | None = None) -> tuple[bool, int]:
        if start_any or end_any:
            raise NotImplementedError("word-break supports full matches only")
        n = len(text)
        if n == 0:
            return self.allow_empty, 0
        reach = [False] * (n + 1)
        reach[0] = True
        steps = 0
        for i in range(n):
            if not reach[i]:
                continue
            for ln in self.lengths:
                steps += 1
                if budget is not None and steps > budget:
                    raise BudgetExceeded(self.name, steps, budget)
                if i + ln <= n and text[i:i + ln] in self.words:
                    reach[i + ln] = True
        return reach[n], steps


__all__ = [
    "START", "AhoCorasick", "BitParallelGlushkov", "BudgetExceeded", "Kernel", "LazyDFA",
    "WordBreak", "literal_strings", "word_break_words",
]
