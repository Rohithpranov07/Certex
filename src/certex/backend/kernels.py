"""Matching kernels: automaton-based, never backtracking (TRD v1.1 §9).

Every kernel implements ``run(text, start_any, end_any, budget) -> (matched, steps)``:
fullmatch = (False, False), ``re.match`` = (False, True), ``re.search`` = (True, True).
Exceeding ``budget`` raises ``BudgetExceeded`` the moment ``steps > budget``.
"""

from __future__ import annotations

from certex.analysis.automata import START, Glushkov
from certex.frontend.ir import Node


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


__all__ = ["START", "BitParallelGlushkov", "BudgetExceeded", "Kernel", "LazyDFA"]
