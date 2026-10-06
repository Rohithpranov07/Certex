"""M4b backend synthesiser: the six-row kernel decision table (TRD v1.1 §B.3)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from certex.analysis.ambiguity import LIN, AmbVerdict
from certex.analysis.backrefs import BrefVerdict
from certex.analysis.types import EASY, WORDBREAK, TypeVerdict
from certex.backend.kernels import (
    AhoCorasick,
    BitParallelGlushkov,
    Kernel,
    LazyDFA,
    PikeVM,
    WordBreak,
    literal_strings,
    word_break_words,
)
from certex.frontend.ir import Node


@dataclass
class Choice:
    kernel: Kernel
    fallback: Kernel | None
    bound: str
    budget: dict[str, Any]      # {"c": int, "m": int, "power": int}
    rule: str                   # names the decision-table row


def budget_c() -> int:
    return int(os.environ.get("CERTEX_BUDGET_C", "8"))


def synthesise(tree: Node, core: Node, tv: TypeVerdict, av: AmbVerdict | None,
               bv: BrefVerdict | None) -> Choice:
    """Pick the kernel, fallback and budget; rows are evaluated top to bottom."""
    c = budget_c()
    if bv is not None:                                                            # row 1
        pike = PikeVM(tree, bv.vars)
        return Choice(pike, None, bv.bound, {"c": c, "m": pike.m, "power": 2 * bv.k + 1},
                      "backreferences -> Pike VM (MFA-k)")
    fallback = BitParallelGlushkov(core)
    budget = {"c": c, "m": fallback.m, "power": 1}
    if tv.cls == EASY:
        words = literal_strings(core)
        if words is not None:                                                     # row 2
            return Choice(AhoCorasick(words), fallback, "O(n+m)", budget,
                          "EASY dictionary -> Aho-Corasick")
    if tv.cls == WORDBREAK:
        wb = word_break_words(core)
        if wb is not None:                                                        # row 3
            return Choice(WordBreak(*wb), fallback, "O(n*L), L = distinct word lengths",
                          budget, "WORDBREAK -> word-break DP")
    if tv.cls == EASY:                                                            # row 4
        return Choice(LazyDFA(core), fallback, "O(n) amortised", budget,
                      "EASY -> near-linear lazy DFA")
    if av is not None and av.degree == LIN and fallback.m <= 64:                  # row 5
        return Choice(fallback, fallback, "O(n) (one machine word)", budget,
                      "LIN, m <= 64 -> shift-and")
    return Choice(LazyDFA(core), fallback, "O(n*m) worst case", budget,         # row 6
                  "default -> lazy DFA with bit-parallel fallback")
