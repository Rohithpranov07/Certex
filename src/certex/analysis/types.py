"""M2 fine-grained type inference (paper §III-B, Algorithm 2).

A homogeneous pattern has exactly one operator per tree depth; reading them top-down gives its
*type* (``o`` = concatenation). The type is normalised with the three Bringmann-Gronlund-Larsen
rules and classified by their dichotomy: EASY (near-linear), WORDBREAK, or HARD.
"""

from __future__ import annotations

from dataclasses import dataclass

from certex.frontend.ir import ALT, CAT, GROUP, PLUS, STAR, Node

EASY, WORDBREAK, HARD, GENERAL = "EASY", "WORDBREAK", "HARD", "GENERAL"
BOUNDS = {EASY: "O~(n)+O(m)", WORDBREAK: "O~(n*m^(1/3)+m)",
          HARD: "(nm)^(1-o(1)) under SETH", GENERAL: "O(nm)"}


@dataclass(frozen=True)
class TypeVerdict:
    homogeneous: bool
    raw_type: str | None         # operator string, 'o' = concatenation, e.g. "o+|o"
    normalised: str | None       # after the three Bringmann et al. rules
    cls: str                     # EASY | WORDBREAK | HARD | GENERAL
    bound: str
    hard_core: str | None = None


_SYMBOL = {CAT: "o", ALT: "|", STAR: "*", PLUS: "+"}


def levels(n: Node) -> list[set[str]]:
    """Operator set per depth (root = depth 0); leaves contribute nothing."""
    out: list[set[str]] = []
    frontier = [n]
    while frontier:
        nxt: list[Node] = []
        ops: set[str] = set()
        for node in frontier:
            if node.op == GROUP:
                nxt.extend(node.kids)
                continue
            if node.op in _SYMBOL:
                ops.add(_SYMBOL[node.op])
                nxt.extend(node.kids)
        if ops:
            out.append(ops)
        frontier = nxt
    return out


def raw_type(n: Node) -> str | None:
    """The operator string if ``n`` is homogeneous, else None."""
    lv = levels(n)
    if any(len(s) != 1 for s in lv):
        return None
    return "".join(next(iter(s)) for s in lv)


def simplify(t: str) -> str:
    """Apply the three normalisation rules to a fixpoint."""
    while True:
        prev = t
        # rule 1: collapse repeated operators
        out: list[str] = []
        for ch in t:
            if not out or out[-1] != ch:
                out.append(ch)
        t = "".join(out)
        # rule 2: +|+ -> +| (first occurrence)
        t = t.replace("+|+", "+|", 1)
        # rule 3: a * preceded only by + or | becomes +
        for i, ch in enumerate(t):
            if ch == "*" and set(t[:i]) <= {"+", "|"}:
                t = t[:i] + "+" + t[i + 1:]
                break
        if t == prev:
            return t


def _is_subsequence(t: str, big: str) -> bool:
    it = iter(big)
    return all(ch in it for ch in t)


def classify_type(t: str) -> str:
    if _is_subsequence(t, "|+o+") or _is_subsequence(t, "|+o|"):
        return EASY
    if t == "+|o":
        return WORDBREAK
    return HARD


def _hard_core(n: Node) -> str | None:
    """Longest simplified HARD type among maximal homogeneous subtrees of ``n``."""
    t = raw_type(n)
    if t is not None:
        s = simplify(t)
        return s if classify_type(s) == HARD else None
    best: str | None = None
    for k in n.kids:
        c = _hard_core(k)
        if c is not None and (best is None or len(c) > len(best)):
            best = c
    return best


def infer_type(core: Node) -> TypeVerdict:
    t = raw_type(core)
    if t is None:
        return TypeVerdict(False, None, None, GENERAL, BOUNDS[GENERAL], _hard_core(core))
    s = simplify(t)
    cls = classify_type(s)
    return TypeVerdict(True, t, s, cls, BOUNDS[cls])
