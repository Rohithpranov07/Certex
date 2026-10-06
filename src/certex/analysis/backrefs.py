"""M4a backreference gate: decide the polynomial bound for patterns with backreferences."""

from __future__ import annotations

from dataclasses import dataclass

from certex.frontend.ir import BREF, GROUP, PLUS, STAR, Node


@dataclass(frozen=True)
class BrefVerdict:
    vars: tuple[int, ...]          # referenced group numbers, sorted
    k: int                         # len(vars); upper bound on active variable degree
    redefined: tuple[int, ...]     # referenced groups inside a loop or copied by {m,n}
    md_candidate: bool             # not redefined
    bound: str                     # f"|a|*n^O({k})"


def analyse_backrefs(tree: Node) -> BrefVerdict | None:
    """Analyse a desugared tree *with* groups; None if it has no backreference.

    ``md_candidate`` is a conservative syntactic stand-in for the O(|a|^5) memory-determinism
    test of Schmid (2019): a pattern is a candidate only when no referenced group can be
    redefined (it sits in no loop and is not duplicated by desugaring). The full test is future
    work (PRD FR-4.3).
    """
    referenced: set[int] = set()
    in_loop: set[int] = set()
    count: dict[int, int] = {}

    def walk(n: Node, looping: bool) -> None:
        if n.op == BREF and n.group is not None:
            referenced.add(n.group)
        if n.op == GROUP and n.group is not None:
            count[n.group] = count.get(n.group, 0) + 1
            if looping:
                in_loop.add(n.group)
        inner = looping or n.op in (STAR, PLUS)
        for k in n.kids:
            walk(k, inner)

    walk(tree, False)
    if not referenced:
        return None
    redefined = tuple(sorted(g for g in referenced if g in in_loop or count.get(g, 0) > 1))
    k = len(referenced)
    return BrefVerdict(tuple(sorted(referenced)), k, redefined, not redefined,
                       f"|a|*n^O({k})")
