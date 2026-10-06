"""Rewrite ``OPT`` and ``REPEAT`` into core operators (TRD v1.1 §3, step 6)."""

from __future__ import annotations

import dataclasses

from certex.frontend.ir import ALT, CAT, OPT, REPEAT, Alt, Cat, Eps, Node, Star


def is_core(n: Node) -> bool:
    """True iff no OPT/REPEAT remains."""
    return n.op not in (OPT, REPEAT) and all(is_core(k) for k in n.kids)


def _optional(a: Node) -> Node:
    return Alt([a, Eps()])


def desugar(n: Node) -> Node:
    if not n.kids:
        return n
    kids = tuple(desugar(k) for k in n.kids)
    if n.op == OPT:
        return _optional(kids[0])
    if n.op == REPEAT:
        a = kids[0]
        copies = [a] * n.lo
        if n.hi is None:
            copies.append(Star(a))
        else:
            copies.extend(_optional(a) for _ in range(n.hi - n.lo))
        return Cat(copies)
    if n.op == CAT:
        return Cat(kids)
    if n.op == ALT:
        return Alt(kids)
    return dataclasses.replace(n, kids=kids)
