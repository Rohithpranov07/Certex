"""CPython engine profile: replays the rewrites of ``re._parser._parse_sub``.

Source read in-session: CPython 3.14.7 ``Lib/re/_parser.py``, function ``_parse_sub``,
lines 452-510 (the same logic exists in 3.11-3.13). On every alternation, in order:

1. common-prefix factoring (lines 472-489): while every branch is non-empty and all first
   elements are equal, move that element in front of the alternation;
2. single-character merge (lines 491-507): if every remaining branch is one element that is
   a literal or a non-negated class, replace the alternation by one class.

Per TRD v1.1 §B.7 row 6 only literals and **non-negated** classes merge; ``.`` and ``[^...]``
block the merge. (sre also merges ``\\D``-style category escapes; this profile does not, as
specified.) The profile is applied bottom-up, before desugaring.
"""

from __future__ import annotations

import dataclasses

from certex.frontend.ir import ALT, CAT, EPS, LIT, Alt, Cat, CharSet, Lit, Node


def _elements(branch: Node) -> list[Node]:
    if branch.op == CAT:
        return list(branch.kids)
    if branch.op == EPS:
        return []
    return [branch]


def _rewrite_alt(branches: tuple[Node, ...]) -> Node:
    items = [_elements(b) for b in branches]
    prefix: list[Node] = []
    while all(items) and all(it[0] == items[0][0] for it in items):
        prefix.append(items[0][0])
        items = [it[1:] for it in items]

    merged: CharSet | None = CharSet()
    for it in items:
        if len(it) == 1 and it[0].op == LIT and it[0].cs is not None and not it[0].cs.negated:
            merged = merged.union(it[0].cs) if merged is not None else None
        else:
            merged = None
            break
    rest = Lit(merged) if merged is not None else Alt([Cat(it) for it in items])
    return Cat([*prefix, rest])


def cpython_profile(n: Node) -> Node:
    if not n.kids:
        return n
    kids = tuple(cpython_profile(k) for k in n.kids)
    if n.op == ALT:
        return _rewrite_alt(kids)
    if n.op == CAT:
        return Cat(kids)
    return dataclasses.replace(n, kids=kids)
