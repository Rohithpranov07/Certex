"""PCRE2 engine profile: identity until calibrated by T5.2."""

from __future__ import annotations

from certex.frontend.ir import Node


def pcre2_profile(n: Node) -> Node:
    return n
