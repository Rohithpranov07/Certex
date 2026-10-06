"""Java engine profile: identity until calibrated by T5.2."""

from __future__ import annotations

from certex.frontend.ir import Node


def java_profile(n: Node) -> Node:
    return n
