"""PCRE2 engine profile: identity, calibrated by replay (T5.2, ``results/e7_calibration.json``).

Calibration (PCRE2 via the ``pcre2`` 0.7.1 package) replays every D1 EXP/POLY attack:
15/24 reproduce as synthesised. The 9 that do not all have a mandatory final literal that the
attack's (empty or failing) suffix omits: ``(\\w+)*@``, ``(x+x+)+y``, ``^([a-z0-9]+[-_.]?)*
[a-z0-9]+@``, ``(a|b|ab)*c``, ``.*a.*b``, ``\\s*\\s*,``, ``\\d+\\d+x``, ``[a-z]*[a-z0-9]*!``,
``^.*=.*;$``. pcre2api(3), option PCRE2_NO_START_OPTIMIZE, documents the cause: a start-up
pre-scan of the subject that "fails immediately" without running the matcher when a required
code unit is absent. With the required literal kept in the suffix, all 24 attacks reproduce
(24/24 recorded in the calibration file); running the original attacks with ``pcre2.NOOPT``
also exposes the blow-up for 8 of the 9 at the 24-character size used.

That is a pre-check on the subject, not a rewrite of the pattern, so the narrowest rewrite
that explains the evidence is none: this profile stays the identity. Nothing here models
engine-specific tree rewrites.
"""

from __future__ import annotations

from certex.frontend.ir import Node


def pcre2_profile(n: Node) -> Node:
    return n
