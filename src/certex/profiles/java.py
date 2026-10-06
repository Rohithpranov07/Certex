"""Java engine profile: identity, calibrated by replay (T5.2, ``results/e7_calibration.json``).

Calibration replays every D1 EXP/POLY attack on ``java.util.regex`` (OpenJDK 25.0.1; the same
harness on Corretto 11.0.24 gives 3/24): only 2/24 reproduce. Source read in-session,
``java.base/java/util/regex/Pattern.java`` from the JDK ``src.zip`` (JDK 11 lines 1806-1818 and
``Loop.match`` ~4903-4965; the same code in JDK 25): after compilation, when the pattern has no
group reference, every greedy group ``Loop`` records the start positions where it already
failed (``posIndex`` / ``localsPos``) and skips them on re-entry, which removes the exponential
re-exploration of nested group loops (e.g. ``(a+)+$``). Single-character ``Curly`` loops are not
memoised, so adjacent loops stay polynomial in principle, but at pump counts up to 2000 the
measured times are sub-millisecond JVM-warm-up noise and the log-log slope test does not
confirm them.

Loop memoisation is a matcher behaviour, not a rewrite of the pattern, so no tree rewrite is
justified by the evidence: this profile stays the identity and the 22 unconfirmed verdicts are
recorded as documented gaps rather than modelled.
"""

from __future__ import annotations

from certex.frontend.ir import Node


def java_profile(n: Node) -> Node:
    return n
