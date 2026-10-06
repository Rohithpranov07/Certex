"""Runtime governor: enforces the safety invariant at match time (TRD v1.1 §11).

No match runs on a backtracking engine. Every match first verifies the certificate, then runs a
kernel under the certificate's step budget; on overrun it falls back to the linear bit-parallel
Glushkov kernel or rejects. It never hangs.
"""

from __future__ import annotations

from dataclasses import dataclass

from certex.backend.certificate import budget_for, verify
from certex.backend.kernels import BudgetExceeded, Kernel
from certex.compiler import Compiled

MODES = {"full": (False, False), "match": (False, True), "search": (True, True)}
OVERRUN = ("fallback", "reject")


class CertificateInvalid(RuntimeError):
    """The certificate signature does not verify, or it disagrees with the compiled kernel."""


@dataclass(frozen=True)
class MatchResult:
    matched: bool
    kernel: str
    steps: int
    fell_back: bool


def _execute(compiled: Compiled, kernel: Kernel, text: str, start_any: bool, end_any: bool,
             budget_override: int | None, on_overrun: str) -> tuple[bool, int, str, bool]:
    budget = (budget_override if budget_override is not None
              else budget_for(compiled.certificate, len(text)))
    try:
        matched, steps = kernel.run(text, start_any, end_any, budget)
        return matched, steps, kernel.name, False
    except BudgetExceeded:
        fallback = compiled.choice.fallback
        if on_overrun == "reject" or fallback is None:
            raise
        matched, steps = fallback.run(text, start_any, end_any, None)
        return matched, steps, fallback.name, True


def run(compiled: Compiled, text: str, mode: str = "full", on_overrun: str = "fallback",
        budget_override: int | None = None) -> MatchResult:
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}; valid modes: {', '.join(MODES)}")
    if on_overrun not in OVERRUN:
        raise ValueError(f"unknown on_overrun {on_overrun!r}; valid: {', '.join(OVERRUN)}")
    cert = compiled.certificate
    if not verify(cert) or cert.get("kernel") != compiled.choice.kernel.name:
        raise CertificateInvalid("certificate does not verify")

    start_any, end_any = MODES[mode]
    if compiled.parsed.anchored_start:
        start_any = False
    if compiled.parsed.anchored_end:
        end_any = False

    kernel = compiled.choice.kernel
    if (start_any or end_any) and not kernel.supports_search:
        if compiled.choice.fallback is None:
            raise CertificateInvalid(f"{kernel.name} cannot run mode {mode!r} and has no fallback")
        kernel = compiled.choice.fallback

    matched, steps, used, fell = _execute(compiled, kernel, text, start_any, end_any,
                                          budget_override, on_overrun)
    # Python's "$" also matches before a final newline, except in a full match.
    if (not matched and mode != "full" and compiled.parsed.anchored_end
            and text.endswith("\n")):
        m2, s2, used2, fell2 = _execute(compiled, kernel, text[:-1], start_any, end_any,
                                        budget_override, on_overrun)
        matched, steps, fell = m2, steps + s2, fell or fell2
        used = used2 if fell2 else used
    return MatchResult(matched, used, steps, fell)
