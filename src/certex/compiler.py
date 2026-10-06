"""The compilation pipeline: parse -> profile -> desugar -> strip groups -> M2/M4a/M3 -> M4b -> sign."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from certex.analysis.ambiguity import EXP, POLY, AmbVerdict, analyse_ambiguity
from certex.analysis.backrefs import BrefVerdict, analyse_backrefs
from certex.analysis.types import TypeVerdict, infer_type
from certex.backend.certificate import pattern_hash, sign
from certex.backend.synth import Choice, synthesise
from certex.frontend.desugar import desugar
from certex.frontend.ir import Node, strip_groups
from certex.frontend.parser import ParseResult, parse
from certex.profiles import get_profile


@dataclass
class Compiled:
    pattern: str
    profile: str
    parsed: ParseResult
    tree: Node                       # desugared, groups kept
    core: Node                       # desugared, groups stripped
    types: TypeVerdict
    ambiguity: AmbVerdict | None
    backrefs: BrefVerdict | None
    choice: Choice
    certificate: dict[str, Any]

    @property
    def degree(self) -> str:
        """EXP | POLY | LIN | UNKNOWN, or "N/A" when backreferences make M3 inapplicable."""
        if self.ambiguity is None:
            return "N/A"
        return self.ambiguity.degree

    @property
    def vulnerable(self) -> bool:
        return self.degree in (EXP, POLY)


def _certificate_body(c: str, profile: str, core: Node, tv: TypeVerdict,
                      av: AmbVerdict | None, bv: BrefVerdict | None, choice: Choice,
                      ) -> dict[str, Any]:
    ambiguity: dict[str, Any] | None = None
    if av is not None:
        attack = None
        if av.attack is not None:
            attack = {"prefix": av.attack.prefix, "pump": av.attack.pump,
                      "suffix": av.attack.suffix}
        ambiguity = {"degree": av.degree, "unexploitable": av.unexploitable,
                     "reason": av.reason, "attack": attack}
    backrefs: dict[str, Any] | None = None
    if bv is not None:
        backrefs = {"vars": list(bv.vars), "k": bv.k, "redefined": list(bv.redefined),
                    "md_candidate": bv.md_candidate, "bound": bv.bound}
    return {
        "pattern_sha256": pattern_hash(c),
        "profile": profile,
        "m": core.size(),
        "type": {"homogeneous": tv.homogeneous, "raw_type": tv.raw_type,
                 "normalised": tv.normalised, "cls": tv.cls, "bound": tv.bound,
                 "hard_core": tv.hard_core},
        "ambiguity": ambiguity,
        "backrefs": backrefs,
        "kernel": choice.kernel.name,
        "fallback": choice.fallback.name if choice.fallback else None,
        "rule": choice.rule,
        "bound": choice.bound,
        "budget": dict(choice.budget),
    }


def compile(pattern: str, profile: str | None = None,
            timeout: float | None = None) -> Compiled:
    """Compile ``pattern``; raises ParseError/UnsupportedSyntax and never hides them."""
    if profile is None:
        profile = os.environ.get("CERTEX_PROFILE", "cpython")
    if timeout is None:
        timeout = float(os.environ.get("CERTEX_TIMEOUT", "2.0"))
    rewrite = get_profile(profile)
    parsed = parse(pattern)
    tree = desugar(rewrite(parsed.tree))
    core = strip_groups(tree)
    tv = infer_type(core)
    bv = analyse_backrefs(tree)
    av = None if bv is not None else analyse_ambiguity(core, timeout)
    choice = synthesise(tree, core, tv, av, bv)
    body = _certificate_body(pattern, profile, core, tv, av, bv, choice)
    return Compiled(pattern, profile, parsed, tree, core, tv, av, bv, choice, sign(body))
