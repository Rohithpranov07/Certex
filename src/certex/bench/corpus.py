"""Public-corpus evaluation (T5.6): CERTEX verdicts on real PyPI regexes, checked by replay.

Corpus: ``datasets/corpus/pypi-uniquePatterns.jsonl`` (source, licence, DOI in ``SOURCE.md``).
Ground truth is replay on CPython:

* every CERTEX EXP/POLY verdict in a seeded sample (``REPLAY_SAMPLE``) is replayed with the
  T5.1 confirmation rules -> precision;
* a seeded sample of ``LIN_SAMPLE`` LIN verdicts is fuzzed with generic attack inputs built
  *without* the rejecting-suffix search (single repeated characters followed by a fixed set of
  suffix characters) -> a lower bound on false negatives, since fuzzing can miss vulnerable
  patterns.

Patterns outside the v1 subset are counted separately and never counted as passes.
"""

from __future__ import annotations

import json
import random
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

import certex
from certex.bench.experiments import DATASETS, SEED, write_result
from certex.engines.replay import BoundAttack, confirm, time_inputs
from certex.frontend.ir import REPEAT, Node
from certex.frontend.parser import ParseError, UnsupportedSyntax, parse

CORPUS = DATASETS / "corpus" / "pypi-uniquePatterns.jsonl"
REPLAY_SAMPLE = 300
LIN_SAMPLE = 500
MAX_EXPANDED = 20000        # skip patterns whose desugared size would exceed this
ANALYSIS_TIMEOUT = 0.5
FUZZ_SUFFIXES = ["\n", "!", "~", "a", "0", " "]
FUZZ_LENGTHS = [30, 500, 2000]


def load_patterns(path: Path = CORPUS) -> list[str]:
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            out.append(json.loads(line)["pattern"])
    return out


def expanded_size(n: Node) -> int:
    """Upper estimate of the node count after desugaring ``{m,n}`` repeats."""
    inner = sum(expanded_size(k) for k in n.kids)
    if n.op == REPEAT:
        return 1 + inner * max(n.hi if n.hi is not None else n.lo + 1, 1)
    return 1 + inner


def classify(pattern: str) -> dict[str, Any]:
    """Compile one pattern; returns a compact record (picklable, for the process pool)."""
    try:
        parsed = parse(pattern)
    except UnsupportedSyntax as e:
        return {"status": "unsupported", "why": e.msg}
    except ParseError as e:
        return {"status": "parse_error", "why": e.msg}
    if expanded_size(parsed.tree) > MAX_EXPANDED:
        return {"status": "too_large"}
    try:
        c = certex.compile(pattern, "cpython", ANALYSIS_TIMEOUT)
    except (ParseError, RecursionError, MemoryError) as e:
        return {"status": "error", "why": type(e).__name__}
    rec: dict[str, Any] = {"status": "analysed", "degree": c.degree, "kernel": c.choice.kernel.name}
    if c.ambiguity is not None and c.ambiguity.attack is not None:
        a = c.ambiguity.attack
        rec["attack"] = [a.prefix, a.pump, a.suffix]
    return rec


def _alphabet(pattern: str) -> list[str]:
    tree = parse(pattern).tree
    chars: set[str] = set()

    def walk(n: Node) -> None:
        if n.cs is not None:
            chars.update(sorted(n.cs.chars)[:3] if not n.cs.negated else ["a"])
        for k in n.kids:
            walk(k)

    walk(tree)
    return sorted(chars)[:4] or ["a"]


def fuzz_lin(pattern: str) -> dict[str, Any]:
    """Look for a slow input on a pattern CERTEX called LIN, without suffix search."""
    worst = 0.0
    for ch in _alphabet(pattern):
        inputs = [ch * n + s for n in FUZZ_LENGTHS for s in FUZZ_SUFFIXES]
        rep = time_inputs("cpython", pattern, inputs, per_input_limit=0.5, wall=5.0)
        slow = rep.hung or rep.gave_up
        worst = max([worst, *(t for _, t in rep.points)])
        if slow:
            return {"vulnerable_found": True, "worst_s": max(worst, 0.5)}
    return {"vulnerable_found": False, "worst_s": worst}


def run(workers: int = 8) -> dict[str, Any]:
    patterns = load_patterns()
    t0 = time.perf_counter()
    with ProcessPoolExecutor(max_workers=workers) as pool:
        records = list(pool.map(classify, patterns, chunksize=200))
    analysis_s = time.perf_counter() - t0

    counts: dict[str, int] = {}
    degrees: dict[str, int] = {}
    why: dict[str, int] = {}
    for rec in records:
        counts[rec["status"]] = counts.get(rec["status"], 0) + 1
        if rec["status"] == "analysed":
            degrees[rec["degree"]] = degrees.get(rec["degree"], 0) + 1
        elif "why" in rec:
            why[rec["why"]] = why.get(rec["why"], 0) + 1

    rng = random.Random(SEED)
    flagged = [i for i, r in enumerate(records)
               if r["status"] == "analysed" and r["degree"] in ("EXP", "POLY") and "attack" in r]
    lin = [i for i, r in enumerate(records)
           if r["status"] == "analysed" and r["degree"] == "LIN"]
    replay_ids = rng.sample(flagged, min(REPLAY_SAMPLE, len(flagged)))
    lin_ids = rng.sample(lin, min(LIN_SAMPLE, len(lin)))

    rows: list[dict[str, Any]] = []
    confirmed = 0
    for i in replay_ids:
        rec = records[i]
        p, (pre, pump, suf) = patterns[i], rec["attack"]
        res = confirm(rec["degree"], BoundAttack(p, pre, pump, suf), "cpython")
        confirmed += bool(res["confirmed"])
        rows.append({"kind": "flagged", "pattern": p, "degree": rec["degree"],
                     "confirmed": res["confirmed"], "evidence": res["evidence"]})
    fn_found = 0
    for i in lin_ids:
        res = fuzz_lin(patterns[i])
        fn_found += bool(res["vulnerable_found"])
        if res["vulnerable_found"]:
            rows.append({"kind": "lin_fuzz_slow", "pattern": patterns[i], **res})

    analysed = counts.get("analysed", 0)
    summary: dict[str, Any] = {
        "corpus": "datasets/corpus/pypi-uniquePatterns.jsonl (see SOURCE.md)",
        "patterns_total": len(patterns), "status_counts": counts,
        "unsupported_syntax": counts.get("unsupported", 0),
        "unsupported_reasons": dict(sorted(why.items(), key=lambda kv: -kv[1])[:15]),
        "analysed": analysed, "degrees": degrees,
        "analysis_runtime_s": round(analysis_s, 2),
        "analysis_mean_ms": round(1000 * analysis_s * workers / max(len(patterns), 1), 3),
        "workers": workers,
        "flagged_total": len(flagged), "replay_sample": len(replay_ids),
        "replay_confirmed": confirmed,
        "precision_estimate": round(confirmed / len(replay_ids), 4) if replay_ids else None,
        "lin_total": len(lin), "lin_fuzz_sample": len(lin_ids),
        "lin_fuzz_slow_found": fn_found,
        "lin_false_negative_rate_lower_bound": round(fn_found / len(lin_ids), 4) if lin_ids else None,
        "note": ("precision is on a seeded sample of flagged patterns; the LIN rate is a "
                 "lower bound (fuzzing can miss); unsupported patterns are not counted as passes"),
    }
    write_result("e1b_corpus", rows, summary)
    return summary

