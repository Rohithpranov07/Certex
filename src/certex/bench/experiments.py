"""Experiments E1-E6 (and engine calibration): every number in the paper comes from here.

Results are written to ``results/e<N>_<name>.json`` as
``{"meta": {cpu, python, engines, seed, date}, "rows": [...], "summary": {...}}``.
Nothing is hard-coded; fixed seeds make E1, E2, E5 and E6 reproducible byte for byte
(``meta.date`` is the calendar day). Timing experiments (E3, E4 and the timing baseline)
depend on the machine and are not expected to be identical across runs.
"""

from __future__ import annotations

import csv
import datetime
import importlib.metadata
import json
import platform
import random
import re
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import certex
from certex.bench import baselines
from certex.bench.d2 import generate
from certex.engines.replay import BoundAttack, confirm, time_inputs
from certex.frontend.parser import ParseError

ROOT = Path(__file__).resolve().parents[3]
DATASETS = ROOT / "datasets"
RESULTS = ROOT / "results"
SEED = 7

# Representative EXP patterns for E3; the paper's own list of six is not reproduced in the
# project documents, so these are chosen from D1 (the walkthrough uses the 2nd and 5th).
E3_PATTERNS = [r"(a+)+$", r"(a|a)*$", r"(\w+\s?)*$", r"(x+x+)+y",
               r"^([a-z0-9]+[-_.]?)*[a-z0-9]+@", r"(a|aa)+$"]
E3_MAX_LENGTH = 48
E3_TARGET_S = 0.5
E3_SERIES = range(12, 27)
E4_SIZES = (5, 10, 20, 40, 60)

EXTRA_PATTERNS = ["abc|def|ghi", "(ab|cd)+", "(ab|cd|a)*", "(?:abc|d)*", "", "a|", "(a|)+",
                  "[^ab]+c", ".x.", "abc$"]
BREF_PATTERNS = [r"(a+)\1", r"(\w+)\s\1", r"<(\w+)>.*</\1>", r"(x+)(y+)\1\2", r"((a)b)*\2",
                 r"(a){2}\1", r"(a|b)?\1", r"(a*)+\1b", r"^(a|b)\1$", r"(a|b)*\1"]
DIFF_ALPHABET = "abcdx0123 .@-_!,=;<>/\n\tyz"


# ---- plumbing ----------------------------------------------------------------------------

def load_d1() -> list[dict[str, str]]:
    with open(DATASETS / "d1_redos.csv", newline="") as f:
        return list(csv.DictReader(f))


def load_d5() -> list[dict[str, str]]:
    with open(DATASETS / "d5_base_paper.csv", newline="") as f:
        return list(csv.DictReader(f))


def _cpu() -> str:
    try:
        if sys.platform == "darwin":
            return subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"],
                                  capture_output=True, text=True, check=True).stdout.strip()
        if sys.platform.startswith("linux"):
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return platform.processor() or platform.machine()


def _java_version() -> str | None:
    try:
        out = subprocess.run(["java", "-version"], capture_output=True, text=True, timeout=20, check=False)
        return (out.stderr or out.stdout).splitlines()[0].strip()
    except (OSError, subprocess.SubprocessError, IndexError):
        return None


def meta(seed: int = SEED) -> dict[str, Any]:
    try:
        pcre2_version: str | None = importlib.metadata.version("pcre2")
    except importlib.metadata.PackageNotFoundError:
        pcre2_version = None
    return {"cpu": _cpu(), "python": platform.python_version(),
            "engines": {"cpython": platform.python_version(), "pcre2": pcre2_version,
                        "java": _java_version()},
            "seed": seed, "date": datetime.datetime.now(tz=datetime.UTC).date().isoformat()}


def write_result(name: str, rows: Any, summary: dict[str, Any], seed: int = SEED,
                 results_dir: Path | None = None) -> Path:
    out = (results_dir or RESULTS)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{name}.json"
    doc = {"meta": meta(seed), "rows": rows, "summary": summary}
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=True) + "\n")
    return path


def metrics(truth: list[bool], pred: list[bool]) -> dict[str, Any]:
    tp = sum(t and p for t, p in zip(truth, pred, strict=True))
    fp = sum((not t) and p for t, p in zip(truth, pred, strict=True))
    fn = sum(t and not p for t, p in zip(truth, pred, strict=True))
    tn = sum((not t) and (not p) for t, p in zip(truth, pred, strict=True))
    n = len(truth)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "n": n,
            "accuracy": round((tp + tn) / n, 4) if n else 0.0,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}


# ---- E1: detection on D1 ----------------------------------------------------------------

def e1_detection() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    truth: list[bool] = []
    preds: dict[str, list[bool]] = {"star_height": [], "certex_none": [], "certex_cpython": []}
    for r in load_d1():
        p = r["pattern"]
        positive = r["label"] in ("EXP", "POLY")
        sh = baselines.star_height_flag(p)
        none = certex.compile(p, profile="none")
        cpy = certex.compile(p, profile="cpython")
        rows.append({"pattern": p, "label": r["label"], "star_height_flag": sh,
                     "certex_none": none.degree, "certex_cpython": cpy.degree,
                     "certex_cpython_correct": cpy.degree == r["label"]})
        truth.append(positive)
        preds["star_height"].append(bool(sh))
        preds["certex_none"].append(none.vulnerable)
        preds["certex_cpython"].append(cpy.vulnerable)
    summary: dict[str, Any] = {name: metrics(truth, pred) for name, pred in preds.items()}
    summary["certex_cpython"]["labels_exact"] = sum(x["certex_cpython_correct"] for x in rows)
    summary["timing_baseline"] = "see e1_timing_baseline.json (machine dependent)"
    write_result("e1_detection", rows, summary)
    return summary


def e1_timing_baseline() -> dict[str, Any]:
    rows = []
    truth: list[bool] = []
    pred: list[bool] = []
    for r in load_d1():
        label, ratio = baselines.timing_label(r["pattern"], seed=SEED)
        truth.append(r["label"] in ("EXP", "POLY"))
        pred.append(label in baselines.TIMING_POSITIVE)
        rows.append({"pattern": r["pattern"], "label": r["label"], "timing_label": label,
                     "median_ratio": ratio})
    summary = metrics(truth, pred)
    write_result("e1_timing_baseline", rows, summary)
    return summary


# ---- E2: D2 type inference ---------------------------------------------------------------

def e2_types() -> dict[str, Any]:
    rows = []
    per_class: dict[str, list[bool]] = {}
    for pattern, expected in generate(seed=11):
        got = certex.compile(pattern, profile="none").types.cls
        rows.append({"pattern": pattern, "expected": expected, "got": got})
        per_class.setdefault(expected, []).append(got == expected)
    summary: dict[str, Any] = {
        "correct": sum(r["expected"] == r["got"] for r in rows), "total": len(rows),
        "recall_by_class": {c: {"correct": sum(v), "total": len(v),
                                "recall": round(sum(v) / len(v), 4)}
                            for c, v in sorted(per_class.items())}}
    write_result("e2_types", rows, summary, seed=11)
    return summary


# ---- E3: attack runtime ------------------------------------------------------------------

def _best_certex_seconds(c: certex.Compiled, text: str, reps: int = 5) -> tuple[float, int]:
    best = float("inf")
    steps = 0
    for _ in range(reps):
        t0 = time.perf_counter()
        res = certex.match(c, text, "full")
        best = min(best, time.perf_counter() - t0)
        steps = res.steps
    return best, steps


def e3_attack_runtime() -> dict[str, Any]:
    rows = []
    for p in E3_PATTERNS:
        c = certex.compile(p)
        a = c.ambiguity.attack if c.ambiguity else None
        if a is None:
            continue
        inputs = []
        k = 1
        while len(a.build(k)) <= E3_MAX_LENGTH:
            inputs.append(a.build(k))
            k += 1
        # Grow the attack until CPython needs E3_TARGET_S seconds (or the length cap is hit).
        rep = time_inputs("cpython", p, inputs, per_input_limit=E3_TARGET_S, wall=30.0)
        if rep.points:
            text = inputs[len(rep.points) - 1]
            cpython_s: float | None = rep.points[-1][1]
        else:
            text = inputs[min(len(rep.points), len(inputs) - 1)]
            cpython_s = None
        cert_s, steps = _best_certex_seconds(c, text)
        rows.append({"pattern": p, "length": len(text), "kernel": c.choice.kernel.name,
                     "cpython_s": cpython_s, "cpython_hung": rep.hung,
                     "certex_s": cert_s, "certex_steps": steps})
    series = []
    c = certex.compile(r"(a+)+$")
    inputs = ["a" * k + "b" for k in E3_SERIES]
    rep = time_inputs("cpython", r"(a+)+$", inputs, per_input_limit=10.0, wall=90.0)
    cp = dict(rep.points)
    for k, text in zip(E3_SERIES, inputs, strict=True):
        cert_s, steps = _best_certex_seconds(c, text)
        series.append({"k": k, "length": len(text), "cpython_s": cp.get(len(text)),
                       "certex_s": cert_s, "certex_steps": steps})
    summary = {"six_patterns": len(rows), "series_points": len(series),
               "note": "six patterns chosen from D1; series is (a+)+$ on a^k b"}
    write_result("e3_attack_runtime", {"patterns": rows, "series": series}, summary)
    return summary


# ---- E4: compile overhead ----------------------------------------------------------------

def _leaf(rng: random.Random) -> str:
    return rng.choice(["a", "b", "c", "d", "[ab]", r"\d", "."])


def _gen(rng: random.Random, size: int) -> tuple[str, str]:
    """A random pattern of roughly ``size`` IR nodes; returns (text, kind)."""
    if size <= 1:
        return _leaf(rng), "leaf"
    if size == 2:
        return _leaf(rng) + rng.choice("*+"), "quant"
    roll = rng.random()
    if roll < 0.3:
        inner, kind = _gen(rng, size - 1)
        wrapped = inner if kind == "leaf" else f"(?:{inner})"
        return wrapped + rng.choice("*+"), "quant"
    parts_n = rng.choice((2, 2, 3))
    remaining = size - 1
    sizes = []
    for i in range(parts_n):
        left = parts_n - i
        s = remaining if left == 1 else rng.randint(1, max(1, remaining - (left - 1)))
        sizes.append(s)
        remaining -= s
    if roll < 0.65:                                   # concatenation
        pieces = []
        for s in sizes:
            text, kind = _gen(rng, s)
            pieces.append(f"(?:{text})" if kind in ("alt", "cat") else text)
        return "".join(pieces), "cat"
    pieces = [_gen(rng, s)[0] for s in sizes]
    return "|".join(pieces), "alt"


def e4_patterns(target: int, count: int = 5, seed: int = SEED) -> list[str]:
    rng = random.Random(f"{seed}:{target}")
    out: list[str] = []
    attempts = 0
    while len(out) < count and attempts < 5000:
        attempts += 1
        text, _ = _gen(rng, target)
        try:
            size = certex.compile(text, timeout=0.5).core.size()
        except ParseError:
            continue
        if 0.8 * target <= size <= 1.25 * target and text not in out:
            out.append(text)
    return out


def e4_compile_overhead(reps: int = 5) -> dict[str, Any]:
    rows = []
    summary: dict[str, Any] = {}
    for target in E4_SIZES:
        times = []
        for p in e4_patterns(target):
            samples = []
            c = None
            for _ in range(reps):
                t0 = time.perf_counter()
                c = certex.compile(p)
                samples.append(time.perf_counter() - t0)
            assert c is not None
            mean = sum(samples) / len(samples)
            times.append(mean)
            rows.append({"target": target, "pattern": p, "m": c.core.size(),
                         "mean_ms": round(mean * 1000, 4), "degree": c.degree})
        summary[str(target)] = {
            "patterns": len(times),
            "mean_ms": round(sum(times) / len(times) * 1000, 4) if times else None,
            "worst_ms": round(max(times) * 1000, 4) if times else None}
    write_result("e4_compile_overhead", rows, summary)
    return summary


# ---- E5: differential ---------------------------------------------------------------------

def differential_patterns() -> list[str]:
    return [r["pattern"] for r in load_d1()] + [r["pattern"] for r in load_d5()] \
        + EXTRA_PATTERNS + BREF_PATTERNS


def e5_differential() -> dict[str, Any]:
    rng = random.Random(1)
    oracle: dict[str, Callable[..., Any]] = {"full": re.fullmatch, "match": re.match,
                                             "search": re.search}
    per_mode = {m: {"cases": 0, "disagreements": 0} for m in oracle}
    mismatches = []
    for p in differential_patterns():
        c = certex.compile(p)
        own = "".join(ch for ch in p if ch.isalnum()) or "a"
        for _ in range(300):
            pool = DIFF_ALPHABET if rng.random() < 0.7 else own
            s = "".join(rng.choice(pool) for _ in range(rng.randint(0, 10)))
            for mode, fn in oracle.items():
                expected = fn(p, s, re.ASCII) is not None
                got = certex.match(c, s, mode).matched
                per_mode[mode]["cases"] += 1
                if got != expected:
                    per_mode[mode]["disagreements"] += 1
                    mismatches.append({"pattern": p, "text": s, "mode": mode})
    summary = {"cases": sum(v["cases"] for v in per_mode.values()),
               "disagreements": sum(v["disagreements"] for v in per_mode.values()),
               "patterns": len(differential_patterns()), "per_mode": per_mode}
    write_result("e5_differential", mismatches, summary, seed=1)
    return summary


# ---- E6: D5 table -------------------------------------------------------------------------

def e6_d5() -> dict[str, Any]:
    rows = []
    for r in load_d5():
        c = certex.compile(r["pattern"])
        rows.append({"pattern": r["pattern"], "base_label": r["base_label"] or None,
                     "raw_type": c.types.raw_type, "normalised_type": c.types.normalised,
                     "class": c.types.cls, "bound": c.types.bound, "degree": c.degree,
                     "kernel": c.choice.kernel.name})
    summary = {"patterns": len(rows),
               "note": "base_label is empty where the base paper's label is not recorded "
                       "in the project data"}
    write_result("e6_d5", rows, summary)
    return summary


# ---- engine calibration (T5.2) ---------------------------------------------------------------

def calibrate(engine: str) -> dict[str, Any]:
    """Replay every D1 EXP/POLY attack on ``engine`` (profile = engine) and record the result."""
    rows: list[dict[str, Any]] = []
    for r in load_d1():
        if r["label"] not in ("EXP", "POLY"):
            continue
        c = certex.compile(r["pattern"], profile=engine)
        a = c.ambiguity.attack if c.ambiguity else None
        if c.degree not in ("EXP", "POLY") or a is None:
            rows.append({"pattern": r["pattern"], "label": r["label"], "degree": c.degree,
                         "confirmed": False, "evidence": "profile removed the vulnerability"})
            continue
        res = confirm(c.degree, BoundAttack(r["pattern"], a.prefix, a.pump, a.suffix), engine)
        rows.append({"pattern": r["pattern"], "label": r["label"], "degree": c.degree,
                     "confirmed": res["confirmed"], "evidence": res["evidence"]})
    confirmed = sum(x["confirmed"] for x in rows)
    summary = {"engine": engine, "confirmed": confirmed, "total": len(rows),
               "rate": round(confirmed / len(rows), 4) if rows else None,
               "unconfirmed": [x["pattern"] for x in rows if not x["confirmed"]]}
    write_result("e7_calibration" if engine != "cpython" else "e7_calibration_cpython",
                 rows, summary)
    return summary


ALL: dict[str, Callable[[], dict[str, Any]]] = {
    "e1": e1_detection, "e1_timing": e1_timing_baseline, "e2": e2_types,
    "e3": e3_attack_runtime, "e4": e4_compile_overhead, "e5": e5_differential, "e6": e6_d5,
}


def run_all() -> dict[str, dict[str, Any]]:
    return {name: fn() for name, fn in ALL.items()}
