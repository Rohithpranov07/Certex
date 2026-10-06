"""Replay harness driver: times attack inputs on real engines without ever hanging the caller.

Each engine runs in its own subprocess under a wall-clock limit; the harness times the match
inside that process (see ``harness/``). Partial output is parsed on timeout.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from itertools import pairwise
from pathlib import Path
from typing import Any

ENGINES = ("cpython", "pcre2", "java")
LIMIT_ERROR = "engine match limit"       # Replay.error value when the engine hit its own limit


@dataclass
class Replay:
    engine: str
    points: list[tuple[int, float]] = field(default_factory=list)   # (length, seconds)
    hung: bool = False                   # wall-clock limit hit, subprocess killed
    gave_up: bool = False                # harness stopped: input over limit, or engine limit
    error: str | None = None


@dataclass
class BoundAttack:
    pattern: str
    prefix: str
    pump: str
    suffix: str

    def build(self, k: int) -> str:
        return self.prefix + self.pump * k + self.suffix


def harness_dir() -> Path:
    env = os.environ.get("CERTEX_HARNESS_DIR")
    return Path(env) if env else Path(__file__).resolve().parents[3] / "harness"


def _java_command() -> list[str]:
    hd = harness_dir()
    build = hd / "build"
    cls = build / "ReplayMain.class"
    src = hd / "ReplayMain.java"
    if not cls.exists() or cls.stat().st_mtime < src.stat().st_mtime:
        javac = shutil.which("javac")
        if javac is None:
            raise RuntimeError("javac not found; the java engine needs a JDK")
        build.mkdir(parents=True, exist_ok=True)
        subprocess.run([javac, "-d", str(build), str(src)], check=True, capture_output=True,
                       timeout=120)
    java = os.environ.get("CERTEX_JAVA") or shutil.which("java") or "java"
    return [java, "-Xss512m", "-cp", str(build), "ReplayMain"]


def _command_and_stdin(engine: str, pattern: str, inputs: list[str],
                       limit: float) -> tuple[list[str], str]:
    hd = harness_dir()
    if engine == "cpython":
        job = json.dumps({"pattern": pattern, "inputs": inputs, "limit": limit})
        return [sys.executable, str(hd / "cpython_replay.py")], job
    if engine == "pcre2":
        job = json.dumps({"pattern": pattern, "inputs": inputs, "limit": limit})
        return [sys.executable, str(hd / "pcre2_replay.py")], job
    if engine == "java":
        lines = [pattern.encode("utf-8").hex(), repr(limit)]
        lines += [s.encode("utf-8").hex() for s in inputs]
        return _java_command(), "\n".join(lines) + "\n"
    raise ValueError(f"unknown engine {engine!r}; valid engines: {', '.join(ENGINES)}")


def time_inputs(engine: str, pattern: str, inputs: list[str], per_input_limit: float = 1.0,
                wall: float | None = None) -> Replay:
    """Time ``fullmatch`` of ``pattern`` on each input in a subprocess; never blocks past ``wall``."""
    if wall is None:
        wall = float(os.environ.get("CERTEX_REPLAY_WALL", "20"))
    replay = Replay(engine)
    try:
        cmd, stdin = _command_and_stdin(engine, pattern, inputs, per_input_limit)
    except (RuntimeError, subprocess.SubprocessError) as e:
        replay.error = str(e)
        return replay
    out = ""
    try:
        proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=wall,
                              check=False)
        out = proc.stdout
        if proc.returncode != 0 and not out:
            replay.error = (proc.stderr or f"exit code {proc.returncode}").strip()[-300:]
    except subprocess.TimeoutExpired as e:
        replay.hung = True
        raw = e.stdout
        out = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else (raw or "")
    for line in out.splitlines():
        try:
            rec: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "error" in rec:
            replay.error = str(rec["error"])
        elif rec.get("limit"):
            replay.gave_up = True
            replay.error = LIMIT_ERROR
        elif "t" in rec:
            replay.points.append((int(rec["len"]), float(rec["t"])))
    if replay.points and replay.points[-1][1] > per_input_limit:
        replay.gave_up = True
    return replay


def _per_char_growth(points: list[tuple[int, float]], floor: float = 1e-3) -> float | None:
    """Geometric-mean growth factor per added character over steps that start above ``floor``."""
    logs = []
    for (l1, t1), (l2, t2) in pairwise(points):
        if t1 >= floor and t2 > 0 and l2 > l1:
            logs.append(math.log(t2 / t1) / (l2 - l1))
    return math.exp(sum(logs) / len(logs)) if logs else None


def _loglog_slope(points: list[tuple[int, float]]) -> float | None:
    pts = [(math.log(k), math.log(t)) for k, t in points if t > 0]
    if len(pts) < 2:
        return None
    mx = sum(x for x, _ in pts) / len(pts)
    my = sum(y for _, y in pts) / len(pts)
    den = sum((x - mx) ** 2 for x, _ in pts)
    return sum((x - mx) * (y - my) for x, y in pts) / den if den else None


def confirm(degree: str, attack: BoundAttack, engine: str,
            exp_max_len: int = 60) -> dict[str, Any]:
    """Replay the attack on ``engine`` and decide whether the claimed ``degree`` reproduces.

    EXP: growth >= 1.2x per character once above 1 ms, or a hang/limit within ``exp_max_len``
    characters. POLY: log-log slope >= 1.5 over pumps k in {250, 500, 1000, 2000}, or a
    hang/limit.
    """
    if degree == "EXP":
        ks: list[int] = []
        k = 1
        while len(attack.build(k)) <= exp_max_len:
            ks.append(k)
            k += 1
        ks = ks or [1]
    elif degree == "POLY":
        ks = [250, 500, 1000, 2000]
    else:
        raise ValueError(f"nothing to confirm for degree {degree!r}")
    inputs = [attack.build(k) for k in ks]
    replay = time_inputs(engine, attack.pattern, inputs)
    xs = [(k, t) for k, (_, t) in zip(ks, replay.points, strict=False)]
    points = list(replay.points)
    if replay.error and replay.error != LIMIT_ERROR:
        return {"confirmed": False, "evidence": f"replay error: {replay.error}", "points": points}
    if replay.hung or replay.gave_up:
        what = "engine limit" if replay.error == LIMIT_ERROR else (
            "wall-clock hang" if replay.hung else "input over the per-input limit")
        longest = points[-1][0] if points else 0
        return {"confirmed": True, "points": points,
                "evidence": f"{what} after {len(points)} timed input(s), longest {longest} chars"}
    if degree == "EXP":
        g = _per_char_growth(points)
        ok = g is not None and g >= 1.2
        ev = "no step above 1 ms" if g is None else f"growth {g:.2f}x per character"
    else:
        s = _loglog_slope(xs)
        ok = s is not None and s >= 1.5
        ev = "too few points" if s is None else f"log-log slope {s:.2f}"
    return {"confirmed": ok, "evidence": ev, "points": points}
