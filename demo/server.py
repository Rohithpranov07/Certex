"""CERTEX demo server: a local web page over the compiler, the governor and the replay harness.

    python demo/server.py            # http://127.0.0.1:8765
    python demo/server.py --port 0   # any free port

Standard library only. Docs read in-session: Python `http.server` (ThreadingHTTPServer,
BaseHTTPRequestHandler: send_response / send_header / end_headers / wfile, rfile) and `json`.

Every match the page asks for runs through ``certex.match`` (the governed kernel). The only
backtracking run is the side-by-side race, and that goes through ``engines.replay.time_inputs``:
CPython ``re`` in its own subprocess under a wall-clock limit, so the server never hangs.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import certex
from certex.backend.certificate import budget_for, verify
from certex.backend.kernels import BudgetExceeded
from certex.compiler import Compiled
from certex.engines.replay import time_inputs
from certex.frontend.ir import to_pattern
from certex.frontend.parser import ParseError
from certex.runtime.governor import CertificateInvalid

ROOT = Path(__file__).resolve().parent.parent
WEB = Path(__file__).resolve().parent / "web"
RESULTS = ROOT / "results"

PROFILES = ("cpython", "pcre2", "java", "none")
MODES = ("full", "match", "search")
MAX_PATTERN = 500
MAX_TEXT = 100_000
MAX_BODY = 256 * 1024
MAX_PUMP = 50_000
RACE_WALL = 6.0            # seconds before the CPython subprocess is killed
RACE_PER_INPUT = 4.0       # the harness stops after the first input slower than this


class BadRequest(ValueError):
    """The request body is missing a field or a field is out of range."""


def _str_field(body: dict[str, Any], name: str, limit: int, default: str | None = None) -> str:
    v = body.get(name, default)
    if not isinstance(v, str):
        raise BadRequest(f"{name} must be a string")
    if len(v) > limit:
        raise BadRequest(f"{name} is longer than {limit} characters")
    return v


def _profile(body: dict[str, Any]) -> str:
    p = _str_field(body, "profile", 16, "cpython")
    if p not in PROFILES:
        raise BadRequest(f"profile must be one of {', '.join(PROFILES)}")
    return p


def _parse_error(e: ParseError) -> dict[str, Any]:
    return {"ok": False, "error": {"kind": type(e).__name__, "message": e.msg,
                                   "offset": e.offset}}


def describe(c: Compiled, compile_ms: float) -> dict[str, Any]:
    """Everything the page shows about one compiled pattern, read off ``Compiled``."""
    amb = c.ambiguity
    attack = None
    if amb is not None and amb.attack is not None:
        a = amb.attack
        attack = {"prefix": a.prefix, "pump": a.pump, "suffix": a.suffix,
                  "example_k": 20, "example": a.build(20)}
    b = c.backrefs
    cert = c.certificate
    return {
        "ok": True,
        "pattern": c.pattern,
        "profile": c.profile,
        "compile_ms": round(compile_ms, 3),
        "degree": c.degree,
        "vulnerable": c.vulnerable,
        "anchored": {"start": c.parsed.anchored_start, "end": c.parsed.anchored_end},
        "groups": c.parsed.ngroups,
        "core": to_pattern(c.core),
        "m": c.core.size(),
        "types": {"cls": c.types.cls, "bound": c.types.bound,
                  "homogeneous": c.types.homogeneous, "raw_type": c.types.raw_type,
                  "normalised": c.types.normalised, "hard_core": c.types.hard_core},
        "ambiguity": None if amb is None else {
            "degree": amb.degree, "unexploitable": amb.unexploitable, "reason": amb.reason,
            "attack": attack},
        "backrefs": None if b is None else {
            "vars": list(b.vars), "k": b.k, "redefined": list(b.redefined),
            "md_candidate": b.md_candidate, "bound": b.bound},
        "kernel": {"name": c.choice.kernel.name,
                   "fallback": c.choice.fallback.name if c.choice.fallback else None,
                   "rule": c.choice.rule, "bound": c.choice.bound,
                   "budget": dict(c.choice.budget)},
        "signature_ok": verify(cert),
        "dev_key": bool(cert.get("dev_key")),
        "certificate": cert,
    }


def api_compile(body: dict[str, Any]) -> dict[str, Any]:
    pattern = _str_field(body, "pattern", MAX_PATTERN)
    profile = _profile(body)
    t0 = time.perf_counter()
    try:
        c = certex.compile(pattern, profile)
    except ParseError as e:
        return _parse_error(e)
    return describe(c, (time.perf_counter() - t0) * 1000)


def api_match(body: dict[str, Any]) -> dict[str, Any]:
    pattern = _str_field(body, "pattern", MAX_PATTERN)
    text = _str_field(body, "text", MAX_TEXT)
    profile = _profile(body)
    mode = _str_field(body, "mode", 8, "full")
    if mode not in MODES:
        raise BadRequest(f"mode must be one of {', '.join(MODES)}")
    try:
        c = certex.compile(pattern, profile)
    except ParseError as e:
        return _parse_error(e)
    t0 = time.perf_counter()
    try:
        res = certex.match(c, text, mode)
    except (CertificateInvalid, BudgetExceeded) as e:
        return {"ok": False, "error": {"kind": type(e).__name__, "message": str(e),
                                       "offset": None}}
    ms = (time.perf_counter() - t0) * 1000
    return {"ok": True, "matched": res.matched, "kernel": res.kernel, "steps": res.steps,
            "fell_back": res.fell_back, "mode": mode, "length": len(text),
            "budget": budget_for(c.certificate, len(text)), "ms": round(ms, 3)}


def api_race(body: dict[str, Any]) -> dict[str, Any]:
    """Run the synthesised attack at pump count ``k`` on CPython ``re`` and on CERTEX."""
    pattern = _str_field(body, "pattern", MAX_PATTERN)
    profile = _profile(body)
    k = body.get("k", 24)
    if not isinstance(k, int) or isinstance(k, bool) or not 1 <= k <= MAX_PUMP:
        raise BadRequest(f"k must be an integer from 1 to {MAX_PUMP}")
    try:
        c = certex.compile(pattern, profile)
    except ParseError as e:
        return _parse_error(e)
    amb = c.ambiguity
    if amb is None or amb.attack is None:
        return {"ok": False, "error": {"kind": "NoAttack", "offset": None,
                                       "message": "this pattern has no synthesised attack "
                                                  f"(degree {c.degree})"}}
    text = amb.attack.build(k)

    t0 = time.perf_counter()
    res = certex.match(c, text, "full")
    certex_s = time.perf_counter() - t0

    replay = time_inputs("cpython", pattern, [text], RACE_PER_INPUT, RACE_WALL)
    cpython_s = replay.points[-1][1] if replay.points else None
    return {
        "ok": True, "k": k, "length": len(text), "degree": c.degree,
        "certex": {"seconds": certex_s, "matched": res.matched, "kernel": res.kernel,
                   "steps": res.steps, "fell_back": res.fell_back,
                   "budget": budget_for(c.certificate, len(text))},
        "cpython": {"seconds": cpython_s, "killed": replay.hung,
                    "wall": RACE_WALL, "error": replay.error},
    }


def _load(name: str) -> dict[str, Any] | None:
    try:
        with open(RESULTS / name) as f:
            data: dict[str, Any] = json.load(f)
            return data
    except (OSError, json.JSONDecodeError):
        return None


def api_evidence() -> dict[str, Any]:
    """Headline numbers straight from ``results/*.json``; nothing here is computed or typed in."""
    out: dict[str, Any] = {"ok": True}
    e1 = _load("e1_detection.json")
    if e1:
        s = e1["summary"]
        out["d1"] = {"n": s["certex_cpython"]["n"],
                     "labels_exact": s["certex_cpython"].get("labels_exact"),
                     "certex_cpython": s["certex_cpython"], "certex_none": s["certex_none"],
                     "star_height": s["star_height"], "meta": e1["meta"]}
    e2 = _load("e2_types.json")
    if e2:
        s = e2["summary"]
        out["d2"] = {"correct": s.get("correct"), "total": s.get("total")}
    e3 = _load("e3_attack_runtime.json")
    if e3:
        out["e3"] = {"patterns": e3["rows"]["patterns"], "meta": e3["meta"]}
    e5 = _load("e5_differential.json")
    if e5:
        s = e5["summary"]
        out["differential"] = {"cases": s["cases"], "disagreements": s["disagreements"],
                               "patterns": s["patterns"]}
    e1b = _load("e1b_corpus.json")
    if e1b:
        s = e1b["summary"]
        out["corpus"] = {k: s.get(k) for k in (
            "patterns_total", "analysed", "unsupported_syntax", "degrees", "flagged_total",
            "replay_sample", "replay_confirmed", "precision_estimate", "analysis_mean_ms")}
    return out


ROUTES_POST = {"/api/compile": api_compile, "/api/match": api_match, "/api/race": api_race}


class Handler(BaseHTTPRequestHandler):
    server_version = "certex-demo"

    def log_message(self, format: str, *args: Any) -> None:
        if not getattr(self.server, "quiet", False):
            super().log_message(format, *args)

    def _send(self, status: int, payload: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, status: int, obj: dict[str, Any]) -> None:
        self._send(status, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/api/evidence":
            self._json(200, api_evidence())
            return
        if path == "/":
            path = "/index.html"
        target = (WEB / path.lstrip("/")).resolve()
        if not target.is_relative_to(WEB) or not target.is_file():
            self._json(404, {"ok": False, "error": {"kind": "NotFound", "message": path,
                                                    "offset": None}})
            return
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        self._send(200, target.read_bytes(), ctype)

    def do_POST(self) -> None:
        route = ROUTES_POST.get(self.path.split("?", 1)[0])
        if route is None:
            self._json(404, {"ok": False, "error": {"kind": "NotFound", "message": self.path,
                                                    "offset": None}})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                raise BadRequest("request body too large")
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise BadRequest("request body must be a JSON object")
            self._json(200, route(body))
        except (BadRequest, json.JSONDecodeError) as e:
            self._json(400, {"ok": False, "error": {"kind": "BadRequest", "message": str(e),
                                                    "offset": None}})


def make_server(host: str = "127.0.0.1", port: int = 8765, quiet: bool = False,
                ) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    srv.quiet = quiet  # type: ignore[attr-defined]
    return srv


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Serve the CERTEX demo page.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args(argv)
    srv = make_server(args.host, args.port)
    host, port = srv.server_address[:2]
    print(f"CERTEX demo on http://{host!s}:{port}  (Ctrl-C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
