"""Command line interface: ``certex compile | check | match | bench``."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import certex
from certex.analysis.ambiguity import UNKNOWN
from certex.backend.kernels import BudgetExceeded
from certex.bench.extract import extract_patterns
from certex.compiler import Compiled
from certex.frontend.parser import ParseError
from certex.runtime.governor import CertificateInvalid

EXIT_OK, EXIT_VULNERABLE, EXIT_ERROR = 0, 1, 2


def _err(e: ParseError) -> str:
    return f"{type(e).__name__}: {e.msg} at offset {e.offset}"


def _summary(c: Compiled) -> str:
    cert = c.certificate
    key = ("DEVELOPMENT KEY (dev_key=true; set CERTEX_KEY outside development)"
           if cert["dev_key"] else "CERTEX_KEY")
    lines = [f"pattern : {c.pattern}", f"profile : {c.profile}", f"signing : {key}"]
    amb = c.ambiguity
    if c.vulnerable and amb is not None and amb.attack is not None:
        a = amb.attack
        lines.append(f"degree  : {c.degree}  (VULNERABLE)")
        lines.append(f"attack  : {a.prefix!r} + {a.pump!r} * k + {a.suffix!r}"
                     f"   e.g. k=20 -> {a.build(20)!r}")
    elif c.degree == "UNKNOWN":
        lines.append(f"degree  : UNKNOWN  ({amb.reason if amb else ''})")
    elif amb is not None and amb.unexploitable:
        lines.append(f"degree  : {c.degree}  (ambiguous but unexploitable: {amb.reason})")
    else:
        lines.append(f"degree  : {c.degree}")
    if c.backrefs is not None:
        b = c.backrefs
        lines.append(f"backrefs: groups {list(b.vars)} k={b.k} redefined={list(b.redefined)} "
                     f"md_candidate={b.md_candidate} bound={b.bound}")
    lines.append(f"class   : {c.types.cls}  {c.types.bound}")
    fb = c.choice.fallback.name if c.choice.fallback else "none"
    lines.append(f"kernel  : {c.choice.kernel.name} (fallback {fb})  [{c.choice.rule}]")
    lines.append(f"bound   : {c.choice.bound}")
    return "\n".join(lines)


def _exit_for(c: Compiled) -> int:
    if c.degree == UNKNOWN:
        return EXIT_ERROR
    return EXIT_VULNERABLE if c.vulnerable else EXIT_OK


def cmd_compile(args: argparse.Namespace) -> int:
    try:
        c = certex.compile(args.pattern, args.profile)
    except ParseError as e:
        print(_err(e), file=sys.stderr)
        return EXIT_ERROR
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    if args.output:
        with open(args.output, "w") as f:
            json.dump(c.certificate, f, indent=2)
            f.write("\n")
    print(json.dumps(c.certificate, indent=2) if args.json else _summary(c))
    return _exit_for(c)


def cmd_check(args: argparse.Namespace) -> int:
    try:
        found = extract_patterns(args.file)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    results: list[tuple[dict[str, Any], Compiled | None]] = []
    saw_error = saw_vuln = False
    for line, pattern in found:
        entry: dict[str, Any] = {"line": line, "pattern": pattern, "certificate": None,
                                 "error": None}
        compiled: Compiled | None = None
        try:
            compiled = certex.compile(pattern, args.profile)
        except ParseError as e:
            entry["error"] = _err(e)
            saw_error = True
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return EXIT_ERROR
        else:
            entry["certificate"] = compiled.certificate
            if compiled.degree == UNKNOWN:
                reason = compiled.ambiguity.reason if compiled.ambiguity else ""
                entry["error"] = f"UNKNOWN: {reason}"
                saw_error = True
            elif compiled.vulnerable:
                saw_vuln = True
        results.append((entry, compiled))
    code = EXIT_ERROR if saw_error else (EXIT_VULNERABLE if saw_vuln else EXIT_OK)
    if args.json:
        print(json.dumps([e for e, _ in results], indent=2))
        return code
    for entry, c in results:
        where = f"{args.file}:{entry['line']}"
        if c is None:
            print(f"{where}: ERROR  {entry['pattern']}  -> {entry['error']}")
        elif entry["error"]:
            print(f"{where}: UNKNOWN  {entry['pattern']}  -> {entry['error']}")
        elif c.vulnerable and c.ambiguity is not None and c.ambiguity.attack is not None:
            a = c.ambiguity.attack
            print(f"{where}: {c.degree}  {entry['pattern']}  attack "
                  f"{a.prefix!r}+{a.pump!r}*k+{a.suffix!r}")
        else:
            print(f"{where}: ok ({c.degree})  {entry['pattern']}")
    print(f"profile: {args.profile or 'default'}; {len(results)} pattern(s); exit {code}")
    return code


def cmd_match(args: argparse.Namespace) -> int:
    try:
        c = certex.compile(args.pattern, args.profile)
        res = certex.match(c, args.text, args.mode)
    except (ParseError, ValueError, CertificateInvalid, BudgetExceeded) as e:
        msg = _err(e) if isinstance(e, ParseError) else f"error: {e}"
        print(msg, file=sys.stderr)
        return EXIT_ERROR
    print(f"matched={res.matched} kernel={res.kernel} steps={res.steps} "
          f"fell_back={res.fell_back} mode={args.mode} profile={c.profile}")
    return EXIT_OK if res.matched else EXIT_VULNERABLE


def cmd_bench(args: argparse.Namespace) -> int:
    from certex.bench import experiments

    what = args.what
    if args.all:
        what = "all"
    if what is None:
        print("error: choose --all, calibrate, corpus or figures", file=sys.stderr)
        return EXIT_ERROR
    if what == "all":
        for name, summary in experiments.run_all().items():
            print(f"{name}: {json.dumps(summary)[:300]}")
        try:
            from certex.bench import figures
            print(figures.render_all())
        except ImportError:
            print("figures skipped (matplotlib not installed; pip install 'certex[figures]')")
        return EXIT_OK
    if what == "calibrate":
        if not args.engine:
            print("error: calibrate needs --engine cpython|pcre2|java", file=sys.stderr)
            return EXIT_ERROR
        s = experiments.calibrate(args.engine)
        print(f"{args.engine}: confirmed {s['confirmed']}/{s['total']}")
        if s["unconfirmed"]:
            print(f"  with the required literal kept in the suffix: "
                  f"{s['confirmed'] + s['adapted_confirmed']}/{s['total']}")
        for p in s["unconfirmed"]:
            print(f"  not confirmed as synthesised: {p}")
        for p in s["unconfirmed_even_adapted"]:
            print(f"  not confirmed even adapted:   {p}")
        return EXIT_OK
    if what == "figures":
        from certex.bench import figures
        print(figures.render_all())
        return EXIT_OK
    if what == "corpus":
        from certex.bench import corpus
        print(json.dumps(corpus.run(), indent=2))
        return EXIT_OK
    return EXIT_ERROR


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="certex", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("compile", help="analyse one pattern and emit a signed certificate")
    c.add_argument("pattern")
    c.add_argument("--profile", help="none|cpython|pcre2|java (default: $CERTEX_PROFILE)")
    c.add_argument("-o", "--output", help="write the certificate JSON here")
    c.add_argument("--json", action="store_true", help="print the certificate as JSON")
    c.set_defaults(func=cmd_compile)

    k = sub.add_parser("check", help="scan a file; exit 0 safe, 1 EXP/POLY, 2 error/UNKNOWN")
    k.add_argument("file")
    k.add_argument("--profile")
    k.add_argument("--json", action="store_true", help="one certificate per pattern, as JSON")
    k.set_defaults(func=cmd_check)

    m = sub.add_parser("match", help="match TEXT through the governed kernel")
    m.add_argument("pattern")
    m.add_argument("text")
    m.add_argument("--mode", choices=("full", "match", "search"), default="full")
    m.add_argument("--profile")
    m.set_defaults(func=cmd_match)

    b = sub.add_parser("bench", help="regenerate results, figures and tables")
    b.add_argument("what", nargs="?", choices=("calibrate", "corpus", "figures"))
    b.add_argument("--all", action="store_true")
    b.add_argument("--engine", choices=("cpython", "pcre2", "java"))
    b.set_defaults(func=cmd_bench)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
