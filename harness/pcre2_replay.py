"""PCRE2 replay harness (PyPI package `pcre2` 0.7.1, https://pypi.org/project/pcre2/).

Same protocol as cpython_replay.py. API used, read in-session from the installed package
(pcre2/__init__.py, _cy.pyx): pcre2.compile(pattern, flags=0, *, jit=True, callout=None),
Pattern.fullmatch(string), pcre2.ASCII.

Engine-side limit: established by running `(a+)+$` on "a"*24+"b": the package raises
pcre2.LibraryError('match limit exceeded'). That is reported as {"len": n, "limit": true}.
"""

import json
import sys
import time

import pcre2


def main() -> None:
    job = json.loads(sys.stdin.read())
    try:
        rx = pcre2.compile(job["pattern"], flags=pcre2.ASCII)
    except pcre2.PatternError as e:
        print(json.dumps({"error": f"compile: {e}"}), flush=True)
        return
    for s in job["inputs"]:
        t0 = time.perf_counter()
        try:
            rx.fullmatch(s)
        except pcre2.LibraryError as e:
            if "limit" in str(e):
                print(json.dumps({"len": len(s), "limit": True}), flush=True)
                return
            print(json.dumps({"error": str(e)}), flush=True)
            return
        dt = time.perf_counter() - t0
        print(json.dumps({"len": len(s), "t": dt}), flush=True)
        if dt > job["limit"]:
            break


if __name__ == "__main__":
    main()
