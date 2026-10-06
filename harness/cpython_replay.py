"""CPython replay harness.

Protocol: one JSON job on stdin: {"pattern": str, "inputs": [str, ...], "limit": seconds}.
For each input it times re.fullmatch (ASCII) INSIDE this process and prints one JSON line
{"len": n, "t": seconds}, flushed, stopping after the first input that exceeds the limit.

Docs read in-session: Python `re` module (re.compile, Pattern.fullmatch, re.ASCII).
"""

import json
import re
import sys
import time


def main() -> None:
    job = json.loads(sys.stdin.read())
    try:
        rx = re.compile(job["pattern"], re.ASCII)
    except re.error as e:
        print(json.dumps({"error": f"compile: {e}"}), flush=True)
        return
    for s in job["inputs"]:
        t0 = time.perf_counter()
        rx.fullmatch(s)
        dt = time.perf_counter() - t0
        print(json.dumps({"len": len(s), "t": dt}), flush=True)
        if dt > job["limit"]:
            break


if __name__ == "__main__":
    main()
