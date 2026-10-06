#!/usr/bin/env bash
# Five-step CERTEX demo. Every timing printed below is measured by this script, in this run.
# Requires the `certex` command (pip install -e ".[dev]") and `grep`.
set -u
cd "$(dirname "$0")/.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "=== 1. The base paper's timing classifier (grep -E, one benign input) ==="
python - <<'PY'
from certex.bench.baselines import timing_label
label, ratio = timing_label(r"(a+)+$")
print(f"pattern (a+)+$ -> timing label {label} (median elapsed/(m*n) = {ratio:.2e})")
print("It times a benign input, so it cannot see the exponential case below.")
PY

echo
echo "=== 2. CERTEX compile: verdict and exploit before any input arrives ==="
certex compile '(a+)+$'
echo "(exit code $? : 1 means vulnerable)"

echo
echo "=== 3. The exploit on CPython vs. the governed CERTEX kernel (26 characters) ==="
python - <<'PY'
import re, time
import certex
c = certex.compile(r"(a+)+$")
text = "a" * 25 + "b"
t0 = time.perf_counter(); re.match(r"(a+)+$", text); cp = time.perf_counter() - t0
t0 = time.perf_counter(); r = certex.match(c, text, "match"); cx = time.perf_counter() - t0
print(f"CPython re.match : {cp:.3f} s")
print(f"certex.match     : {cx * 1000:.3f} ms  (kernel {r.kernel}, {r.steps} steps, matched={r.matched})")
PY

echo
echo "=== 4. certex check as a CI gate ==="
cat > "$tmp/validators.py" <<'PY'
import re
EMAIL = re.compile(r"^([a-z0-9]+[-_.]?)*[a-z0-9]+@")
DIGITS = re.compile(r"^\d+$")
PY
certex check "$tmp/validators.py"
echo "(exit code $? : 1 blocks the merge)"

echo
echo "=== 5. Engine profiles: (0|[0-9])+\$ ==="
certex compile '(0|[0-9])+$' --profile none | grep -E 'profile|degree'
echo "(exit code ${PIPESTATUS[0]})"
certex compile '(0|[0-9])+$' --profile cpython | grep -E 'profile|degree'
echo "(exit code ${PIPESTATUS[0]})"
