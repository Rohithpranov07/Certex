# CERTEX

CERTEX is a regular-expression compiler written in Python. Before any input arrives it decides how
expensive a pattern can become, proves it with a working exploit string, and runs every match on a
kernel that cannot blow up. The decision is written into an HMAC-signed certificate and a runtime
governor enforces the certificate's step budget on every match.

```
pattern -> parse -> engine profile -> desugar -> strip groups
        -> M2 type inference | M3 ambiguity (EDA/IDA + attack) | M4a backreference gate
        -> M4b kernel synthesis -> signed certificate -> runtime governor -> match
```

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"            # add ,engines for PCRE2 replay and ,figures for plots
pytest -q                          # fast suite; `pytest -m slow` runs replay and perf guards
```

Python 3.11 or newer. The Java replay target needs a JDK (17 or newer recommended; point
`CERTEX_JAVA` at a specific `java` binary if the default one is older). Configuration lives in
`.env.example` (`CERTEX_KEY`, `CERTEX_PROFILE`, `CERTEX_TIMEOUT`, `CERTEX_BUDGET_C`,
`CERTEX_REPLAY_WALL`).

## Quick start

```bash
certex compile '(a+)+$'            # degree EXP, the attack triple, class, kernel; exit 1
certex compile '^\d+$'             # degree LIN; exit 0
certex compile '(0|[0-9])+$' --profile none      # EXP (what a naive detector reports)
certex compile '(0|[0-9])+$' --profile cpython   # LIN (CPython merges the branches)
certex check patterns.txt          # one pattern per line, or a .py/.js file; exit 0 / 1 / 2
certex match '(\w+)\s\1' 'hello hello'            # matched through the governed kernel
```

`certex check` exit codes: 0 all safe, 1 any EXP/POLY, 2 any parse error or UNKNOWN (2 wins when
both occur). `--json` prints one certificate per pattern.

```python
import certex
c = certex.compile(r"(a+)+$")
c.degree, c.choice.kernel.name, c.types.cls      # ('EXP', 'lazy-dfa', 'EASY')
certex.match(c, "a" * 40 + "b", "full")          # MatchResult(matched=False, kernel='lazy-dfa', ...)
```

## The safety invariant

No CERTEX match ever runs on a backtracking engine. Every match runs on an automaton kernel
(bit-parallel Glushkov / lazy DFA / Aho-Corasick / word-break / Pike VM) under the step budget
`c * (m+1) * (n+1)^power + 64` of a certificate whose signature verifies. When the budget is
exceeded the governor falls back to the linear bit-parallel Glushkov kernel, or rejects
(`on_overrun="reject"`, and always for backreference patterns, which have no fallback). A
tampered certificate raises `CertificateInvalid`. The fault-injection tests run every D1 attack
with a deliberately wrong budget and finish in under a second.

## Reproducing the evidence

```bash
certex bench --all            # E1-E6 -> results/*.json, figures, results/tables.md
certex bench figures          # re-render figures and tables from results/ only
certex bench calibrate --engine pcre2     # or java / cpython -> results/e7_calibration.json
bash demo/demo.sh             # five-step demo; every timing printed is measured by the script
```

E1, E2, E5 and E6 are deterministic (fixed seeds; `meta.date` is the calendar day). E3, E4 and the
timing baseline depend on the machine. Each JSON records CPU, Python and engine versions, seed
and date.

## What the current results say

These are the numbers produced by this repository's own runs (see `results/`):

* D1 (43 patterns: 14 EXP / 10 POLY / 19 LIN): CERTEX with the CPython profile labels 43/43; with
  profile `none` the only error is the false positive `(0|[0-9])+$`.
* D2 (252 generated homogeneous patterns): 252/252.
* Differential test against Python `re` (ASCII; full/match/search) through the governor: 64,800
  cases, 0 disagreements.
* All 24 D1 attacks reproduce on CPython. On PCRE2, 15/24 reproduce as synthesised and 24/24 once
  the suffix keeps the pattern's required final literal; on Java only 2/24 reproduce (see below).

## Limitations

* **Syntax.** Only the v1 subset is supported: lookaround, atomic groups, inline flags, lazy and
  possessive quantifiers, `\b \B \A \Z`, named backreferences and Unicode classes raise
  `UnsupportedSyntax`; `^` and `$` are accepted only at the whole-pattern boundaries (not with a
  top-level `|`); repeat bounds are capped at 1000. Matching is Python `re` semantics on ASCII.
* **Engine profiles.** Only the CPython profile rewrites anything. The PCRE2 and Java profiles are
  the identity: calibration found no pattern rewrite that explains the unconfirmed attacks. PCRE2
  skips a match when a required final literal is absent from the subject (a pre-check, not a
  rewrite); the JDK memoises failed start positions of greedy group loops, which defuses most
  nested-quantifier attacks. See the docstrings of `profiles/pcre2.py` and `profiles/java.py`.
* **Merging of `\D`-style escapes.** CPython also merges `\D \W \S` branches into one class; this
  profile merges only literals and non-negated classes, as specified, so it can report a
  false positive there.
* **Speed.** The kernels are pure Python: on benign input CPython's C engine is far faster. CERTEX
  claims worst-case safety, not raw throughput.
* **Backreferences.** `md_candidate` is a conservative syntactic stand-in for the full memory
  determinism test; the Pike VM bound is `|prog| * (n+1)^(2k)` states per position.
* **Evidence gaps.** The base paper's labels for the D5 cases are not recorded in the data, so
  `results/e6_d5.json` leaves them empty; the six E3 patterns were chosen from D1; the table
  numbers in `results/tables.md` are inferred. The public-corpus experiment is not run yet.
