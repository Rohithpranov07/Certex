/* CERTEX demo client. Talks to demo/server.py; every number shown comes from a server response
   (measured live, or read from results/*.json). User text is only ever inserted as text nodes. */
"use strict";

const $ = (id) => document.getElementById(id);
const state = { profile: "cpython", mode: "full", last: null, racing: false };
const PROFILE_NAMES = { cpython: "CPython", pcre2: "PCRE2", java: "Java", none: "No profile" };
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/* ---------- helpers ---------- */
function el(tag, props, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    n.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return n;
}
const code = (s) => el("code", null, s);

async function post(path, body) {
  const res = await fetch(path, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => null);
  if (!data) throw new Error(`The server answered ${res.status} without JSON. Is demo/server.py running?`);
  return data;
}

function fmtSeconds(s) {
  if (s === null || s === undefined) return "—";
  if (s >= 1) return `${s.toFixed(2)} s`;
  if (s >= 1e-3) return `${(s * 1e3).toFixed(1)} ms`;
  return `${(s * 1e6).toFixed(0)} µs`;
}
const fmtInt = (n) => Number(n).toLocaleString("en-US");
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

function setRadio(group, attr, value) {
  for (const b of group.querySelectorAll(".tab")) {
    const on = b.dataset[attr] === value;
    b.setAttribute("aria-checked", String(on));
    b.tabIndex = on ? 0 : -1;
  }
}
function wireRadio(group, attr, onPick) {
  group.addEventListener("click", (e) => {
    const b = e.target.closest(".tab");
    if (b) { setRadio(group, attr, b.dataset[attr]); onPick(b.dataset[attr]); }
  });
  group.addEventListener("keydown", (e) => {
    if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(e.key)) return;
    const tabs = [...group.querySelectorAll(".tab")];
    const i = tabs.findIndex((t) => t.getAttribute("aria-checked") === "true");
    const step = e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 1;
    const next = tabs[(i + step + tabs.length) % tabs.length];
    e.preventDefault();
    next.focus();
    setRadio(group, attr, next.dataset[attr]);
    onPick(next.dataset[attr]);
  });
}

/* ---------- verdict copy ---------- */
function verdictCopy(r) {
  const k = r.kernel;
  const engine = PROFILE_NAMES[r.profile];
  const amb = r.ambiguity;
  const runs = [`CERTEX runs it on `, code(k.name), ` instead, ${k.bound}.`];
  switch (r.degree) {
    case "EXP":
      return { tone: "danger", headline: "Exponential backtracking",
        deck: [`On the attack below, a backtracking engine (${engine} profile) does work that doubles with every extra pump. `, ...runs] };
    case "POLY":
      return { tone: "danger", headline: "Polynomial backtracking",
        deck: [`On long attack inputs a backtracking engine (${engine} profile) slows down polynomially${amb.reason ? `: ${amb.reason}` : ""}. `, ...runs] };
    case "LIN":
      if (amb && amb.unexploitable) {
        return { tone: "safe", headline: "Ambiguous, but not exploitable",
          deck: [`${amb.reason}. No input can force the backtracking blow-up. `, ...runs] };
      }
      return { tone: "safe", headline: "Linear time on every input",
        deck: [`No ambiguity a backtracking engine could exploit. CERTEX still runs it on `, code(k.name), `, ${k.bound}.`] };
    case "UNKNOWN":
      return { tone: "neutral", headline: "Analysis gave up",
        deck: [`${(amb && amb.reason) || "The analysis hit its time limit"}. CERTEX still runs it on `, code(k.name), ` under a step budget, so it cannot hang.`] };
    default: {
      const b = r.backrefs;
      return { tone: "neutral", headline: "Backreferences",
        deck: [`Ambiguity analysis does not apply to backreferences. The gate tracks ${plural(b.k, "group", "groups")} and runs a memory-aware Pike VM, ${b.bound}. On overrun it rejects rather than fall back.`] };
    }
  }
}

/* ---------- pipeline rail ---------- */
function step(stamp, kicker, headline, deck, extra, flavour) {
  return el("li", { class: `step${flavour ? ` step--${flavour}` : ""}` },
    el("p", { class: "step__stamp", text: stamp }),
    el("div", { class: "step__card" },
      el("p", { class: "step__kicker", text: kicker }),
      el("p", { class: "step__headline" }, headline),
      deck ? el("p", { class: "step__deck" }, deck) : null,
      extra || null));
}
function kv(pairs) {
  const dl = el("dl", { class: "kv" });
  for (const [k, v] of pairs) {
    if (v === null || v === undefined || v === "") continue;
    dl.append(el("dt", { text: k }), el("dd", null, v));
  }
  return dl;
}

function renderStream(r) {
  const ol = $("stream");
  ol.replaceChildren();
  const anchors = [r.anchored.start && "start", r.anchored.end && "end"].filter(Boolean);
  ol.append(step("Parse", "v1 syntax subset",
    [`${plural(r.groups, "capture group", "capture groups")}`],
    anchors.length ? `Anchored at the ${anchors.join(" and ")}.` : "Unanchored.", null, "ok"));

  const rewrite = r.profile === "none"
    ? "No engine rewrites. This is what a naive detector would analyse."
    : `What the ${PROFILE_NAMES[r.profile]} engine actually compiles, after its own rewrites and with sugar like ? and {m,n} expanded.`;
  ol.append(step("Profile", `${PROFILE_NAMES[r.profile]} → desugar → strip groups`,
    [code(r.core || "ε")], rewrite, kv([["positions m", String(r.m)]])));

  const t = r.types;
  ol.append(step("M2", "Type inference · SETH class",
    [`${t.cls} `, el("span", { class: "muted", text: t.bound })],
    t.homogeneous ? "Homogeneous pattern: its operator type decides the fine-grained class." : "Not homogeneous: the general bound applies.",
    kv([["raw type", t.raw_type], ["normalised", t.normalised], ["hard core", t.hard_core]])));

  if (r.ambiguity) {
    const a = r.ambiguity;
    ol.append(step("M3", "Ambiguity · EDA / IDA",
      [a.degree], a.reason || (a.degree === "LIN" ? "No exploitable ambiguity found." : null),
      a.attack ? kv([["prefix", code(a.attack.prefix)], ["pump", code(a.attack.pump)], ["suffix", code(a.attack.suffix)]]) : null,
      r.vulnerable ? "flag" : a.degree === "LIN" ? "ok" : null));
  } else {
    ol.append(step("M3", "Ambiguity · EDA / IDA", ["Not applicable"],
      "Backreferences make the language non-regular, so M4a decides instead.", null, "skip"));
  }

  if (r.backrefs) {
    const b = r.backrefs;
    ol.append(step("M4a", "Backreference gate", [`Groups ${b.vars.join(", ")} · k = ${b.k}`],
      b.md_candidate ? "No referenced group is redefined inside a loop: tractable." : "A referenced group is redefined inside a loop.",
      kv([["redefined", b.redefined.length ? b.redefined.join(", ") : "none"], ["bound", b.bound]])));
  } else {
    ol.append(step("M4a", "Backreference gate", ["No backreferences"], null, null, "skip"));
  }

  const k = r.kernel;
  const bud = k.budget;
  ol.append(step("M4b", "Kernel synthesis", [code(k.name)], k.rule,
    kv([["fallback", k.fallback ? code(k.fallback) : "none (rejects on overrun)"], ["bound", k.bound],
        ["budget", `${bud.c} · (${bud.m}+1) · (n+1)^${bud.power} + 64 steps`]]), "ok"));

  ol.append(step("Sign", "HMAC certificate",
    [r.signature_ok ? "Signature verifies" : "Signature does not verify"],
    r.dev_key ? "Signed with the development key. Set CERTEX_KEY to sign with your own." : "Signed with CERTEX_KEY.",
    kv([["sha-256", code(String(r.certificate.pattern_sha256).slice(0, 16) + "…")], ["compile", `${r.compile_ms} ms`]]),
    r.signature_ok ? "ok" : "flag"));
}

/* ---------- certificate ---------- */
function highlightJSON(obj) {
  const frag = document.createDocumentFragment();
  const json = JSON.stringify(obj, null, 2);
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
  let last = 0;
  for (const m of json.matchAll(re)) {
    frag.append(json.slice(last, m.index));
    const cls = m[1] ? (m[2] ? "j-key" : "j-str") : m[3] ? "j-lit" : "j-num";
    frag.append(el("span", { class: cls, text: m[1] || m[0] }));
    if (m[2]) frag.append(m[2]);
    last = m.index + m[0].length;
  }
  frag.append(json.slice(last));
  return frag;
}

function renderCertificate(r) {
  $("cert-json").replaceChildren(highlightJSON(r.certificate));
  const status = $("cert-status");
  status.textContent = r.signature_ok
    ? `Signature verifies${r.dev_key ? " · development key" : ""}`
    : "Signature does not verify";
  status.classList.toggle("is-ok", r.signature_ok);
  $("copy-cert").disabled = false;
  $("download-cert").disabled = false;
}

/* ---------- analyze ---------- */
function showError(err, pattern) {
  const box = $("pattern-error");
  box.replaceChildren();
  $("pattern").setAttribute("aria-invalid", "true");
  document.querySelector(".pattern-row").classList.add("is-error");
  if (typeof err.offset === "number") {
    const at = Math.min(err.offset, pattern.length);
    const bad = pattern.slice(at, at + 1) || "end";
    box.append(`${err.kind === "UnsupportedSyntax" ? "Not supported" : "Cannot parse"}: ${err.message} at offset ${err.offset}. `,
      el("span", { class: "caret" }, el("code", { class: "caret__ok", text: pattern.slice(0, at) }), code(bad)));
  } else {
    box.append(err.message);
  }
  box.hidden = false;
  clearReport();
}

/* A failed analysis must not leave the previous pattern's report on screen. */
function clearReport() {
  state.last = null;
  $("verdict").hidden = true;
  $("stream").hidden = true;
  $("report-empty").hidden = false;
  $("report-empty-title").textContent = "No report: the pattern above did not compile.";
  $("report-empty-deck").textContent = "Fix the pattern at the marked offset, or pick an example.";
  $("cert-json").textContent = "No certificate: nothing compiled.";
  const status = $("cert-status");
  status.textContent = "No certificate";
  status.classList.remove("is-ok");
  $("copy-cert").disabled = true;
  $("download-cert").disabled = true;
  $("race-body").hidden = true;
  $("race-empty").hidden = false;
  $("race-empty-title").textContent = "Analyze a pattern first.";
  $("race-empty-deck").textContent = "Only exponential and polynomial patterns have an attack to run.";
  $("match-result").textContent = "";
}
function clearError() {
  $("pattern-error").hidden = true;
  $("pattern").removeAttribute("aria-invalid");
  document.querySelector(".pattern-row").classList.remove("is-error");
}

async function analyze() {
  const pattern = $("pattern").value;
  const btn = $("analyze-btn");
  btn.classList.add("is-busy");
  btn.textContent = "Analyzing…";
  clearError();
  try {
    const r = await post("/api/compile", { pattern, profile: state.profile });
    if (!r.ok) { showError(r.error, pattern); return; }
    state.last = r;
    const url = new URL(location.href);
    url.searchParams.set("p", pattern);
    url.searchParams.set("profile", state.profile);
    history.replaceState(null, "", url);
    renderReport(r);
    renderCertificate(r);
    prepareRace(r);
  } catch (e) {
    showError({ message: e.message }, pattern);
  } finally {
    btn.classList.remove("is-busy");
    btn.textContent = "Analyze pattern";
  }
}

function renderReport(r) {
  $("report-empty").hidden = true;
  const v = $("verdict");
  const copy = verdictCopy(r);
  v.dataset.tone = copy.tone;
  $("verdict-tag").textContent = `${PROFILE_NAMES[r.profile]} profile`;
  $("verdict-degree").textContent = r.degree;
  $("verdict-headline").textContent = copy.headline;
  $("verdict-deck").replaceChildren(...copy.deck.map((d) => (d instanceof Node ? d : document.createTextNode(d))));

  const atk = r.ambiguity && r.ambiguity.attack;
  $("attack").hidden = !atk;
  if (atk) {
    $("attack-prefix").textContent = JSON.stringify(atk.prefix);
    $("attack-pump").textContent = JSON.stringify(atk.pump);
    $("attack-suffix").textContent = JSON.stringify(atk.suffix);
    $("attack-example").textContent = JSON.stringify(atk.example);
  }
  v.hidden = false;
  if (!reduceMotion) {
    v.classList.remove("is-entering");
    void v.offsetWidth;
    v.classList.add("is-entering");
  }
  renderStream(r);
  $("stream").hidden = false;
}

/* ---------- race ---------- */
function prepareRace(r) {
  const atk = r.ambiguity && r.ambiguity.attack;
  $("race-body").hidden = !atk;
  $("race-empty").hidden = !!atk;
  resetLanes();
  if (!atk) {
    $("race-empty-title").textContent = r.degree === "N/A"
      ? "Nothing to race: backreference patterns have no synthesised attack."
      : `Nothing to race: this pattern is ${r.degree === "LIN" ? "linear" : "unresolved"} (${r.degree}).`;
    $("race-empty-deck").textContent = "Only exponential and polynomial patterns come with an attack string. Try the Nested repeat or Quadratic example.";
    return;
  }
  const slider = $("pump");
  // Exponential blow-up shows within a few dozen pumps; polynomial needs thousands.
  if (r.degree === "EXP") { slider.min = 1; slider.max = 32; slider.step = 1; slider.value = 24; }
  else { slider.min = 1000; slider.max = 30000; slider.step = 1000; slider.value = 15000; }
  updatePump();
}
function updatePump() {
  const k = Number($("pump").value);
  $("pump-out").textContent = String(k);
  const a = state.last && state.last.ambiguity && state.last.ambiguity.attack;
  if (a) {
    const n = a.prefix.length + a.pump.length * k + a.suffix.length;
    $("pump-length").textContent = `Input length ${fmtInt(n)} characters.`;
  }
}
function resetLanes() {
  for (const id of ["cp", "cx"]) {
    $(`${id}-time`).textContent = "—";
    $(`${id}-bar`).style.width = "0";
    $(`${id}-meta`).textContent = "Not run yet";
  }
  $("race-ratio").textContent = "";
}

async function race() {
  if (state.racing || !state.last) return;
  state.racing = true;
  const btn = $("race-btn");
  btn.classList.add("is-busy");
  btn.textContent = "Running…";
  resetLanes();
  $("cp-meta").textContent = "Waiting for CPython…";
  $("cx-meta").textContent = "Waiting for CPython to finish…";
  // A visible clock while the request is pending: wall time seen by this browser, not a result.
  const t0 = performance.now();
  const tick = setInterval(() => {
    $("cp-time").textContent = `${((performance.now() - t0) / 1000).toFixed(1)} s`;
  }, 100);
  try {
    const r = await post("/api/race", { pattern: state.last.pattern, profile: state.last.profile, k: Number($("pump").value) });
    clearInterval(tick);
    if (!r.ok) { $("cp-time").textContent = "—"; $("cp-meta").textContent = r.error.message; $("cx-meta").textContent = ""; return; }
    const cp = r.cpython, cx = r.certex;
    const cpS = cp.killed ? cp.wall : cp.seconds;
    $("cp-time").textContent = cp.killed ? `> ${cp.wall} s` : fmtSeconds(cp.seconds);
    $("cp-meta").textContent = cp.killed
      ? `Still backtracking after ${cp.wall} s on ${fmtInt(r.length)} characters. The process was killed.`
      : cp.error ? `CPython error: ${cp.error}` : `re.fullmatch on ${fmtInt(r.length)} characters.`;
    $("cx-time").textContent = fmtSeconds(cx.seconds);
    $("cx-meta").textContent = `${cx.matched ? "Matched" : "No match"} on ${cx.kernel}${cx.fell_back ? " (fell back)" : ""}: ${fmtInt(cx.steps)} of ${fmtInt(cx.budget)} budgeted steps.`;
    if (cpS) {
      $("cp-bar").style.width = "100%";
      $("cx-bar").style.width = `${Math.max(0.6, (cx.seconds / cpS) * 100)}%`;
      const ratio = cpS / cx.seconds;
      $("race-ratio").textContent = ratio >= 1
        ? `CPython took ${ratio >= 100 ? fmtInt(Math.round(ratio)) : ratio.toFixed(1)}× longer${cp.killed ? " before it was stopped" : ""}.`
        : state.last.profile !== "cpython"
          ? `CPython is not slowed down: its own rewrites remove the ambiguity the ${PROFILE_NAMES[state.last.profile]} analysis reports. Analyze with the CPython profile to see this.`
          : "At this size CPython is still faster. Raise the pump count.";
    }
  } catch (e) {
    clearInterval(tick);
    $("cp-meta").textContent = e.message;
  } finally {
    state.racing = false;
    btn.classList.remove("is-busy");
    btn.textContent = "Run both engines";
  }
}

/* ---------- match ---------- */
async function matchText(ev) {
  ev.preventDefault();
  const out = $("match-result");
  if (!state.last) { out.textContent = "Analyze a pattern first; the match runs under its certificate."; return; }
  out.textContent = "Matching…";
  try {
    const r = await post("/api/match", { pattern: state.last.pattern, profile: state.last.profile, text: $("match-text").value, mode: state.mode });
    if (!r.ok) { out.textContent = `${r.error.kind}: ${r.error.message}`; return; }
    out.replaceChildren(
      el("span", { class: `pill${r.matched ? "" : " pill--no"}`, text: r.matched ? "Match" : "No match" }),
      code(r.kernel),
      ` · ${fmtInt(r.steps)} of ${fmtInt(r.budget)} budgeted steps · ${r.ms} ms${r.fell_back ? " · fell back to the linear kernel" : ""}`);
  } catch (e) {
    out.textContent = e.message;
  }
}

/* ---------- evidence ---------- */
function tile(variant, tag, num, headline, deck, wide) {
  return el("article", { class: `tile tile--${variant}${wide ? ` tile--${wide}` : ""}` },
    el("p", { class: "pill", text: tag }),
    num !== null ? el("p", { class: "tile__num", text: num }) : null,
    el("p", { class: "tile__headline" }, headline),
    deck ? el("p", { class: "tile__deck" }, deck) : null);
}

async function loadEvidence() {
  const box = $("tiles");
  let ev;
  try {
    ev = await (await fetch("/api/evidence")).json();
  } catch {
    box.replaceChildren(el("p", { class: "body-compact muted", text: "Could not reach demo/server.py, so no results to show." }));
    return;
  }
  const tiles = [];
  if (ev.d1) {
    const c = ev.d1.certex_cpython, n = ev.d1.certex_none, s = ev.d1.star_height;
    tiles.push(tile("mint", "D1 · ReDoS benchmark", `${c.labels_exact ?? c.tp + c.tn}/${c.n}`,
      "Patterns labelled exactly with the CPython profile",
      `Accuracy ${c.accuracy}. Without the profile: ${n.accuracy}. A star-height ≥ 2 check: ${s.accuracy}.`));
  }
  if (ev.differential) {
    const d = ev.differential;
    tiles.push(tile("violet", "Differential test", fmtInt(d.disagreements),
      `Disagreements with Python re in ${fmtInt(d.cases)} cases`,
      `${d.patterns} patterns, full / match / search modes, every match through the governor.`));
  }
  if (ev.corpus) {
    const c = ev.corpus;
    tiles.push(tile("white", "PyPI corpus", fmtInt(c.patterns_total),
      "Real-world patterns scanned",
      `${fmtInt(c.analysed)} analysed, ${fmtInt(c.flagged_total)} flagged. ${c.replay_confirmed} of ${c.replay_sample} sampled flags reproduced on CPython (precision ${c.precision_estimate}). Mean analysis ${c.analysis_mean_ms} ms.`));
  }
  if (ev.d2) {
    tiles.push(tile("line", "D2 · type inference", `${ev.d2.correct}/${ev.d2.total}`,
      "Generated patterns given the right SETH class", null));
  }
  if (ev.e3) {
    const rows = ev.e3.patterns.map((p) => el("tr", null,
      el("td", null, code(p.pattern)),
      el("td", { class: "num", text: String(p.length) }),
      el("td", { class: "num", text: fmtSeconds(p.cpython_s) }),
      el("td", { class: "num", text: fmtSeconds(p.certex_s) }),
      el("td", { class: "num speedup", text: `${fmtInt(Math.round(p.cpython_s / p.certex_s))}×` })));
    const table = el("table", { class: "e3" },
      el("thead", null, el("tr", null,
        el("th", { scope: "col", text: "Pattern" }), el("th", { scope: "col", class: "num", text: "Input" }),
        el("th", { scope: "col", class: "num", text: "CPython" }), el("th", { scope: "col", class: "num", text: "CERTEX" }),
        el("th", { scope: "col", class: "num", text: "Ratio" }))),
      el("tbody", null, rows));
    const m = ev.e3.meta;
    tiles.push(el("article", { class: "tile tile--line tile--full" },
      el("p", { class: "pill", text: "E3 · attack runtime" }),
      el("p", { class: "tile__headline", text: "Six D1 attacks, CPython re against the CERTEX kernel" }),
      el("div", { class: "table-wrap" }, table),
      el("p", { class: "tile__deck muted", text: `Measured on ${m.cpu}, Python ${m.python}, ${m.date}. Machine dependent; rerun with certex bench --all.` })));
  }
  if (ev.d1 && ev.d1.meta) {
    const m = ev.d1.meta;
    $("evidence-meta").replaceChildren("Read live from ", code("results/*.json"), `, last produced on ${m.date} (${m.cpu}, Python ${m.python}) by `, code("certex bench --all"), ".");
  }
  box.replaceChildren(...(tiles.length ? tiles : [el("p", { class: "body-compact muted", text: "No results files found. Run certex bench --all." })]));
}

/* ---------- nav highlight ---------- */
function watchSections() {
  const links = new Map([...document.querySelectorAll(".mono-link")].map((a) => [a.getAttribute("href").slice(1), a]));
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (!e.isIntersecting) continue;
      for (const a of links.values()) a.classList.remove("is-active");
      const a = links.get(e.target.id);
      if (a) a.classList.add("is-active");
    }
  }, { rootMargin: "-40% 0px -55% 0px" });
  for (const id of links.keys()) { const s = $(id); if (s) io.observe(s); }
}

/* ---------- wire up ---------- */
function init() {
  wireRadio($("profile-tabs"), "profile", (p) => { state.profile = p; if (state.last) analyze(); });
  wireRadio($("mode-tabs"), "mode", (m) => { state.mode = m; });
  setRadio($("profile-tabs"), "profile", state.profile);
  setRadio($("mode-tabs"), "mode", state.mode);

  $("analyzer").addEventListener("submit", (e) => { e.preventDefault(); analyze(); });
  $("pattern").addEventListener("input", clearError);
  $("examples").addEventListener("click", (e) => {
    const b = e.target.closest(".chip");
    if (!b) return;
    $("pattern").value = b.dataset.pattern;
    state.profile = b.dataset.profile;
    setRadio($("profile-tabs"), "profile", state.profile);
    analyze();
  });
  $("pump").addEventListener("input", updatePump);
  $("race-btn").addEventListener("click", race);
  $("matchbox").addEventListener("submit", matchText);

  $("copy-cert").addEventListener("click", async () => {
    if (!state.last) return;
    const btn = $("copy-cert");
    try {
      await navigator.clipboard.writeText(JSON.stringify(state.last.certificate, null, 2));
      btn.textContent = "Copied";
    } catch {
      btn.textContent = "Copy blocked";
    }
    setTimeout(() => { btn.textContent = "Copy JSON"; }, 1600);
  });
  $("download-cert").addEventListener("click", () => {
    if (!state.last) return;
    const blob = new Blob([JSON.stringify(state.last.certificate, null, 2) + "\n"], { type: "application/json" });
    const a = el("a", { href: URL.createObjectURL(blob), download: "certificate.json" });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });

  const q = new URLSearchParams(location.search);
  if (q.has("p")) $("pattern").value = q.get("p");
  if (q.has("profile") && PROFILE_NAMES[q.get("profile")]) {
    state.profile = q.get("profile");
    setRadio($("profile-tabs"), "profile", state.profile);
  }
  watchSections();
  loadEvidence();
  analyze();
}

document.addEventListener("DOMContentLoaded", init);
