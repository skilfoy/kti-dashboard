#!/usr/bin/env python3
"""Validate the analyst-authored datasets, rebuild their derived display fields, and append a hash-chained ledger entry.

Run: python3 -I pipeline/authored_build.py DIR [--kind "Daily reassessment"] [--catalogs FEEDS/catalogs.json]
     python3 -I pipeline/authored_build.py DIR --check
DIR holds the authored datasets (data/authored). The daily reassessment edits them in place and then runs the first
form, which rewrites them with their derived fields and appends a ledger entry. --check is what the site workflow runs
before every deploy: it validates, verifies the ledger's hash chain, and confirms the files on disk are exactly what
this script would write, without writing anything. The validator holds final authority over a run (Fleurat et al.
ch5, ch16): any failure exits non-zero and nothing ships.

Two datasets are kept by this script and never edited by hand:
  history.json   the change log: one event per change of a tracked value (theater level and trend, judgment title,
                 likelihood, severity, status, rank and horizon, indicator state, vector level and trend), stamped
                 with the run that made it. --check fails when a tracked value differs from the log, so a level or a
                 judgment cannot move without a run recording it.
  outcomes.json  the forecast record: one row per judgment horizon that has passed, with the outcome and the cited
                 items behind it. The analyst writes the row; this script derives its probability and Brier score.
Currency rules (review cadence, judgment horizons, requirement reviews) depend on today's date. They gate a
reassessment (the first form) and print as warnings under --check, so an overdue review never blocks a feed deploy.
"""
import datetime as dt
import glob
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]


def opt(name, default=""):
    if name in args:
        k = args.index(name)
        v = args[k + 1]
        del args[k:k + 2]
        return v
    return default


CHECK = "--check" in args
if CHECK:
    args.remove("--check")
KIND = opt("--kind", "Run")
CATALOGS = opt("--catalogs", "")
OUT = args[0]
FROM_JSON = OUT

# The datasets as published; derived display fields are rebuilt below.
load = lambda n: json.load(open(os.path.join(FROM_JSON, n), encoding="utf-8"))
S = [s for s in load("sources.json") if not s["source_id"].startswith("GAP-")]
I = [{k: v for k, v in r.items() if k not in ("source_name", "theater_name", "grade")} for r in load("items.json")]
T = load("theaters.json")
IND = [{k: v for k, v in r.items() if k != "theater_name"} for r in load("theater_indicators.json")]
J = load("judgments.json")
E = [{k: v for k, v in r.items() if k not in ("item_title", "source_name", "grade", "url", "date")} for r in load("evidence.json")]
V = load("vectors.json")
P = load("pirs.json")
C = [{k: v for k, v in r.items() if k != "source_name"} for r in load("collection_matrix.json")]
M = load("method.json")
F = load("followons.json")
VE = load("verticals.json")
if os.path.exists(os.path.join(FROM_JSON, "chokepoints.json")):
    CP = load("chokepoints.json")
else:  # seed from the authored module
    sys.path.insert(0, HERE)
    from authored_chokepoints import CHOKEPOINTS as CP  # noqa: E402
HIST = load("history.json") if os.path.exists(os.path.join(FROM_JSON, "history.json")) else []
OUTC = [{k: v for k, v in r.items() if k not in ("judgment_title", "p", "brier")} for r in load("outcomes.json")] if os.path.exists(os.path.join(FROM_JSON, "outcomes.json")) else []
LEADS = load("leads.json") if os.path.exists(os.path.join(FROM_JSON, "leads.json")) else []
for t in T:  # derived below from last_reviewed and the level's cadence
    t.pop("review_by", None)
for j in J:  # keep the action line consistent with its parts
    j["cta"] = f"{j['stakeholder']} needs to {j['action']} within {j['timeframe']}."
NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

for gid, name, note in [("GAP-TEL", "Internal telemetry (SIEM, EDR, identity provider)", "Not connected"),
                        ("GAP-ASSET", "Asset inventory", "Not connected"),
                        ("GAP-DEEPFAKE", "Deepfake and voice-clone fraud reporting", "No source selected")]:
    if not any(s["source_id"] == gid for s in S):
        S.append({"source_id": gid, "name": name, "url": "", "owner_type": "Gap", "tier": "", "reliability": "",
                  "default_credibility": None, "validity": "", "collection_method": "", "maintenance": "",
                  "provider_bias": "", "time_contract": "", "cadence": "", "status": note, "used_for": "Collection gap",
                  **{k: "" for k in ["crit_timeliness", "crit_relevancy", "crit_accuracy", "crit_context", "crit_format", "crit_enrichment", "crit_licensing"]}})

errors, checks = [], 0


def check(cond, msg):
    global checks
    checks += 1
    if not cond:
        errors.append(msg)


warnings = []


def due(cond, msg):
    """A currency rule: fails a reassessment, warns under --check (see the module note)."""
    if CHECK:
        if not cond:
            warnings.append(msg)
    else:
        check(cond, msg)


TODAY = NOW.date()
EXCERPT_FROM = 1126  # items numbered from here carry an excerpt and a fetch time
norm_txt = lambda s: re.sub(r"\W+", " ", str(s).lower()).strip()
day = lambda s: dt.date.fromisoformat(s)
# Days a theater may go without review, by ThreatCon level; review_by is last_reviewed plus this.
CADENCE = {5: 2, 4: 2, 3: 4, 2: 7, 1: 7}
LIKELIHOODS = {"Almost no chance", "Very unlikely", "Unlikely", "Roughly even chance", "Likely", "Very likely", "Almost certain"}
ids = lambda rows, k: [r[k] for r in rows]
src_ids = set(ids(S, "source_id"))
item_ids = set(ids(I, "item_id"))
th_ids = set(ids(T, "theater_id")) | {"T-GLB"}
j_ids = set(ids(J, "judgment_id"))
pir_ids = set(ids(P, "pir_id"))
VEC = {"", "Exploitation & edge devices", "Identity & valid accounts", "Phishing & social engineering", "Ransomware & malware",
       "DDoS", "Fraud", "Insider", "Supply chain"}
CATS = {"Official", "Industry", "Media", "Research", "Party claim", "Reference", "Feed data"}
VERS = {"Claimed", "Reported", "Corroborated", "Confirmed", "Denied"}
iso = re.compile(r"^\d{4}-\d{2}-\d{2}$")

for name, rows, key in [("sources", S, "source_id"), ("items", I, "item_id"), ("theaters", T, "theater_id"),
                        ("indicators", IND, "ind_id"), ("judgments", J, "judgment_id"), ("evidence", E, "evid_id"),
                        ("vectors", V, "vector_id"), ("pirs", P, "pir_id"), ("matrix", C, "cell"), ("method", M, "rule_id"),
                        ("followons", F, "fp_id")]:
    check(len(ids(rows, key)) == len(set(ids(rows, key))), f"{name}: duplicate {key}")

for it in I:
    check(it["source_id"] in src_ids, f"{it['item_id']}: unknown source {it['source_id']}")
    check(it["url"].startswith("https://"), f"{it['item_id']}: missing https URL")
    check(it["theater_id"] in th_ids, f"{it['item_id']}: unknown theater {it['theater_id']}")
    check(it["vector"] in VEC, f"{it['item_id']}: unknown vector {it['vector']}")
    check(it["reliability"] in "ABCDEF" and len(it["reliability"]) == 1, f"{it['item_id']}: bad reliability")
    check(it["credibility"] in (1, 2, 3, 4, 5, 6), f"{it['item_id']}: bad credibility")
    check(it["category"] in CATS, f"{it['item_id']}: bad category")
    check(it["veracity"] in VERS, f"{it['item_id']}: bad veracity")
    check(bool(iso.match(it["date"])) and bool(iso.match(it["reported"])), f"{it['item_id']}: date not ISO")
    check(it["date"] <= NOW.date().isoformat(), f"{it['item_id']}: date in the future")
    if it["category"] == "Party claim" and it["veracity"] == "Claimed":
        check(it["reliability"] in "CDEF", f"{it['item_id']}: party claim graded above C")
    check(it["lane"] in ("Event", "Statement", "Disruption"), f"{it['item_id']}: bad lane {it['lane']}")
    check(it["date_precision"] in ("day", "week", "month", "approximate"), f"{it['item_id']}: bad date_precision {it['date_precision']}")
    check(it["reported"] <= TODAY.isoformat(), f"{it['item_id']}: reported date in the future")
    check(len(it["title"]) <= 500, f"{it['item_id']}: title over 500 characters")
    check(bool(it["origin"].strip()), f"{it['item_id']}: no origin")
    # Proof of reading (release 2.2): every item added from I-1126 on carries a sentence copied from the cited page
    # and the time the page was read. pipeline/verify_citations.py fetches the page in the site workflow and checks
    # that the sentence is on it; the excerpt stays in this repository and is left out of the published data.
    if int(it["item_id"].split("-")[1]) >= EXCERPT_FROM:
        ex = str(it.get("excerpt") or "")
        check(60 <= len(ex) <= 400, f"{it['item_id']}: needs an excerpt of 60 to 400 characters copied from the cited page")
        check(norm_txt(ex) != norm_txt(it["title"]), f"{it['item_id']}: the excerpt is the page's wording, not the item title")
        check(bool(re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?Z$", str(it.get("fetched_at") or ""))), f"{it['item_id']}: needs fetched_at, the UTC time the page was read (YYYY-MM-DDTHH:MMZ)")
    # A headline seen only in search results is credibility 3 (runbook standing rules).
    if it["title"].rstrip(". ").endswith(", headline"):
        check(it["credibility"] >= 3, f"{it['item_id']}: a headline-only item is graded credibility 3 or lower")
for ind in IND:
    check(ind["theater_id"] in th_ids, f"{ind['ind_id']}: unknown theater")
    check(ind["state"] in ("Not observed", "Emerging", "Observed", "Confirmed"), f"{ind['ind_id']}: bad state")
    check(ind["item_id"] == "" or ind["item_id"] in item_ids, f"{ind['ind_id']}: unknown item {ind['item_id']}")
    if ind["state"] in ("Observed", "Confirmed"):
        check(ind["item_id"] != "", f"{ind['ind_id']}: observed without a cited item")
for t in T:
    check(t["judgment_id"] == "" or t["judgment_id"] in j_ids, f"{t['theater_id']}: unknown judgment")
    check(1 <= t["threatcon"] <= 5, f"{t['theater_id']}: threatcon out of range")
    check(any(i["theater_id"] == t["theater_id"] for i in I), f"{t['theater_id']}: no cited item")
    check(bool(iso.match(str(t.get("last_reviewed", "")))) and t["last_reviewed"] <= TODAY.isoformat(), f"{t['theater_id']}: last_reviewed missing or in the future")
    check(t["trend"] in ("Escalating", "Stable", "De-escalating"), f"{t['theater_id']}: bad trend {t['trend']}")
    # The basis is the current rationale, not a running log; the change log and the items keep the history.
    check(len(t["basis"]) <= 3500, f"{t['theater_id']}: basis over 3,500 characters (keep the standing rationale and the newest developments)")
    if iso.match(str(t.get("last_reviewed", ""))):
        t["review_by"] = (day(t["last_reviewed"]) + dt.timedelta(days=CADENCE[t["threatcon"]])).isoformat() if 1 <= t["threatcon"] <= 5 else ""
        due(TODAY.isoformat() <= t["review_by"], f"{t['theater_id']}: review overdue (ThreatCon {t['threatcon']} is reviewed every {CADENCE.get(t['threatcon'])} days; last reviewed {t['last_reviewed']})")
for j in J:
    sup = [e for e in E if e["judgment_id"] == j["judgment_id"] and e["role"] == "Supports"]
    check(len(sup) >= 1, f"{j['judgment_id']}: no supporting evidence")
    for p in [x.strip() for x in j["pirs"].split(",") if x.strip()]:
        check(p in pir_ids, f"{j['judgment_id']}: unknown PIR {p}")
    retired = j.get("status") == "Retired"
    check(j["likelihood"] in LIKELIHOODS, f"{j['judgment_id']}: likelihood is not an ICD-203 term")
    check(j.get("status") in ("Maintained", "Raised", "Lowered", "New", "Retired"), f"{j['judgment_id']}: bad status {j.get('status')}")
    check(not retired or j["exec_rank"] == 0, f"{j['judgment_id']}: a retired judgment keeps exec_rank 0")
    # Every live judgment names the date by which it is scored: a forecast with no horizon cannot be wrong.
    if not retired:
        check(bool(iso.match(str(j.get("horizon", "")))), f"{j['judgment_id']}: needs a horizon (ISO date by which the judgment is scored)")
        if iso.match(str(j.get("horizon", ""))):
            due(j["horizon"] >= TODAY.isoformat(), f"{j['judgment_id']}: horizon {j['horizon']} has passed; record the outcome in outcomes.json, then set a new horizon or retire the judgment")
            check(j["horizon"] > j["opened"], f"{j['judgment_id']}: horizon not after the opening date")
        if j["exec_rank"] > 0 and iso.match(str(j.get("last_reviewed", ""))):
            due((TODAY - day(j["last_reviewed"])).days <= 7, f"{j['judgment_id']}: a ranked judgment is reviewed at least weekly (last reviewed {j['last_reviewed']})")
check(len([j for j in J if j["exec_rank"] > 0]) >= 1, "no executive judgments ranked")
# The forecast record: one row per horizon that has passed.
check(len(ids(OUTC, "outcome_id")) == len(set(ids(OUTC, "outcome_id"))), "outcomes: duplicate outcome_id")
_range = re.compile(r"^(\d{1,3})-(\d{1,3})%$")
for o in OUTC:
    oid = o.get("outcome_id")
    check(o.get("judgment_id") in j_ids, f"{oid}: unknown judgment {o.get('judgment_id')}")
    check(o.get("outcome") in ("Held", "Did not hold", "Indeterminate"), f"{oid}: outcome must be Held, Did not hold or Indeterminate")
    check(o.get("likelihood") in LIKELIHOODS and bool(_range.match(str(o.get("probability", "")))), f"{oid}: needs the ICD-203 term and probability range in force at the horizon")
    check(all(iso.match(str(o.get(k, ""))) for k in ("opened", "horizon", "resolved")), f"{oid}: opened, horizon and resolved must be ISO dates")
    if all(iso.match(str(o.get(k, ""))) for k in ("opened", "horizon", "resolved")):
        check(o["opened"] < o["horizon"] <= o["resolved"] <= TODAY.isoformat(), f"{oid}: dates must run opened < horizon <= resolved <= today")
    refs = [x.strip() for x in str(o.get("item_ids", "")).split(",") if x.strip()]
    check(len(refs) >= 1 and all(x in item_ids for x in refs), f"{oid}: needs at least one cited item, each in items.json")
    check(len(str(o.get("statement", ""))) >= 20 and len(str(o.get("basis", ""))) >= 20, f"{oid}: needs the judged statement and the basis for the outcome")
# Lead feedback: what the analyst run did with each machine lead it opened (triage or advisory). The record is the
# triage tier's precision at the analyst's budget, so a row is written for a rejected lead as well as a used one.
check(len(ids(LEADS, "lead_id")) == len(set(ids(LEADS, "lead_id"))), "leads: duplicate lead_id")
check(len({(l.get("link"), l.get("date")) for l in LEADS}) == len(LEADS), "leads: the same link is recorded twice on one day")
for l in LEADS:
    lid = l.get("lead_id")
    check(bool(re.match(r"^L-\d{4,}$", str(lid))), f"{lid}: lead_id must look like L-0001")
    check(bool(iso.match(str(l.get("date", "")))) and str(l.get("date")) <= TODAY.isoformat(), f"{lid}: date must be an ISO date, today or earlier")
    check(str(l.get("link", "")).startswith("https://"), f"{lid}: link must be the lead's https URL")
    check(l.get("source") in ("triage", "psirt"), f"{lid}: source must be triage or psirt")
    check(l.get("disposition") in ("used", "duplicate", "rejected", "wrong"), f"{lid}: disposition must be used, duplicate, rejected or wrong")
    refs = [x.strip() for x in str(l.get("item_ids", "")).split(",") if x.strip()]
    check(all(x in item_ids for x in refs), f"{lid}: item_ids must be in items.json")
    if l.get("disposition") in ("used", "duplicate"):
        check(len(refs) >= 1, f"{lid}: a used or duplicate lead names the item that carries the event")
    check(10 <= len(str(l.get("reason", ""))) <= 240, f"{lid}: reason is one sentence, 10 to 240 characters")
    check(8 <= len(str(l.get("title", ""))) <= 300, f"{lid}: title is the lead's headline")
    check(l.get("relevance") in (None, 0, 1, 2, 3), f"{lid}: relevance is the tier's 0 to 3 label when it had one")
for p in P:
    if iso.match(str(p.get("last_reviewed", ""))):
        due((TODAY - day(p["last_reviewed"])).days <= 35, f"{p['pir_id']}: requirement review overdue (last reviewed {p['last_reviewed']}; reviewed at least every 35 days)")
for e in E:
    check(e["item_id"] in item_ids, f"{e['evid_id']}: unknown item {e['item_id']}")
    check(e["judgment_id"] in j_ids, f"{e['evid_id']}: unknown judgment")
    check(e["role"] in ("Supports", "Weakens", "Context"), f"{e['evid_id']}: bad role")
    # Analysis of competing hypotheses: an evidence row may rate its item against the judgment's stated alternatives,
    # as "H2:I; H3:N" (C consistent, I inconsistent, N not diagnostic). H1, the judgment itself, is read from `role`.
    if e.get("ach"):
        alts = set(re.findall(r"\bH(\d+):", next((j.get("alternatives") or "" for j in J if j["judgment_id"] == e["judgment_id"]), "")))
        parts = [p.strip() for p in str(e["ach"]).split(";") if p.strip()]
        ok_form = all(re.match(r"^H\d+:[CIN]$", p) for p in parts)
        check(ok_form, f"{e['evid_id']}: ach must read like 'H2:I; H3:N' with ratings C, I or N")
        if ok_form:
            hs = [p[1:].split(":")[0] for p in parts]
            check(len(hs) == len(set(hs)) and all(h in alts for h in hs), f"{e['evid_id']}: ach names a hypothesis the judgment's alternatives do not state, or one twice")
for c in C:
    check(c["source_id"] in src_ids, f"{c['cell']}: unknown source")
    check(c["pir_id"] in pir_ids, f"{c['cell']}: unknown PIR")
for p in P:
    for k in "SDFRT":
        check(p[k] in (1, 2, 3, 4), f"{p['pir_id']}: {k} outside 1-4")
vec_ids = {v["vector_id"] for v in V}
for ve in VE:
    for tid in ve["theater_w"]:
        check(tid in th_ids, f"{ve['vertical_id']}: unknown theater weight {tid}")
    for vid in ve["vector_w"]:
        check(vid in vec_ids, f"{ve['vertical_id']}: unknown vector weight {vid}")
check(sum(1 for ve in VE if ve.get("default") == "Yes") == 1, "verticals: need exactly one default")
check(len({c["chokepoint_id"] for c in CP}) == len(CP), "chokepoints: duplicate id")
for c in CP:
    cid = c.get("chokepoint_id")
    check(-180 <= c["lon"] <= 180 and -90 <= c["lat"] <= 90, f"chokepoint {cid}: coordinates out of range")
    check(all(isinstance(c[k], (int, float)) and c[k] >= 0 for k in ("flow_2023", "flow_2024", "flow_1h25")), f"chokepoint {cid}: flows must be non-negative numbers")
    check(c["theater_id"] == "" or c["theater_id"] in th_ids, f"chokepoint {cid}: unknown theater {c['theater_id']}")
    check(str(c.get("url", "")).startswith("https://"), f"chokepoint {cid}: needs a source URL")
# Writing-style gate on every prose field the page shows (Sean's standing rules)
BANNED = [(r"\bactually\b", "the word 'actually'"), (r"\bmatters?\b|\bmattered\b", "'matters' as emphasis"),
          (r"\b(?:is|are|was|were) not [^.;:]{2,80}\. (?:It|They|This|That) (?:is|are|was|were)\b", "'X is not Y. It is Z.' framing"),
          (r"\bbecomes? [^.;:]{2,60} when\b", "'x becomes y when z' framing"),
          (r"\bnot (?:just|merely|only|simply) [^.;:]{2,80}[,;] but\b", "a negative-then-positive juxtaposition"),
          (r"\u2014[^\u2014]*\u2014[^\u2014]*\u2014", "more than two em dashes in one field")]
for name, rows in [("items", I), ("theaters", T), ("indicators", IND), ("judgments", J), ("evidence", E), ("vectors", V),
                   ("pirs", P), ("method", M), ("followons", F), ("verticals", VE), ("chokepoints", CP),
                   ("outcomes", OUTC), ("leads", LEADS)]:
    for r in rows:
        for k, v in r.items():
            if isinstance(v, str):
                for rx, label in BANNED:
                    check(not re.search(rx, v, re.I), f"{name} {list(r.values())[0]} {k}: contains {label}")

# Measurable indicator rules must name a live indicator in its own theater (authored_indicator_rules.py writes them).
ind_theater = {i["ind_id"]: i["theater_id"] for i in IND}
if os.path.exists(os.path.join(FROM_JSON, "indicator_rules.json")):
    for r in load("indicator_rules.json"):
        check(r.get("ind_id") in ind_theater, f"rule {r.get('rule_id')}: unknown indicator {r.get('ind_id')}")
        check(ind_theater.get(r.get("ind_id")) == r.get("theater_id"), f"rule {r.get('rule_id')}: theater differs from its indicator's")

# The ledger's hash chain: every entry's hash covers its own fields, and each names the hash before it.
ledger = load("ledger.json") if os.path.exists(os.path.join(FROM_JSON, "ledger.json")) else []
entry_hash = lambda e: hashlib.sha256(json.dumps({k: v for k, v in e.items() if k != "hash"}, sort_keys=True).encode()).hexdigest()
for n, e in enumerate(ledger):
    check(e.get("hash") == entry_hash(e), f"ledger {e.get('run_id')}: hash does not match its fields")
    check(e.get("prev_hash") == (ledger[n - 1]["hash"] if n else "GENESIS"), f"ledger {e.get('run_id')}: breaks the chain")

# The change log. Tracked values as they stand now, against the last value the log holds for each.
TRACK = [("theater", T, "theater_id", "name", ("threatcon", "trend")),
         ("judgment", J, "judgment_id", "title", ("title", "likelihood", "severity", "status", "exec_rank", "horizon")),
         ("indicator", IND, "ind_id", "indicator", ("state",)),
         ("vector", V, "vector_id", "vector", ("level", "trend"))]
logged = {(e["kind"], e["id"], e["field"]): e["to"] for e in HIST}
pending = []
for kind, rows, key, label, fields in TRACK:
    for r in rows:
        for f in fields:
            if r.get(f) is None or r.get(f) == "":
                continue
            cur = str(r[f])
            if logged.get((kind, r[key], f)) != cur:
                pending.append({"kind": kind, "id": r[key], "name": r[label], "field": f, "from": logged.get((kind, r[key], f)), "to": cur})
check(len(ids(HIST, "event_id")) == len(set(ids(HIST, "event_id"))), "history: duplicate event_id")
ledger_runs = {e.get("run_id") for e in ledger}
for e in HIST:
    check(e.get("run_id") in ledger_runs, f"history {e.get('event_id')}: names run {e.get('run_id')}, which the ledger does not hold")
if CHECK:
    check(not pending, "history: " + str(len(pending)) + " tracked value(s) differ from the change log, first " +
          "; ".join(f"{p['id']} {p['field']} {p['from']} to {p['to']}" for p in pending[:4]) +
          " (run pipeline/authored_build.py without --check so the run records them)")

# Competing-hypotheses backlog: evidence rows of ranked judgments that carry no rating against the stated alternatives.
# A warning, so the run sees the work it owes (runbook section 2, step 6) without a failed build.
for j in J:
    if (j.get("exec_rank") or 0) > 0 and j.get("status") != "Retired" and re.search(r"\bH\d+:", j.get("alternatives") or ""):
        owed = [e["evid_id"] for e in E if e["judgment_id"] == j["judgment_id"] and not e.get("ach")]
        if owed:
            warnings.append(f"{j['judgment_id']}: {len(owed)} evidence rows lack an ach rating against the alternatives (first {owed[0]}); rate them when this judgment is reviewed")
if errors:
    print("VALIDATOR FAILED")
    for e in errors:
        print(" -", e)
    sys.exit(1)
for w in warnings:
    print("WARN", w)

RUN_ID = f"R-{len(ledger) + 1:04d}"
if not CHECK:
    for n, p in enumerate(pending):
        HIST.append({"event_id": f"H-{len(HIST) + 1:05d}", "run_id": RUN_ID, "date": TODAY.isoformat(), **p})
jtitle = {j["judgment_id"]: j["title"] for j in J}
for o in OUTC:  # derived: the midpoint of the stated range, and the Brier score of a scored outcome
    lo, hi = (int(x) for x in _range.match(o["probability"]).groups())
    o["judgment_title"] = jtitle[o["judgment_id"]]
    o["p"] = round((lo + hi) / 200, 3)
    o["brier"] = None if o["outcome"] == "Indeterminate" else round((o["p"] - (1 if o["outcome"] == "Held" else 0)) ** 2, 4)

written = {}


def dump(name, rows):
    written[name] = json.dumps(rows, separators=(",", ":"), ensure_ascii=False)


# Denormalize display names so tables cite one source each
sname = {s["source_id"]: s["name"] for s in S}
tname = {t["theater_id"]: t["name"] for t in T}
tname["T-GLB"] = "Global (cyber)"
for it in I:
    it["source_name"] = sname[it["source_id"]]
    it["theater_name"] = tname[it["theater_id"]]
    it["grade"] = f"{it['reliability']}{it['credibility']}"
for c in C:
    c["source_name"] = sname[c["source_id"]]
for ind in IND:
    ind["theater_name"] = tname[ind["theater_id"]]
for e in E:
    it = next(x for x in I if x["item_id"] == e["item_id"])
    e["item_title"] = it["title"]
    e["source_name"] = it["source_name"]
    e["grade"] = it["grade"]
    e["url"] = it["url"]
    e["date"] = it["date"]

dump("sources.json", S)
dump("items.json", sorted(I, key=lambda r: (r["date"], r["item_id"]), reverse=True))
dump("theaters.json", sorted(T, key=lambda r: (-r["threatcon"], r["name"])))
dump("theater_indicators.json", IND)
dump("judgments.json", J)
dump("evidence.json", E)
dump("vectors.json", sorted(V, key=lambda r: (-r["level"], r["vector"])))
dump("pirs.json", P)
dump("collection_matrix.json", C)
dump("method.json", M)
dump("followons.json", F)
dump("verticals.json", VE)
dump("chokepoints.json", CP)
dump("outcomes.json", OUTC)
dump("leads.json", LEADS)
dump("history.json", HIST)

if CHECK:
    # The committed files must be exactly what a run writes, so nothing reaches the site without passing through here.
    stale = [n for n, text in written.items() if open(os.path.join(OUT, n), encoding="utf-8").read() != text]
    if stale:
        print("VALIDATOR FAILED")
        print(" - not normalized (run pipeline/authored_build.py without --check and commit the result): " + ", ".join(stale))
        sys.exit(1)
    print(f"validator: {checks} checks passed; {len(written)} datasets normalized; ledger chain of {len(ledger)} entries intact")
    sys.exit(0)

for name, text in written.items():
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
        f.write(text)
    print(f"{name}: {len(json.loads(text))} rows")

# Hash-chained run ledger (Gupta & Tennin p117): each entry commits to the authored dataset contents and the previous entry.
h = hashlib.sha256()
for p in sorted(glob.glob(os.path.join(OUT, "*.json"))):
    if os.path.basename(p) == "ledger.json":
        continue
    h.update(os.path.basename(p).encode())
    h.update(open(p, "rb").read())
cats = json.load(open(CATALOGS)) if CATALOGS and os.path.exists(CATALOGS) else []
entry = {
    "run_id": RUN_ID,
    "at": NOW.isoformat().replace("+00:00", "Z"),
    "kind": KIND,
    "catalogs": "; ".join(f"{c['catalog']} {c['version']}" for c in cats),
    "items": len(I),
    "judgments": len(J),
    "theaters": len(T),
    "changes": len(pending),
    "validator": f"Passed {checks} checks",
    "content_hash": h.hexdigest(),
    "prev_hash": ledger[-1]["hash"] if ledger else "GENESIS",
}
entry["hash"] = entry_hash(entry)
ledger.append(entry)
with open(os.path.join(OUT, "ledger.json"), "w", encoding="utf-8") as f:
    f.write(json.dumps(ledger, separators=(",", ":"), ensure_ascii=False))
print(f"validator: {checks} checks passed; ledger {entry['run_id']} head {entry['hash'][:16]}")
