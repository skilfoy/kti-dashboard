#!/usr/bin/env python3
"""Validate the analyst-authored datasets, rebuild their derived display fields, and append a hash-chained ledger entry.

Run: python3 -I pipeline/authored_build.py DIR [--kind "Daily reassessment"] [--catalogs FEEDS/catalogs.json]
     python3 -I pipeline/authored_build.py DIR --check
DIR holds the authored datasets (data/authored). The daily reassessment edits them in place and then runs the first
form, which rewrites them with their derived fields and appends a ledger entry. --check is what the site workflow runs
before every deploy: it validates, verifies the ledger's hash chain, and confirms the files on disk are exactly what
this script would write, without writing anything. The validator holds final authority over a run (Fleurat et al.
ch5, ch16): any failure exits non-zero and nothing ships.
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
CT = load("controls.json")
AS = load("assets.json")
EX = load("exposure_darkweb.json")
if os.path.exists(os.path.join(FROM_JSON, "chokepoints.json")):
    CP = load("chokepoints.json")
else:  # seed from the authored module
    sys.path.insert(0, HERE)
    from authored_chokepoints import CHOKEPOINTS as CP  # noqa: E402
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
for j in J:
    sup = [e for e in E if e["judgment_id"] == j["judgment_id"] and e["role"] == "Supports"]
    check(len(sup) >= 1, f"{j['judgment_id']}: no supporting evidence")
    for p in [x.strip() for x in j["pirs"].split(",") if x.strip()]:
        check(p in pir_ids, f"{j['judgment_id']}: unknown PIR {p}")
check(len([j for j in J if j["exec_rank"] > 0]) >= 1, "no executive judgments ranked")
for e in E:
    check(e["item_id"] in item_ids, f"{e['evid_id']}: unknown item {e['item_id']}")
    check(e["judgment_id"] in j_ids, f"{e['evid_id']}: unknown judgment")
    check(e["role"] in ("Supports", "Weakens", "Context"), f"{e['evid_id']}: bad role")
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
for ct in CT:
    check(ct["vector_id"] in vec_ids, f"controls {ct['vector_id']}: unknown vector")
    check(0 <= ct["coverage"] <= 1, f"controls {ct['vector_id']}: coverage outside 0-1")
for a in AS:
    check(a["exposure"] in ("Internet-facing", "Internal"), f"asset {a.get('host')}: bad exposure")
    for k in ("host", "product", "site", "source"):
        check(isinstance(a.get(k), str), f"asset {a.get('host')}: missing {k}")
check(len({a["host"] for a in AS}) == len(AS), "assets: host must be unique (the page keys rows by host)")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
for x in EX:
    check(x.get("severity") in ("Low", "Medium", "High", "Critical"), f"exposure {x.get('kind')}: bad severity")
    check(isinstance(x.get("metric"), int) and x["metric"] >= 0, f"exposure {x.get('kind')}: metric must be a non-negative integer")
    # Counts only: an email address or a password-looking field in the dark-web read must never reach the page.
    check(not _EMAIL.search(json.dumps(x)), f"exposure {x.get('kind')}: contains an email address")
    check(not any(k in x for k in ("password", "passwords", "top_passwords", "top_logins", "login")), f"exposure {x.get('kind')}: carries credential fields")
check(len({x["kind"] for x in EX}) == len(EX), "exposure: kind must be unique (the page keys rows by kind)")
check(len({c["chokepoint_id"] for c in CP}) == len(CP), "chokepoints: duplicate id")
for c in CP:
    cid = c.get("chokepoint_id")
    check(-180 <= c["lon"] <= 180 and -90 <= c["lat"] <= 90, f"chokepoint {cid}: coordinates out of range")
    check(all(isinstance(c[k], (int, float)) and c[k] >= 0 for k in ("flow_2023", "flow_2024", "flow_1h25")), f"chokepoint {cid}: flows must be non-negative numbers")
    check(c["theater_id"] == "" or c["theater_id"] in th_ids, f"chokepoint {cid}: unknown theater {c['theater_id']}")
    check(str(c.get("url", "")).startswith("https://"), f"chokepoint {cid}: needs a source URL")
# Writing-style gate on every prose field the page shows (Sean's standing rules)
BANNED = [(r"\bactually\b", "the word 'actually'"), (r"\bmatters?\b|\bmattered\b", "'matters' as emphasis")]
for name, rows in [("items", I), ("theaters", T), ("indicators", IND), ("judgments", J), ("evidence", E), ("vectors", V),
                   ("pirs", P), ("method", M), ("followons", F), ("verticals", VE), ("controls", CT), ("chokepoints", CP)]:
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

if errors:
    print("VALIDATOR FAILED")
    for e in errors:
        print(" -", e)
    sys.exit(1)


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
dump("controls.json", CT)
dump("assets.json", AS)
dump("exposure_darkweb.json", EX)
dump("chokepoints.json", CP)

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
    "run_id": f"R-{len(ledger) + 1:04d}",
    "at": NOW.isoformat().replace("+00:00", "Z"),
    "kind": KIND,
    "catalogs": "; ".join(f"{c['catalog']} {c['version']}" for c in cats),
    "items": len(I),
    "judgments": len(J),
    "theaters": len(T),
    "validator": f"Passed {checks} checks",
    "content_hash": h.hexdigest(),
    "prev_hash": ledger[-1]["hash"] if ledger else "GENESIS",
}
entry["hash"] = entry_hash(entry)
ledger.append(entry)
with open(os.path.join(OUT, "ledger.json"), "w", encoding="utf-8") as f:
    f.write(json.dumps(ledger, separators=(",", ":"), ensure_ascii=False))
print(f"validator: {checks} checks passed; ledger {entry['run_id']} head {entry['hash'][:16]}")
