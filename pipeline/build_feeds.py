#!/usr/bin/env python3
"""Rebuild every machine-built ("feed") dataset from its public sources, in order.

Run: python3 -I pipeline/build_feeds.py WORK FEEDS [YYYY-MM-DD]
  WORK   scratch folder for downloads (raw, raw2, raw3, raw4 are made inside it). Downloads are untrusted data:
         every step runs with -I and nothing under WORK is executed.
  FEEDS  folder of built datasets. Start it from the previous build (the workflow restores it from its cache): a step
         that fails leaves that step's datasets as they were, and the failure is recorded in FEEDS/_build.json.
Steps: fetch.py and build_data.py (KEV, CVE, ATT&CK, ICS, leak-site and media baselines), build_gazetteer.py (the entity
gazetteer the collector's entities job matches against), fetch_defense.py and
build_defense.py (threat-informed defense), fetch_weaponization.py and build_weaponization.py (PoC and weaponization
dates; reads FEEDS/kev.json and FEEDS/early_warning.json), fetch_cvelist.py and build_baserates.py (weakness base rates by
product family over every CVE List V5 record; reads the same two datasets and fetch.py's KEV and CVSS-BT downloads).
Exit status 1 when the core step (build_data.py) failed, so the workflow keeps the last good site.
"""
import datetime as dt
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WORK, FEEDS = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
DAY = sys.argv[3] if len(sys.argv) > 3 else dt.date.today().isoformat()
RAW, RAW2, RAW3, RAW4, RAW5 = (os.path.join(WORK, d) for d in ("raw", "raw2", "raw3", "raw4", "raw5"))
for d in (WORK, FEEDS, RAW, RAW2, RAW3, RAW4, RAW5):
    os.makedirs(d, exist_ok=True)

STEPS = [
    ("fetch", ["fetch.py", RAW, RAW2, DAY]),
    ("build_data", ["build_data.py", RAW, RAW2, FEEDS, DAY]),
    ("build_gazetteer", ["build_gazetteer.py", RAW, RAW2, FEEDS, DAY]),
    ("fetch_defense", ["fetch_defense.py", RAW3]),
    ("build_defense", ["build_defense.py", RAW, RAW3, FEEDS, DAY]),
    ("fetch_weaponization", ["fetch_weaponization.py", RAW4, FEEDS]),
    ("build_weaponization", ["build_weaponization.py", RAW4, FEEDS, DAY]),
    ("fetch_cvelist", ["fetch_cvelist.py", RAW5, DAY]),
    ("build_baserates", ["build_baserates.py", RAW5, RAW, RAW2, FEEDS, DAY]),
]
# A build step needs its fetch; a failed fetch skips the build so yesterday's datasets stand.
NEEDS = {"build_data": "fetch", "build_gazetteer": "build_data", "build_defense": "fetch_defense", "build_weaponization": "fetch_weaponization",
         "build_baserates": ("fetch_cvelist", "build_data")}

results = {}
for name, (script, *args) in STEPS:
    need = NEEDS.get(name, ())
    bad = [n for n in ((need,) if isinstance(need, str) else need) if results.get(n, {}).get("status") == "failed"]
    if bad:
        results[name] = {"status": "skipped", "reason": ", ".join(bad) + " failed"}
        print(f"== {name}: skipped ({', '.join(bad)} failed)", flush=True)
        continue
    t0 = time.time()
    print(f"== {name}", flush=True)
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, script), *args], cwd=WORK, capture_output=True, text=True, timeout=3600)
    tail = (r.stdout[-3000:] + ("\n" + r.stderr[-3000:] if r.stderr else "")).strip()
    print(tail, flush=True)
    results[name] = {"status": "ok" if r.returncode == 0 else "failed", "exit": r.returncode, "seconds": round(time.time() - t0, 1)}
    if r.returncode:
        results[name]["error"] = (r.stderr or r.stdout)[-600:]

now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
prev = {}
p = os.path.join(FEEDS, "_build.json")
if os.path.exists(p):
    try:
        prev = json.load(open(p))
    except ValueError:
        prev = {}
core_ok = results["build_data"]["status"] == "ok"
doc = {"at": now if core_ok else prev.get("at"), "date": DAY if core_ok else prev.get("date"), "attempted": now, "steps": results}
json.dump(doc, open(p, "w"), indent=1)
print(json.dumps(doc, indent=1))
sys.exit(0 if core_ok else 1)
