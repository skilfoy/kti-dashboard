#!/usr/bin/env python3
"""Rebuild data/authored/history.json, the change log, from this repository's Git history.

Run once, from the repository root, with full history fetched: python3 -I pipeline/backfill_history.py data/authored
It walks every commit that touched the authored datasets, oldest first, reads the tracked values at each commit
(theater level and trend, judgment title, likelihood, severity, status, rank and horizon, indicator state, vector level
and trend) and writes one event per change, stamped with the ledger run at that commit. The first commit gives the
baseline rows (from: null). After this, pipeline/authored_build.py keeps the log: each run appends its own events and
--check fails when a tracked value differs from the log. Kept in the repository so the log can be reproduced.
"""
import json
import subprocess
import sys

OUT = sys.argv[1].rstrip("/")
TRACK = [("theater", "theaters.json", "theater_id", "name", ("threatcon", "trend")),
         ("judgment", "judgments.json", "judgment_id", "title", ("title", "likelihood", "severity", "status", "exec_rank", "horizon")),
         ("indicator", "theater_indicators.json", "ind_id", "indicator", ("state",)),
         ("vector", "vectors.json", "vector_id", "vector", ("level", "trend"))]


def git(*a):
    return subprocess.run(["git", *a], capture_output=True, text=True, check=True).stdout


def at(commit, name):
    try:
        return json.loads(git("show", f"{commit}:{OUT}/{name}"))
    except (subprocess.CalledProcessError, ValueError):
        return None


commits = git("log", "--reverse", "--format=%H", "--", OUT).split()
logged, events = {}, []
for c in commits:
    ledger = at(c, "ledger.json") or []
    if not ledger:
        continue
    run_id, date = ledger[-1]["run_id"], ledger[-1]["at"][:10]
    for kind, name, key, label, fields in TRACK:
        for r in at(c, name) or []:
            for f in fields:
                if r.get(f) is None or r.get(f) == "":
                    continue
                cur = str(r[f])
                if logged.get((kind, r[key], f)) != cur:
                    events.append({"event_id": f"H-{len(events) + 1:05d}", "run_id": run_id, "date": date, "kind": kind, "id": r[key],
                                   "name": r[label], "field": f, "from": logged.get((kind, r[key], f)), "to": cur})
                    logged[(kind, r[key], f)] = cur
with open(f"{OUT}/history.json", "w", encoding="utf-8") as fh:
    fh.write(json.dumps(events, separators=(",", ":"), ensure_ascii=False))
moves = [e for e in events if e["from"] is not None]
print(f"history.json: {len(events)} events from {len(commits)} commits ({len(events) - len(moves)} baseline, {len(moves)} changes)")
