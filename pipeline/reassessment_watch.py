#!/usr/bin/env python3
"""Is the daily reassessment current? A check without a model, for the "Reassessment watch" workflow.

Run: python3 -I pipeline/reassessment_watch.py data/authored [--now 2026-11-14T14:23:00Z]
     python3 -I pipeline/reassessment_watch.py --self-test
Prints one JSON object: {"ok": bool, "problems": [...], "head": {...}}. Exit status is 0 either way; the workflow reads
the JSON and keeps one GitHub issue open while "ok" is false. Problems:
  - no "Daily reassessment" ledger entry in the last 25 hours (the run is due at 06:45 America/Chicago, which is 11:45
    or 12:45 UTC; the workflow looks at 14:23 and 20:23 UTC)
  - the validator's currency warnings: a theater past its review date, a judgment past its horizon or its weekly
    review, a requirement past its review (pipeline/authored_build.py --check prints them as WARN lines)
"""
import datetime as dt
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_AGE_HOURS = 25


def judge(ledger, warnings, now):
    daily = [e for e in ledger if e.get("kind") == "Daily reassessment"]
    head = daily[-1] if daily else None
    problems = []
    if not head:
        problems.append("The ledger holds no daily reassessment entry.")
    else:
        age = (now - dt.datetime.fromisoformat(head["at"].replace("Z", "+00:00"))).total_seconds() / 3600
        if age > MAX_AGE_HOURS:
            problems.append(f"No daily reassessment in the last {MAX_AGE_HOURS} hours: the newest is {head['run_id']} at {head['at']} ({age:.0f} hours ago).")
    problems += warnings
    return {"ok": not problems, "problems": problems,
            "head": {k: head.get(k) for k in ("run_id", "at", "items", "validator")} if head else None}


def self_test():
    now = dt.datetime(2026, 11, 14, 14, 23, tzinfo=dt.timezone.utc)
    fresh = [{"run_id": "R-0026", "at": "2026-11-14T12:51:00Z", "kind": "Daily reassessment"}]
    stale = [{"run_id": "R-0024", "at": "2026-11-13T12:51:00Z", "kind": "Daily reassessment"},
             {"run_id": "R-0025", "at": "2026-11-14T13:00:00Z", "kind": "Platform upgrade 2.1"}]
    assert judge(fresh, [], now)["ok"]
    assert not judge(stale, [], now)["ok"], "another kind of run does not stand in for the daily one"
    assert judge(stale, [], now)["head"]["run_id"] == "R-0024"
    assert not judge(fresh, ["T-HOA: review overdue"], now)["ok"]
    assert len(judge(stale, ["x", "y"], now)["problems"]) == 3
    assert not judge([], [], now)["ok"]
    print("PASS 6 checks (reassessment watch)")


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--self-test" in args:
        self_test()
        sys.exit(0)
    now = dt.datetime.now(dt.timezone.utc)
    if "--now" in args:
        now = dt.datetime.fromisoformat(args[args.index("--now") + 1].replace("Z", "+00:00"))
        del args[args.index("--now"):args.index("--now") + 2]
    folder = args[0]
    ledger = json.load(open(os.path.join(folder, "ledger.json"), encoding="utf-8"))
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "authored_build.py"), folder, "--check"], capture_output=True, text=True)
    warnings = [line[5:] for line in r.stdout.splitlines() if line.startswith("WARN ")]
    if r.returncode != 0:
        warnings.append("The validator fails on the committed data: " + " | ".join(r.stdout.strip().splitlines()[-4:]))
    print(json.dumps(judge(ledger, warnings, now), indent=1))
