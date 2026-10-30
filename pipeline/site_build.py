#!/usr/bin/env python3
"""Assemble the site's data: every file dataset into public/data and the dataset catalog into public/site.json.

Run: python3 -I pipeline/site_build.py --authored data/authored --feeds FEEDS --out public [--commit SHA] [--allow-missing]
  --authored  the analyst-authored datasets (committed in data/authored)
  --feeds     the machine-built datasets (pipeline/build_feeds.py output, restored from the workflow cache)
  --out       the static site root; writes OUT/data/<id>.json and OUT/site.json
Each dataset file is parsed (it must be a JSON list of row objects) and written compact. Its URL carries the first
12 hex digits of its SHA-256, so a browser can cache it for a year and still sees a new build at once.
A dataset missing from both folders fails the build unless --allow-missing, which leaves it out of the catalog (the
page then shows that panel as unavailable).
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # this folder only: the catalog module
from datasets import AUTHORED, D, OWNER, PARAMS, Q, FEED_SCHEDULE, JUDGED_SCHEDULE, CARRIED  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--authored", required=True)
ap.add_argument("--feeds", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--commit", default=os.environ.get("GITHUB_SHA", ""))
ap.add_argument("--allow-missing", action="store_true")
a = ap.parse_args()

now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
data_dir = os.path.join(a.out, "data")
os.makedirs(data_dir, exist_ok=True)
for f in os.listdir(data_dir):  # a dataset dropped from the catalog leaves no file behind
    if f.endswith(".json"):
        os.remove(os.path.join(data_dir, f))


def load_json(p):
    try:
        return json.load(open(p, encoding="utf-8"))
    except (OSError, ValueError):
        return None


ledger = load_json(os.path.join(a.authored, "ledger.json")) or []
judged_at = ledger[-1]["at"] if ledger and isinstance(ledger[-1], dict) and ledger[-1].get("at") else None
feed_build = load_json(os.path.join(a.feeds, "_build.json")) or {}
feeds_at = feed_build.get("at")

catalog, missing, total = {}, [], 0
for ds, (title, desc) in D.items():
    src = os.path.join(a.authored if ds in AUTHORED else a.feeds, ds + ".json")
    rows = load_json(src)
    if rows is None:
        missing.append(ds)
        continue
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        sys.exit(f"{src}: not a JSON list of row objects")
    blob = json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    open(os.path.join(data_dir, ds + ".json"), "wb").write(blob)
    total += len(blob)
    entry = {"title": title, "description": desc, "kind": "file", "url": f"/data/{ds}.json?v={hashlib.sha256(blob).hexdigest()[:12]}", "rows": len(rows), "bytes": len(blob)}
    if ds in OWNER:
        entry["schedule"] = CARRIED
        if judged_at:
            entry["updated"] = {"at": judged_at, "by": "Analyst"}
    elif ds in AUTHORED:
        entry["schedule"], entry["staleAfterHours"] = JUDGED_SCHEDULE, 48
        if judged_at:
            entry["updated"] = {"at": judged_at, "by": "Daily reassessment"}
    else:
        entry["schedule"], entry["staleAfterHours"] = FEED_SCHEDULE, 48
        if feeds_at:
            entry["updated"] = {"at": feeds_at, "by": "Site build"}
    catalog[ds] = entry
for ds, (title, desc, url) in Q.items():
    if not url.startswith("/api/"):
        sys.exit(f"{ds}: query URL must be same-origin /api/..., got {url}")
    catalog[ds] = {"title": title, "description": desc, "kind": "query", "url": url}

if missing and not a.allow_missing:
    sys.exit("missing datasets: " + ", ".join(missing))
site = {"title": "Global threat intelligence", "built": now, "commit": a.commit[:12] if a.commit else None,
        "feeds": {"at": feeds_at, "steps": {k: v.get("status") for k, v in (feed_build.get("steps") or {}).items()}},
        "params": PARAMS, "datasets": catalog}
json.dump(site, open(os.path.join(a.out, "site.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(f"site.json: {sum(1 for d in catalog.values() if d['kind'] == 'file')} files ({total / 1e6:.1f} MB), "
      f"{sum(1 for d in catalog.values() if d['kind'] == 'query')} queries" + (f"; missing: {', '.join(missing)}" if missing else ""))
