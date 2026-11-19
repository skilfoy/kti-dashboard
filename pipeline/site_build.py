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
    if rows is None and ds == "verification":
        rows = []  # the first build after a cache loss: every item shows as pending until the verifier has run
    if ds == "items" and rows is not None:
        # Excerpts are the run's proof of reading, checked by pipeline/verify_citations.py; they stay in the repository.
        rows = [{**{k: v for k, v in r.items() if k != "excerpt"}, "has_excerpt": bool(r.get("excerpt"))} for r in rows]
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

# The change feed (JSON Feed 1.1): one entry per ledger run, newest first, saying what the run changed. Built from the
# ledger and the change log, so a reader or a tool can follow the site's assessed changes without opening the page.
LV = {"5": "CRITICAL", "4": "HIGH", "3": "ELEVATED", "2": "GUARDED", "1": "NORMAL"}
FIELD = {"threatcon": "ThreatCon level", "trend": "trend", "title": "title", "likelihood": "likelihood", "severity": "severity",
         "status": "status", "exec_rank": "executive rank", "horizon": "horizon", "state": "state", "level": "level"}
history = load_json(os.path.join(a.authored, "history.json")) or []
HOME = "https://intel.kilfoycyber.com"
first_logged = history[0]["run_id"] if history else "R-9999"
entries = []
for n, run in enumerate(ledger):
    if not isinstance(run, dict) or not run.get("run_id"):
        continue
    moves = [e for e in history if e.get("run_id") == run["run_id"] and e.get("from") is not None]
    show = lambda e, x: (f"{x} {LV.get(str(x), '')}".strip() if e["kind"] == "theater" and e["field"] == "threatcon" else str(x))
    lines = [f"{e['kind'].capitalize()} {e['id']} ({e['name']}): {FIELD.get(e['field'], e['field'])} {show(e, e['from'])} to {show(e, e['to'])}" for e in moves]
    prev = ledger[n - 1] if n else None
    delta = run["items"] - prev["items"] if prev and isinstance(run.get("items"), int) and isinstance(prev.get("items"), int) else None
    if run["run_id"] < first_logged:  # the change log holds nothing about runs before its baseline
        head = "run before the change log began"
    else:
        head = f"{len(moves)} change{'' if len(moves) == 1 else 's'} to levels, trends, judgments and indicators" if moves else "no level, trend, judgment or indicator moved"
    text = f"{run.get('kind', 'Run')} {run['run_id']}: {head}; {run.get('items')} cited items" + (f" (net {delta:+d})" if delta is not None else "") + f". {run.get('validator', '')}."
    entries.append({"id": f"{HOME}/#run-{run['run_id']}", "url": f"{HOME}/#brief-since", "title": f"{run['run_id']}: {head}",
                    "content_text": "\n".join([text] + lines), "date_published": run.get("at"),
                    "_kti": {"run_id": run["run_id"], "kind": run.get("kind"), "hash": run.get("hash"), "changes": len(moves)}})
feed = {"version": "https://jsonfeed.org/version/1.1", "title": "Global threat intelligence: assessed changes by run",
        "home_page_url": HOME + "/", "feed_url": HOME + "/feed.json", "language": "en",
        "description": "One entry per reassessment run with the ThreatCon, trend, judgment and warning-indicator changes it logged. Marked TLP:GREEN and PAP:AMBER.",
        "authors": [{"name": "Sean Kilfoy"}], "items": entries[::-1][:60]}
json.dump(feed, open(os.path.join(a.out, "feed.json"), "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
print(f"feed.json: {len(feed['items'])} runs")

# The data sources registry (data/data_sources.json, checked by pipeline/check_data_sources.mjs) is published as is at the
# site root for the /data-sources page, outside /data so its URL stays stable.
reg_src = os.path.join(os.path.dirname(os.path.abspath(a.authored)), "data_sources.json")
if os.path.exists(reg_src):
    reg = json.load(open(reg_src, encoding="utf-8"))
    json.dump(reg, open(os.path.join(a.out, "data-sources.json"), "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
    print(f"data-sources.json: {len(reg.get('rows', []))} sources")
# The source network registry (data/feeds.json, built by pipeline/feeds_build.py) is published at /data/feeds.json, where
# the collector's sources job reads it, so a registry change reaches the collector with the site deploy.
feeds_src = os.path.join(os.path.dirname(os.path.abspath(a.authored)), "feeds.json")
if os.path.exists(feeds_src):
    fr = json.load(open(feeds_src, encoding="utf-8"))
    os.makedirs(os.path.join(a.out, "data"), exist_ok=True)
    json.dump(fr, open(os.path.join(a.out, "data", "feeds.json"), "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
    print(f"feeds.json: {len(fr.get('feeds', []))} feeds")
# The standing watches (data/watches.json) are published at /data/watches.json, where the collector's watch job reads
# them; each must name a PIR of the authored register and a known kind.
watches_src = os.path.join(os.path.dirname(os.path.abspath(a.authored)), "watches.json")
if os.path.exists(watches_src):
    wd = json.load(open(watches_src, encoding="utf-8"))
    pir_ids = {r["pir_id"] for r in (load_json(os.path.join(a.authored, "pirs.json")) or [])}
    kinds = {"entity_terms", "entity_category", "terms", "kev_added", "cve_surge", "first_seen", "surge", "coincidence"}
    for w in wd.get("watches", []):
        if w.get("pir") not in pir_ids or w.get("kind") not in kinds or (w.get("terms") and w["terms"] not in wd.get("terms", {})):
            sys.exit(f"data/watches.json: watch {w.get('id')} names an unknown PIR, kind or term list")
    os.makedirs(os.path.join(a.out, "data"), exist_ok=True)
    json.dump(wd, open(os.path.join(a.out, "data", "watches.json"), "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
    print(f"watches.json: {len(wd.get('watches', []))} watches")
# The entity gazetteer (build_gazetteer.py) is a document, not a row dataset: published at /data/entity_gazetteer.json,
# where the collector's entities job reads it, the same way.
gaz_src = os.path.join(a.feeds, "entity_gazetteer.json")
if os.path.exists(gaz_src):
    gz = json.load(open(gaz_src, encoding="utf-8"))
    os.makedirs(os.path.join(a.out, "data"), exist_ok=True)
    json.dump(gz, open(os.path.join(a.out, "data", "entity_gazetteer.json"), "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
    print(f"entity_gazetteer.json: {len(gz.get('entities', []))} entities, {len(gz.get('edges', []))} curated edges")
