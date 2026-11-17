#!/usr/bin/env python3
"""Citation repair queue: the cited pages that the citation check found gone or not carrying their item, in the order to
repair them, each with the action that fits it.

Reads the verification dataset the site publishes (pipeline/verify_citations.py builds it in the Site workflow) and the
authored items, evidence and judgments. It changes nothing; the daily run repairs what it lists (runbook section 2).

  python3 -I pipeline/citation_queue.py [--verification URL|path] [--authored data/authored] [--max 5] [--json]
  python3 -I pipeline/citation_queue.py --self-test

Order: pages gone (404, 410), then mismatches, then partial matches on items that support a ranked judgment. Within a
state, items behind ranked judgments come first, then the newest. "derived" items (figures computed from a dataset) and
unverifiable states (blocked, thin, error) are not repair work and are left out.
"""
import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request

PUBLIC = "https://intel.kilfoycyber.com/data/verification.json"
# Pages whose content changes after they are cited: live prices, daily bulletins, briefs, live blogs.
DYNAMIC = re.compile(r"(tradingeconomics\.com|mnd\.gov\.tw|straits\.live|/live/|liveblog|live-blog|/briefs?/|/latest)", re.I)
RANK = {"gone": 0, "mismatch": 1, "weak_match": 2}


def archive_url(item):
    day = re.sub(r"[^0-9]", "", str(item.get("reported") or item.get("date") or ""))[:8]
    return f"https://web.archive.org/web/{day or '*'}/{item['url']}"


def action(state, item):
    arch = archive_url(item)
    if state == "gone":
        return ("The page answers 404 or 410. Find the article's new address on the publisher's site or an archived copy "
                f"({arch}) and cite whichever carries the claim, with an excerpt and fetched_at. If neither exists, cite another "
                "source that carries it; if no source does, lower credibility to 6 (truth cannot be judged) and say why in the report.")
    if state == "mismatch" and DYNAMIC.search(item["url"]):
        return ("The page changes after it is cited (a live price, a daily bulletin or a brief), so today's text no longer "
                f"carries the claim. Cite the dated article, or the archived copy from the item's date ({arch}), with an excerpt.")
    if state == "mismatch":
        return ("The page carries few of the title's figures and names. Open it: if it carries the claim in other words, record "
                f"an excerpt and fetched_at; if it has changed since, cite the archived copy ({arch}); if it never carried the "
                "claim, cite the page that does or correct the title to what the page says.")
    return ("Partial match. Open the page; if it carries the claim, record an excerpt and fetched_at so the next check finds "
            "it, and if it does not, repair it as a mismatch.")


def build(verification, items, evidence, judgments, limit=5):
    ranked = {j["judgment_id"] for j in judgments if (j.get("exec_rank") or 0) > 0 and j.get("status") != "Retired"}
    behind = {}
    for e in evidence:
        if e.get("judgment_id") in ranked:
            behind.setdefault(e["item_id"], set()).add(e["judgment_id"])
    supports = {e["item_id"] for e in evidence if e.get("judgment_id") in ranked and e.get("role") == "Supports"}
    by_id = {i["item_id"]: i for i in items}
    queue = []
    for r in verification:
        st, it = r.get("state"), by_id.get(r.get("item_id"))
        if not it or st not in RANK or (st == "weak_match" and it["item_id"] not in supports):
            continue
        queue.append({"item_id": it["item_id"], "state": st, "title": it["title"], "url": it["url"], "host": r.get("host") or "",
                      "date": it.get("date", ""), "judgments": sorted(behind.get(it["item_id"], [])), "action": action(st, it)})
    queue.sort(key=lambda q: (RANK[q["state"]], 0 if q["judgments"] else 1, -int(re.sub(r"\D", "", q["item_id"]) or 0)))
    return queue[:limit] if limit else queue


def read_json(src):
    if re.match(r"https?://", src):
        req = urllib.request.Request(src, headers={"User-Agent": "kti-citation-queue/1.0", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as f:
            return json.loads(f.read().decode("utf-8"))
    with open(src, encoding="utf-8") as f:
        return json.load(f)


def self_test():
    items = [{"item_id": f"I-{n}", "title": f"Item {n}", "url": u, "date": "2026-10-16"} for n, u in
             [(1, "https://a.example/story"), (2, "https://tradingeconomics.com/commodity/brent-crude-oil"), (3, "https://b.example/x"),
              (4, "https://c.example/y"), (5, "https://d.example/z"), (6, "https://e.example/w")]]
    ver = [{"item_id": "I-1", "state": "mismatch"}, {"item_id": "I-2", "state": "mismatch"}, {"item_id": "I-3", "state": "gone"},
           {"item_id": "I-4", "state": "weak_match"}, {"item_id": "I-5", "state": "weak_match"}, {"item_id": "I-6", "state": "derived"}]
    ev = [{"item_id": "I-4", "judgment_id": "KJ-01", "role": "Supports"}, {"item_id": "I-1", "judgment_id": "KJ-01", "role": "Context"}]
    js = [{"judgment_id": "KJ-01", "exec_rank": 1, "status": "Active"}]
    q = build(ver, items, ev, js, limit=0)
    ids = [x["item_id"] for x in q]
    checks = [
        (ids == ["I-3", "I-1", "I-2", "I-4"], f"order: gone, mismatch behind a ranked judgment, other mismatch, supporting partial match: {ids}"),
        ("I-5" not in ids and "I-6" not in ids, "partial matches outside ranked support and derived items are left out"),
        ("archived copy from the item's date (https://web.archive.org/web/20261016/" in q[2]["action"], "a live page is pointed at the dated archive copy"),
        ("credibility to 6" in q[0]["action"], "a gone page names the last resort"),
        (q[1]["judgments"] == ["KJ-01"], "the ranked judgment behind an item is named"),
        (len(build(ver, items, ev, js, limit=2)) == 2, "the queue is capped"),
    ]
    bad = [m for c, m in checks if not c]
    if bad:
        raise SystemExit("FAIL " + "; ".join(bad))
    print(f"PASS {len(checks)} checks (citation repair queue)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verification", default=PUBLIC)
    ap.add_argument("--authored", default="data/authored")
    ap.add_argument("--max", type=int, default=5)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    ver = read_json(a.verification)
    ver = ver if isinstance(ver, list) else ver.get("rows", [])
    load = lambda n: read_json(os.path.join(a.authored, n))
    q = build(ver, load("items.json"), load("evidence.json"), load("judgments.json"), a.max)
    if a.json:
        print(json.dumps(q, indent=1, ensure_ascii=False))
        return
    if not q:
        print("Citation repair queue is empty.")
        return
    for x in q:
        print(f"{x['item_id']} [{x['state']}] {x['title'][:120]}\n  {x['url']}" + (f"\n  behind {', '.join(x['judgments'])}" if x["judgments"] else "") + f"\n  {x['action']}\n")


if __name__ == "__main__":
    main()
