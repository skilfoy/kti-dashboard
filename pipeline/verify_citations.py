#!/usr/bin/env python3
"""Citation verification without a model: does each cited page exist, and does it carry the claim?

For every item in data/authored/items.json this script fetches the cited URL from wherever it runs (the site workflow's
runner) and records what it found. It is independent of the session that wrote the item: the reassessment says it
fetched a page; this checks the page.

  python3 -I pipeline/verify_citations.py --items data/authored/items.json --state <dir>/verification_state.json \
      --out <feeds dir>/verification.json [--max 120] [--gate-from 1126] [--only I-1,I-2]
  python3 -I pipeline/verify_citations.py --self-test

States, one per item:
  excerpt_found    the item's excerpt (a sentence the run copied from the page) is on the page
  claim_supported  no excerpt, or the excerpt was not found, and at least 60 percent of the title's distinctive tokens
                   (figures, CVE ids, proper nouns) are on the page
  weak_match       30 to 60 percent of those tokens are on the page
  mismatch         the page answered with real text and carries under 30 percent of the tokens and no excerpt
  derived          a "Feed data" item: its title states a figure computed from the cited dataset (a median, a count over a
                   window, a price on a date), which no page text carries; the check is that the dataset page answers
  thin             the page answered with too little text to judge (script-rendered or a teaser)
  blocked          the site refused the request (401, 403, 429, 451, a challenge page): unverifiable from here
  gone             404 or 410
  error            timeout, DNS failure, another status
  pending          not fetched yet

The state file (kept in the workflow's cache, never committed) holds every result with the excerpt check's detail; the
output dataset is the public part: state, status, counts and times, with no page text and no excerpt.

--gate-from N fails the run (exit 1) when an item numbered N or higher is "gone", or is a "mismatch" on a page with
substantial text. Blocked, thin and error states never fail a run: they are unverifiable, and the site says so.
No third-party system is scanned: one GET per cited page, identified by User-Agent, at most two at a time per host.
"""
import concurrent.futures as cf
import datetime as dt
import gzip
import hashlib
import html
import json
import re
import sys
import threading
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zlib

UA = "kti-citation-check/1.0 (+https://intel.kilfoycyber.com; verifies that cited pages carry the cited claim)"
MAX_BYTES = 2_500_000
RECHECK_DAYS = 45          # a verified page is read again after this long
RETRY_DAYS = 3             # blocked, thin and error states are tried again after this long
SUBSTANTIAL = 3000         # characters of page text needed before a mismatch can count against an item
STOP = set("""The A An In On At For Of And Or But With From By To As After Before Since While During Between Over Under
Into Its Their His Her This That These Those It They He She We Is Are Was Were Be Been Has Have Had Will Would Could
Should May Might Not No New One Two Three Four Five Six Seven Eight Nine Ten First Second Third According Reports
Reported Says Said Per About Around Nearly More Most Some All Any Each Both Monday Tuesday Wednesday Thursday Friday
Saturday Sunday January February March April May June July August September October November December Headline""".split())


def norm(s):
    s = unicodedata.normalize("NFKC", s or "")
    s = s.translate({0x2018: "'", 0x2019: "'", 0x201C: '"', 0x201D: '"', 0x2013: "-", 0x2014: "-", 0x2212: "-", 0xA0: " "})
    return re.sub(r"\s+", " ", s).strip().lower()


def page_text(raw):
    t = re.sub(r"(?is)<(script|style|noscript|svg|template)\b.*?</\1>", " ", raw)
    t = re.sub(r"(?is)<!--.*?-->", " ", t)
    # Keep what search engines and social cards read too: titles, descriptions and JSON-LD bodies.
    metas = " ".join(re.findall(r'(?is)<meta[^>]+content="([^"]{20,2000})"', raw))
    ld = " ".join(re.findall(r'(?is)<script[^>]+application/ld\+json[^>]*>(.*?)</script>', raw))
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    return norm(html.unescape(t + " " + metas + " " + ld))


def tokens(title):
    """Distinctive tokens of a title: CVE ids, figures and proper nouns."""
    out = []
    for m in re.findall(r"CVE-\d{4}-\d{4,7}", title):
        out.append(m.lower())
    for m in re.findall(r"(?<![\w-])\d[\d,]*(?:\.\d+)?(?![\w-]*-\d)", re.sub(r"CVE-\d{4}-\d{4,7}", " ", title)):
        d = m.replace(",", "").rstrip(".")
        if len(d.replace(".", "")) >= 2 and not re.fullmatch(r"20\d\d", d):
            out.append(d)
    words = re.findall(r"[A-Za-z][A-Za-z'’-]{3,}", title)
    starts = {m.group(1) for m in re.finditer(r"(?:^|[.;:]\s+)([A-Za-z][A-Za-z'’-]{3,})", title)}
    for w in words:
        if w[0].isupper() and w not in STOP and w not in starts and not w.isupper() or (w.isupper() and len(w) >= 4 and w not in STOP):
            out.append(norm(w))
    seen, uniq = set(), []
    for t in out:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq[:24]


def token_hit(tok, text, digits):
    if re.fullmatch(r"[\d.]+", tok):
        return tok in digits
    return tok in text


def excerpt_found(excerpt, text):
    """True when the excerpt is on the page: verbatim, or a run of at least 8 consecutive words (or 70 percent of its
    words, if shorter) in order. Tolerates the small edits a quoting tool makes; a paraphrase does not pass."""
    e = norm(excerpt)
    if not e:
        return False
    if e in text:
        return True
    w = e.split()
    need = max(5, min(8, int(len(w) * 0.7)))
    if len(w) < need:
        return False
    return any(" ".join(w[i:i + need]) in text for i in range(0, len(w) - need + 1))


def judge(item, status, raw, final_url):
    host = urllib.parse.urlparse(item["url"]).netloc.lower()
    base = {"http_status": status, "host": re.sub(r"^www\.", "", host), "has_excerpt": bool(item.get("excerpt")),
            "tokens_total": 0, "tokens_found": 0, "chars": 0, "text_sha256": None, "moved_to": None}
    fh = urllib.parse.urlparse(final_url or item["url"]).netloc.lower()
    if fh and re.sub(r"^www\.", "", fh) != base["host"]:
        base["moved_to"] = re.sub(r"^www\.", "", fh)
    if status in (404, 410):
        return {**base, "state": "gone"}
    if status in (401, 403, 429, 451):
        return {**base, "state": "blocked"}
    if status != 200 or raw is None:
        return {**base, "state": "error"}
    text = page_text(raw)
    base["chars"] = len(text)
    base["text_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if re.search(r"just a moment|attention required|verify you are human|enable javascript and cookies|access denied|are you a robot|captcha", text[:1500]) and len(text) < 6000:
        return {**base, "state": "blocked"}
    toks = tokens(item["title"])
    digits = set(re.sub(r"(?<=\d),(?=\d)", "", text).replace("%", " ").split()) | set(re.findall(r"\d+(?:\.\d+)?", re.sub(r"(?<=\d),(?=\d)", "", text)))
    found = sum(1 for t in toks if token_hit(t, text, digits))
    base["tokens_total"], base["tokens_found"] = len(toks), found
    share = found / len(toks) if toks else 0
    if item.get("excerpt") and excerpt_found(item["excerpt"], text):
        return {**base, "state": "excerpt_found"}
    if item.get("category") == "Feed data":
        return {**base, "state": "derived"}
    if len(text) < 600:
        return {**base, "state": "thin"}
    if len(toks) >= 3 and share >= 0.6:
        return {**base, "state": "claim_supported"}
    if len(toks) >= 3 and share >= 0.3:
        return {**base, "state": "weak_match"}
    if len(toks) < 3:
        return {**base, "state": "weak_match" if share > 0 else "thin"}
    return {**base, "state": "mismatch" if len(text) >= SUBSTANTIAL else "thin"}


def fetch(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
                                               "Accept-Encoding": "gzip, deflate", "Accept-Language": "en"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(MAX_BYTES)
            enc = (r.headers.get("Content-Encoding") or "").lower()
            try:
                if enc == "gzip":
                    body = gzip.decompress(body)
                elif enc == "deflate":
                    body = zlib.decompress(body)
            except (OSError, zlib.error):
                body = zlib.decompressobj(47).decompress(body) if enc else body
            ctype = r.headers.get("Content-Type") or ""
            m = re.search(r"charset=([\w-]+)", ctype)
            if "pdf" in ctype:
                return r.status, None, r.geturl()
            return r.status, body.decode(m.group(1) if m else "utf-8", errors="replace"), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, None, url
    except Exception:  # noqa: BLE001 - timeouts, DNS, TLS: all "error"
        return 0, None, url


def num(item_id):
    return int(item_id.split("-")[1])


def plan(items, state, now, limit, only=None):
    """Which items to fetch this run: never checked (newest first), then retries, then the oldest verified."""
    def age(r):
        return (now - dt.datetime.fromisoformat(r["checked_at"].replace("Z", "+00:00"))).days
    fresh, retry, old = [], [], []
    for it in items:
        if only and it["item_id"] not in only:
            continue
        r = state.get(it["item_id"])
        if only or not r or r.get("url") != it["url"] or bool(it.get("excerpt")) != r.get("has_excerpt"):
            fresh.append(it)
        elif r["state"] in ("blocked", "thin", "error") and age(r) >= RETRY_DAYS and r.get("tries", 1) < 4:
            retry.append(it)
        elif age(r) >= RECHECK_DAYS:
            old.append(it)
    fresh.sort(key=lambda i: -num(i["item_id"]))
    old.sort(key=lambda i: state[i["item_id"]]["checked_at"])
    return (fresh + retry + old)[:limit]


def run(items, state, limit, only=None, fetcher=fetch, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    todo = plan(items, state, now, limit, only)
    by_url = {}
    for it in todo:
        by_url.setdefault(it["url"], []).append(it)
    locks, guard = {}, threading.Lock()

    def one(url):
        host = urllib.parse.urlparse(url).netloc
        with guard:
            sem = locks.setdefault(host, threading.Semaphore(2))
        with sem:
            return url, fetcher(url)

    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        for url, (status, raw, final) in ex.map(one, list(by_url)):
            for it in by_url[url]:
                prev = state.get(it["item_id"]) or {}
                r = judge(it, status, raw, final)
                state[it["item_id"]] = {"item_id": it["item_id"], "url": it["url"], "checked_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                        "tries": (prev.get("tries", 0) + 1) if prev.get("url") == it["url"] else 1, **r}
    live = {i["item_id"] for i in items}
    for k in [k for k in state if k not in live]:
        del state[k]
    return len(todo)


def public_rows(items, state):
    rows = []
    for it in sorted(items, key=lambda i: num(i["item_id"])):
        r = state.get(it["item_id"])
        rows.append({"item_id": it["item_id"], "source_name": it.get("source_name"), "grade": it.get("grade"), "date": it.get("date"),
                     "host": (r or {}).get("host") or re.sub(r"^www\.", "", urllib.parse.urlparse(it["url"]).netloc.lower()),
                     "state": r["state"] if r else "pending", "http_status": r["http_status"] if r else None,
                     "has_excerpt": bool(it.get("excerpt")), "tokens_found": r["tokens_found"] if r else None,
                     "tokens_total": r["tokens_total"] if r else None, "moved_to": r["moved_to"] if r else None,
                     "checked_at": r["checked_at"] if r else None})
    return rows


def gate(items, state, gate_from):
    bad = []
    for it in items:
        if num(it["item_id"]) < gate_from:
            continue
        r = state.get(it["item_id"])
        if not r:
            continue
        if r["state"] == "gone":
            bad.append(f"{it['item_id']}: the cited page answers HTTP {r['http_status']} ({it['url']})")
        elif r["state"] == "mismatch":
            bad.append(f"{it['item_id']}: the cited page answered with {r['chars']} characters of text and carries {r['tokens_found']} of the title's {r['tokens_total']} figures and names"
                       + (", and the excerpt is not on it" if it.get("excerpt") else "") + f" ({it['url']})")
    return bad


def self_test():
    page = """<html><head><title>IMO Council condemns attacks</title><script>var x = "130 ignored";</script></head><body>
      <p>The IMO said it had verified at least 130 attacks on commercial vessels and 25 seafarer deaths, after the tanker
      VELOS SAPPHIRE was struck in the Strait of Hormuz on 5 November.</p>""" + "<p>Filler sentence about shipping lanes and insurance markets.</p>" * 80 + "</body></html>"
    it = {"item_id": "I-2000", "url": "https://example.org/a", "title": "The IMO verified at least 130 attacks on commercial vessels and 25 seafarer deaths; VELOS SAPPHIRE was hit in the Strait of Hormuz on 5 November."}
    r = judge(it, 200, page, it["url"])
    assert r["state"] == "claim_supported", r
    assert judge({**it, "excerpt": "verified at least 130 attacks on commercial vessels and 25 seafarer deaths"}, 200, page, it["url"])["state"] == "excerpt_found"
    assert judge({**it, "excerpt": "it had verified at least 130 attacks on commercial ships and 25 seafarer deaths, after the tanker"}, 200, page, it["url"])["state"] == "excerpt_found", "a small edit inside a long quote still matches on a run of words"
    assert not excerpt_found("The organisation counted over one hundred assaults against merchant shipping this year", page_text(page)), "a paraphrase does not pass"
    other = "<html><body>" + "<p>Recipes for autumn soups, with notes on stock and seasoning.</p>" * 120 + "</body></html>"
    assert judge(it, 200, other, it["url"])["state"] == "mismatch"
    assert judge(it, 200, "<html><body><div id=app></div></body></html>", it["url"])["state"] == "thin"
    assert judge(it, 404, None, it["url"])["state"] == "gone"
    assert judge(it, 403, None, it["url"])["state"] == "blocked"
    assert judge(it, 200, "<html><body>Just a moment... verify you are human</body></html>", it["url"])["state"] == "blocked"
    assert judge(it, 0, None, it["url"])["state"] == "error"
    assert judge(it, 200, page, "https://other.example.com/x")["moved_to"] == "other.example.com"
    assert "cve-2026-114713" in tokens("CISA added UnrealIRCd CVE-2026-114713 (CVSS 8.6) on 13 November 2026") and "8.6" in tokens("CISA added UnrealIRCd CVE-2026-114713 (CVSS 8.6)")
    assert "2026" not in tokens("Something happened in 2026 to Acme Corporation"), "a bare year is not distinctive"
    state = {}
    calls = []
    fake = lambda u: (calls.append(u), (200, page, u))[1]
    items = [it, {**it, "item_id": "I-2001"}, {**it, "item_id": "I-1999", "url": "https://example.org/b"}]
    n = run(items, state, 10, fetcher=fake)
    assert n == 3 and len(calls) == 2, "one request per URL, shared by the items that cite it"
    assert run(items, state, 10, fetcher=fake) == 0, "verified items are not fetched again before the recheck window"
    state["I-1999"]["state"] = "gone"; state["I-1999"]["http_status"] = 404
    assert gate(items, state, 2000) == [] and len(gate(items, state, 1999)) == 1
    rows = public_rows(items, state)
    assert [r["item_id"] for r in rows] == ["I-1999", "I-2000", "I-2001"] and "excerpt" not in rows[0] and "text_sha256" not in rows[0]
    assert run(items[:1], state, 10, fetcher=fake) == 0 and "I-2001" not in state, "state for dropped items is pruned"
    feed = {"item_id": "I-9", "title": "Edge-device CVEs reached KEV a median of 1 day after publication (60 CVEs)", "url": "https://github.com/cisagov/kev-data", "category": "Feed data"}
    assert judge(feed, 200, "<html><body>" + "<p>Repository of the KEV catalog in JSON and CSV.</p>" * 80 + "</body></html>", feed["url"])["state"] == "derived", "Feed data: derived"
    assert judge(feed, 404, None, feed["url"])["state"] == "gone", "Feed data whose page is gone: gone"
    print("PASS 21 checks (citation verification)")


if __name__ == "__main__":
    a = sys.argv[1:]
    if "--self-test" in a:
        self_test()
        sys.exit(0)
    opt = lambda k, d=None: a[a.index(k) + 1] if k in a else d
    items = json.load(open(opt("--items"), encoding="utf-8"))
    try:
        state = {r["item_id"]: r for r in json.load(open(opt("--state"), encoding="utf-8"))}
    except (OSError, ValueError):
        state = {}
    only = set(opt("--only").split(",")) if opt("--only") else None
    n = run(items, state, int(opt("--max", "120")), only)
    json.dump(sorted(state.values(), key=lambda r: num(r["item_id"])), open(opt("--state"), "w", encoding="utf-8"), separators=(",", ":"))
    rows = public_rows(items, state)
    json.dump(rows, open(opt("--out"), "w", encoding="utf-8"), separators=(",", ":"), ensure_ascii=False)
    counts = {}
    for r in rows:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    print(f"verification: fetched {n} this run; {len(rows)} items: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1])))
    if opt("--gate-from"):
        bad = gate(items, state, int(opt("--gate-from")))
        if bad:
            print("CITATION GATE FAILED")
            for b in bad:
                print(" -", b)
            sys.exit(1)
