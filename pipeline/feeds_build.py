#!/usr/bin/env python3
"""Source network registry: merge the curated core (data/sources/core.json) with open feed lists, validate every feed,
and write data/feeds.json, the registry the collector's sources job reads (pushed to the bucket as ref/feeds.json).

Open lists (cloned at build time; their licences travel in the registry's "lists" block):
  muchdogesec/awesome_threat_intel_blogs (CC BY 4.0)    CTI blogs; home pages, feeds found by discovery
  thehappydinoa/awesome-threat-intel-rss (CC0 1.0)       threat-intel feeds
  zer0yu/CyberSecurityRSS (see repository)               security research and news OPML
  plenaryapp/awesome-rss-feeds (Apache 2.0)              national news by country, security and world news
The core adds cyber news, CERTs and agencies, vulnerability sources, think tanks, maritime and defense press, the theater
news feeds of the news job, and Google News query feeds: cyber topics, two queries a theater, and site: feeds for outlets
that refuse cloud requests (titles and links as Google syndicates them).

Validation fetches each feed (honest User-Agent), parses it, and keeps feeds with an entry in the last 180 days. A home
page without a feed is searched for one (link rel=alternate, then common paths). Each kept feed gets a tier from its
volume: 1 (read every 20 minutes) at 3 or more entries a day, 2 (hourly) at 0.3 or more, 3 (every 4 hours) below.
Everything refused is listed in "rejected" with the reason.

  python3 -I pipeline/feeds_build.py [--lists DIR] [--out data/feeds.json] [--workers 48]
  python3 -I pipeline/feeds_build.py --self-test
"""
import argparse, concurrent.futures as cf, datetime as dt, hashlib, html, json, os, re, subprocess, sys, time, urllib.parse, urllib.request
from email.utils import parsedate_to_datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UA = "kti-source-network/1.0 (+https://intel.kilfoycyber.com; threat-intelligence feed reader)"
LISTS = [
    ("awesome_threat_intel_blogs", "https://github.com/muchdogesec/awesome_threat_intel_blogs", "CC BY 4.0"),
    ("awesome-threat-intel-rss", "https://github.com/thehappydinoa/awesome-threat-intel-rss", "CC0 1.0"),
    ("CyberSecurityRSS", "https://github.com/zer0yu/CyberSecurityRSS", "see repository"),
    ("awesome-rss-feeds", "https://github.com/plenaryapp/awesome-rss-feeds", "Apache 2.0"),
]
# Hosts whose first path segment is a separate publication (a subreddit, a Medium author); the three-feeds-a-host cap
# counts those segments instead.
MULTI = {"reddit.com", "medium.com", "old.reddit.com", "feeds.feedburner.com", "feeds.feedblitz.com", "rss.app"}
GUESS = ["feed/", "feed", "rss.xml", "rss", "atom.xml", "index.xml", "feed.xml", "blog/feed/", "blog/rss.xml"]
OSR_CAT = {"News": "cyber-news", "ThreatIntelligence": "research", "Threat Intelligence": "research"}


def gnews(q, days=1, hl="en-US", gl="US", ceid="US:en"):
    return "https://news.google.com/rss/search?" + urllib.parse.urlencode({"q": f"{q} when:{days}d", "hl": hl, "gl": gl, "ceid": ceid})


def canon(u):
    p = urllib.parse.urlsplit(u.strip())
    host = (p.hostname or "").lower()
    if host.startswith("www."): host = host[4:]
    return f"{host}{p.path.rstrip('/')}{'?' + p.query if p.query else ''}"


def fid(u):
    p = urllib.parse.urlsplit(u)
    host = re.sub(r"^www\.", "", (p.hostname or "x").lower())
    return re.sub(r"[^a-z0-9]+", "-", host.split(".")[0 if host.count(".") < 2 else -2])[:24] + "-" + hashlib.sha1(canon(u).encode()).hexdigest()[:6]


def unent(s):
    return html.unescape(re.sub(r"<!\[CDATA\[([\s\S]*?)\]\]>", r"\1", s or "")).strip()


def tag(block, name):
    m = re.search(rf"<{name}\b[^>]*>([\s\S]*?)</{name}>", block, re.I)
    return re.sub(r"<[^>]+>", " ", unent(m.group(1))).strip() if m else ""


def when(s):
    s = (s or "").strip()
    if not s: return None
    try:
        d = parsedate_to_datetime(s)
    except Exception:
        try: d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception: return None
    if d.tzinfo is None: d = d.replace(tzinfo=dt.timezone.utc)
    return d


def parse_feed(xml):
    """[{title, link, published}] or None when the answer is no feed (mirrors parseFeedItems in neon/parts/37c-reg.mjs)."""
    s = xml or ""
    if not re.search(r"<(rss|feed|rdf:RDF)\b", s[:5000], re.I): return None
    blocks = re.findall(r"<item\b[\s\S]*?</item>", s, re.I) or re.findall(r"<entry\b[\s\S]*?</entry>", s, re.I)
    out = []
    for b in blocks[:60]:
        link = tag(b, "link")
        if not link.startswith("http"):
            m = re.search(r"<link\b[^>]*rel=[\"']alternate[\"'][^>]*href=[\"']([^\"']+)", b, re.I) or re.search(r"<link\b[^>]*href=[\"']([^\"']+)", b, re.I)
            link = unent(m.group(1)) if m else ""
        t = tag(b, "title")
        d = when(tag(b, "pubDate") or tag(b, "published") or tag(b, "updated") or tag(b, "dc:date"))
        if t and link.startswith("http"): out.append({"title": t[:300], "link": link, "published": d})
    return out


def lang_of(titles):
    s = " ".join(titles)[:4000]
    if not s: return "en"
    n = len(s)
    for code, rx in (("zh", r"[一-鿿]"), ("ru", r"[Ѐ-ӿ]"), ("ar", r"[؀-ۿ]"), ("ja", r"[぀-ヿ]"), ("ko", r"[가-힯]")):
        if len(re.findall(rx, s)) / n > 0.15: return code
    return "en"


def fetch(u, accept="application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.5", timeout=20):
    try:
        req = urllib.request.Request(u, headers={"User-Agent": UA, "Accept": accept})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(3_000_000).decode("utf-8", "replace"), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, "", u
    except Exception as e:
        return 0, str(e)[:120], u


def discover(home):
    st, body, final = fetch(home, accept="text/html")
    cands = []
    if st == 200:
        for m in re.finditer(r"<link\b[^>]*>", body[:400000], re.I):
            t = m.group(0)
            if re.search(r"rel\s*=\s*[\"']?alternate", t, re.I) and re.search(r"application/(rss|atom)\+xml", t, re.I):
                h = re.search(r"href\s*=\s*[\"']([^\"']+)", t, re.I)
                if h and "comments" not in h.group(1).lower(): cands.append(urllib.parse.urljoin(final, unent(h.group(1))))
    base = final if final.endswith("/") else final + "/"
    cands += [urllib.parse.urljoin(base, g) for g in GUESS]
    for c in list(dict.fromkeys(cands))[:8]:
        st2, body2, _ = fetch(c)
        if st2 == 200 and parse_feed(body2): return c, body2
    return None, ("home page " + str(st)) if st != 200 else "no feed found"


def check(c, now):
    try:
        return _check(c, now)
    except Exception as e:
        return {**c, "ok": False, "why": "error: " + str(e)[:100]}


def _check(c, now):
    url, why, body = c["url"], None, None
    if c.get("home") and not url:
        url, got = discover(c["home"])
        if not url: return {**c, "ok": False, "why": got}
        body = got
    if body is None:
        st, body, _ = fetch(url)
        if st in (0, 429, 500, 502, 503, 504, 520, 521, 522, 524):
            time.sleep(2); st, body, _ = fetch(url, timeout=30)
        if st != 200 or parse_feed(body) is None:
            if c.get("home") or c.get("site"):
                alt, got = discover(c.get("home") or c.get("site"))
                if alt: url, body = alt, got
                else: return {**c, "ok": False, "why": f"HTTP {st}" if st != 200 else "answer is not a feed"}
            else:
                return {**c, "ok": False, "why": f"HTTP {st}" if st != 200 else "answer is not a feed"}
    items = parse_feed(body) or []
    dated = [i["published"] for i in items if i["published"]]
    newest = max(dated) if dated else None
    if c.get("gnews"):
        pass
    elif not items:
        return {**c, "url": url, "ok": False, "why": "feed has no entries"}
    elif newest and (now - newest).days > 180:
        return {**c, "url": url, "ok": False, "why": f"dormant: newest entry {newest.date()}"}
    recent = [d for d in dated if (now - d).days <= 14]
    per_day = len(recent) / 14 if recent else (0 if dated else 0.2)
    if dated and len(dated) >= 10 and min(dated) > now - dt.timedelta(days=14):
        span = max((now - min(dated)).total_seconds() / 86400, 0.25)
        per_day = len(dated) / span
    tier = 1 if (c.get("gnews") or per_day >= 3) else 2 if per_day >= 0.3 else 3
    return {**c, "url": url, "ok": True, "tier": tier, "per_day": round(per_day, 2), "entries": len(items),
            "newest": newest.isoformat() if newest else None, "lang": lang_of([i["title"] for i in items[:20]])}


def clone(lists_dir):
    os.makedirs(lists_dir, exist_ok=True)
    for name, url, _ in LISTS:
        d = os.path.join(lists_dir, name)
        if not os.path.isdir(d):
            subprocess.run(["git", "clone", "-q", "--depth", "1", url, d], check=False, timeout=180)


def opml_feeds(path):
    s = open(path, encoding="utf-8", errors="replace").read()
    out, cat = [], None
    for m in re.finditer(r"<outline\b[^>]*>", s):
        t = m.group(0)
        attr = lambda k: unent((re.search(rf'\b{k}\s*=\s*"([^"]*)"', t) or re.search(rf"\b{k}\s*=\s*'([^']*)'", t) or [None, ""])[1])
        x = attr("xmlUrl")
        if not x: cat = attr("text") or cat; continue
        out.append({"name": attr("title") or attr("text") or x, "url": x, "site": attr("htmlUrl"), "group": cat})
    return out


def candidates(lists_dir, core):
    c = []
    add = lambda **k: c.append(k)
    for name, url, cat in core["feeds"]:
        add(name=name, url=url, category=cat, region="Global", origin="core")
    news = open(os.path.join(ROOT, "neon/parts/37g-news.mjs"), encoding="utf-8").read()
    for m in re.finditer(r"\{ id: '([^']+)', name: '([^']+)', region: '([^']+)', url: '([^']+)' \}", news):
        reg = m.group(3)
        add(name=m.group(2), url=m.group(4), category="maritime" if reg == "Maritime" else "geopolitics", region="Global" if reg in ("Maritime", "Asia") else reg, origin="core")
    for q in core["gnews_topics_cyber"]:
        add(name=f"Google News: {q}", url=gnews(q), category="topic-cyber", region="Global", origin="gnews", gnews=True)
    for hl, gl, ceid, q in core.get("gnews_topics_lang", []):
        add(name=f"Google News ({ceid}): {q}", url=gnews(q, 1, hl, gl, ceid), category="topic-cyber", region="Global", origin="gnews", gnews=True)
    for th, q in core["gnews_topics_theater"]:
        add(name=f"Google News: {q}", url=gnews(q), category="topic-theater", region=th, origin="gnews", gnews=True)
    for name, host, cat, reg in core["gnews_sites"]:
        add(name=f"{name} (via Google News)", url=gnews(f"site:{host}", 2), category=cat, region=reg, origin="gnews", gnews=True, publisher=host)
    p = os.path.join(lists_dir, "awesome_threat_intel_blogs", "README.md")
    if os.path.exists(p):
        for m in re.finditer(r"<tr>\s*<td>([\s\S]*?)</td>\s*<td>([\s\S]*?)</td>\s*<td>\s*<a href='([^']+)'", open(p, encoding="utf-8").read()):
            name = re.sub(r"<[^>]+>", "", m.group(1)).strip()
            if name and name != "Name":
                add(name=name, url="", home=m.group(3), category="research", region="Global", origin="awesome_threat_intel_blogs")
    p = os.path.join(lists_dir, "awesome-threat-intel-rss", "README.md")
    if os.path.exists(p):
        sec = "research"
        for line in open(p, encoding="utf-8"):
            h = re.match(r"###\s+(.+)", line)
            if h: sec = "community" if "Communit" in h.group(1) else "government" if "Gov" in h.group(1) else "cyber-news" if "News" in h.group(1) else "research"
            f = re.match(r"\s*\* Feed: (https?://\S+)", line)
            if f: add(name=last if "last" in dir() else f.group(1), url=f.group(1), category=sec, region="Global", origin="awesome-threat-intel-rss")
            n = re.match(r"\* (.+)", line)
            if n and not line.startswith("    "): last = n.group(1).strip()
    p = os.path.join(lists_dir, "CyberSecurityRSS", "CyberSecurityRSS.opml")
    if os.path.exists(p):
        for f in opml_feeds(p):
            add(name=f["name"], url=f["url"], site=f["site"], category=OSR_CAT.get(f["group"], "research"), region="Global", origin="CyberSecurityRSS")
    base = os.path.join(lists_dir, "awesome-rss-feeds")
    for country, reg in core["countries"].items():
        p = os.path.join(base, "countries", "with_category", country + ".opml")
        if os.path.exists(p):
            for f in opml_feeds(p): add(name=f"{f['name']} ({country})", url=f["url"], category="geopolitics", region=reg, origin="awesome-rss-feeds")
    for cat_file, cat in (("Cyber security.opml", "cyber-news"), ("News.opml", "geopolitics")):
        p = os.path.join(base, "recommended", "with_category", cat_file)
        if os.path.exists(p):
            for f in opml_feeds(p): add(name=f["name"], url=f["url"], category=cat, region="Global", origin="awesome-rss-feeds")
    return c


def build(lists_dir, out, workers):
    core = json.load(open(os.path.join(ROOT, "data/sources/core.json"), encoding="utf-8"))
    clone(lists_dir)
    cand, seen = [], set()
    for x in candidates(lists_dir, core):
        k = canon(x["url"]) if x["url"] else "home:" + canon(x["home"])
        if k in seen: continue
        seen.add(k); cand.append(x)
    now = dt.datetime.now(dt.timezone.utc)
    print(f"{len(cand)} candidate feeds; validating with {workers} workers", file=sys.stderr)
    res, t0 = [], time.time()
    g = [x for x in cand if x.get("gnews")]
    o = [x for x in cand if not x.get("gnews")]
    with cf.ThreadPoolExecutor(workers) as ex:
        res += list(ex.map(lambda x: check(x, now), o))
    with cf.ThreadPoolExecutor(3) as ex:
        res += list(ex.map(lambda x: (time.sleep(0.4), check(x, now))[1], g))
    # A core outlet that refuses or answers no feed is read through a Google News site: feed instead, so no core source is
    # dropped for the way its server answers.
    heal = [r for r in res if not r.get("ok") and r.get("origin") == "core" and r.get("url")]
    with cf.ThreadPoolExecutor(3) as ex:
        res += list(ex.map(lambda r: (time.sleep(0.4), check({**r, "name": r["name"] + " (via Google News)", "url": gnews("site:" + re.sub(r"^www\.", "", urllib.parse.urlsplit(r["url"]).hostname or ""), 2),
            "origin": "gnews", "gnews": True, "publisher": re.sub(r"^www\.", "", urllib.parse.urlsplit(r["url"]).hostname or ""), "healed_from": r["url"], "ok": None, "why": None}, now))[1], heal))
    kept, rejected, hosts, urls = [], [], {}, set()
    for r in sorted(res, key=lambda r: (r.get("origin") != "core", r.get("origin") != "gnews", r["name"].lower())):
        if not r.get("ok"):
            rejected.append({"name": r["name"], "url": r.get("url") or r.get("home"), "origin": r["origin"], "why": r["why"]}); continue
        k = canon(r["url"])
        if k in urls: continue
        h = k.split("/")[0]
        if h in MULTI: h = "/".join(k.split("/")[:3])
        if not r.get("gnews"):
            hosts[h] = hosts.get(h, 0) + 1
            if hosts[h] > 3:
                rejected.append({"name": r["name"], "url": r["url"], "origin": r["origin"], "why": "fourth feed of one host"}); continue
        urls.add(k)
        kept.append({"id": fid(r["url"]), "name": r["name"][:120], "url": r["url"], "category": r["category"], "region": r["region"], "tier": r["tier"],
                     "lang": r["lang"], "per_day": r["per_day"], "origin": r["origin"], **({"publisher": r["publisher"]} if r.get("publisher") else {}),
                     **({"gnews": True} if r.get("gnews") else {}), **({"healed_from": r["healed_from"]} if r.get("healed_from") else {})})
    ids = {}
    for k in kept:
        if k["id"] in ids: k["id"] += "-" + str(len(ids))
        ids[k["id"]] = 1
    counts = {}
    for k in kept: counts[k["category"]] = counts.get(k["category"], 0) + 1
    doc = {"generated": now.isoformat(timespec="seconds"), "validated_in_s": round(time.time() - t0), "candidates": len(cand), "count": len(kept),
           "by_category": dict(sorted(counts.items())), "by_tier": {t: sum(1 for k in kept if k["tier"] == t) for t in (1, 2, 3)},
           "lists": [{"name": n, "url": u, "license": l} for n, u, l in LISTS] + [{"name": "KTI core", "url": "data/sources/core.json", "license": "project"}],
           "feeds": sorted(kept, key=lambda k: (k["tier"], k["category"], k["name"].lower())),
           "rejected": sorted(rejected, key=lambda r: (r["origin"], r["name"].lower()))}
    json.dump(doc, open(out, "w", encoding="utf-8"), indent=0, ensure_ascii=False)
    print(f"kept {len(kept)} of {len(cand)} ({doc['by_category']}); tiers {doc['by_tier']}; rejected {len(rejected)}", file=sys.stderr)


def self_test():
    rss = "<rss><channel><item><title>A &amp; B</title><link>https://x.example/a</link><pubDate>Mon, 16 Nov 2026 10:00:00 GMT</pubDate></item></channel></rss>"
    atom = "<feed><entry><title><![CDATA[Zero]]></title><link rel='alternate' href='https://y.example/z'/><updated>2026-11-16T10:00:00Z</updated></entry></feed>"
    a, b = parse_feed(rss), parse_feed(atom)
    checks = [(a and a[0]["title"] == "A & B" and a[0]["published"].year == 2026, "RSS item"), (b and b[0]["link"] == "https://y.example/z", "Atom alternate link"),
              (parse_feed("<html>x</html>") is None, "a page is no feed"), (canon("https://www.X.example/feed/") == "x.example/feed", "canonical URL"),
              (lang_of(["网络安全 漏洞 预警"]) == "zh", "language of Chinese titles"), ("when%3A1d" in gnews("data breach"), "Google News query window"),
              (fid("https://www.bleepingcomputer.com/feed/").startswith("bleepingcomputer-"), "feed id")]
    bad = [m for ok, m in checks if not ok]
    if bad: raise SystemExit("FAIL " + "; ".join(bad))
    print(f"PASS {len(checks)} checks (source network builder)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--lists", default="/tmp/kti-feed-lists")
    ap.add_argument("--out", default=os.path.join(ROOT, "data/feeds.json"))
    ap.add_argument("--workers", type=int, default=48)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    self_test() if a.self_test else build(a.lists, a.out, a.workers)
