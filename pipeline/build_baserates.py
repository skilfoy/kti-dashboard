#!/usr/bin/env python3
"""Weakness base rates by product family: how often each CWE, in each kind of product, reached exploitation.

Run: python3 -I build_baserates.py RAW5 RAW RAW2 FEEDS YYYY-MM-DD
  RAW5/cves.zip, RAW5/cvelist.json   every CVE List V5 record at midnight UTC (fetch_cvelist.py)
  RAW/kev.json                       CISA KEV (fetch.py)
  RAW2/cvss-bt.csv                   CVSS-BT exploitation and weaponization signals for every CVE (fetch.py)
  FEEDS/kev.json, FEEDS/early_warning.json   the rows the page annotates (build_data.py)
Writes FEEDS/weakness_rates.json, FEEDS/weakness_families.json and FEEDS/weakness_cve.json.

Method (docs/weakness-base-rates.md):
  Window      CVEs published in the 36 months that end 90 days before the build, so each has had at least 90 days for
              exploitation evidence to appear. CVE List V5 records carry a CWE and a vendor for most CVEs only from 2023 on.
  Family      pipeline/families.py, from the record's vendor, product and title, its CNA and any package registry.
  CWE         the CNA's CWE identifiers, else CISA's ADP ones. A CVE listing two CWEs counts in both cells, so a
              family's CWE shares can add up to more than 100%.
  Outcomes    exploited: CISA KEV or VulnCheck KEV lists it; weaponized: a Metasploit module or Nuclei template exists;
              PoC public: Exploit-DB or a GitHub PoC repository (CVSS-BT flags, KEV catalog).
  Rate        exploited CVEs over CVEs in the cell, with a Wilson 95% interval. Lift is the cell's rate over its family's.
  Per CVE     each KEV and early-warning CVE takes its first listed CWE and its family; the base is that family's cell
              when it holds at least MIN_N CVEs, else the CWE across all families, else none.
Self-test: python3 -I build_baserates.py --self-test
"""
import csv
import datetime as dt
import json
import math
import os
import re
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # this folder only: the product families module
import families as F  # noqa: E402

WINDOW_DAYS, LAG_DAYS = 1096, 90
MIN_N = 30        # a cell with fewer CVEs is not used as a CVE's base
KEEP_N = 15       # cells with fewer CVEs are left out of weakness_rates
ALL = "All families"
CWE_RX = re.compile(r"^CWE-\d+$")
VAGUE = {"", "n/a", "unknown", "unspecified", "none", "-"}


def wilson(k, n, z=1.96):
    if not n:
        return None, None
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return round(max(0.0, (c - m) / d), 5), round(min(1.0, (c + m) / d), 5)


def r5(x):
    return None if x is None else round(x, 4)


def load_bt(path):
    out = {}
    csv.field_size_limit(10_000_000)
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            t = lambda k: r.get(k) == "True"  # noqa: E731
            out[r["cve"]] = (t("cisa_kev") or t("vulncheck_kev"), t("metasploit") or t("nuclei"), t("exploitdb") or t("poc_github"))
    return out


def cwes_of(rec):
    cont = rec.get("containers", {})
    names = {}
    for src in [cont.get("cna", {})] + (cont.get("adp") or []):
        ids = []
        for p in src.get("problemTypes") or []:
            for d in p.get("descriptions") or []:
                c = str(d.get("cweId") or "").upper().strip()
                if CWE_RX.match(c):
                    if c not in ids:
                        ids.append(c)
                    desc = re.sub(r"^\s*CWE-\d+\s*[:\-–]?\s*", "", str(d.get("description") or "")).strip()
                    if desc and not desc.upper().startswith("CWE"):
                        names.setdefault(c, desc[:140])
        if ids:
            return ids, names
    return [], names


def product_of(rec):
    cna = rec.get("containers", {}).get("cna", {})
    title = cna.get("title") or ""
    if not title:
        title = next((d.get("value", "") for d in cna.get("descriptions") or [] if str(d.get("lang", "")).startswith("en")), "")
    for a in cna.get("affected") or []:
        v, p = str(a.get("vendor") or ""), str(a.get("product") or "")
        if v.strip().lower() not in VAGUE or p.strip().lower() not in VAGUE:
            return v, p, title[:160], a.get("collectionURL") or "", a.get("packageName") or ""
    a = (cna.get("affected") or [{}])[0]
    return "", "", title[:160], a.get("collectionURL") or "", a.get("packageName") or ""


def scan(zip_path, start, end, want):
    """One pass over every record: window statistics per CVE, and the fields of the wanted CVEs at any date."""
    window, wanted, names = [], {}, defaultdict(Counter)
    with zipfile.ZipFile(zip_path) as z:
        for n in z.namelist():
            if not n.endswith(".json") or "/CVE-" not in n:
                continue
            try:
                rec = json.loads(z.read(n))
            except ValueError:
                continue
            meta = rec.get("cveMetadata", {})
            if meta.get("state") != "PUBLISHED":
                continue
            cid = meta.get("cveId", "")
            pub = (meta.get("datePublished") or "")[:10]
            inwin = start <= pub < end
            if not inwin and cid not in want:
                continue
            ids, nm = cwes_of(rec)
            for c, d in nm.items():
                names[c][d] += 1
            v, p, title, coll, pkg = product_of(rec)
            cna = meta.get("assignerShortName") or ""
            fam, ec, basis = F.classify(v, p, title, cna, coll, pkg)
            row = (cid, fam, basis, ids)
            if inwin:
                window.append(row)
            if cid in want:
                wanted[cid] = {"family": fam, "basis": basis, "cwes": ids, "cna": cna}
    cwe_name = {c: cnt.most_common(1)[0][0] for c, cnt in names.items()}
    return window, wanted, cwe_name


def outcome(cid, bt, kev):
    e, w, p = bt.get(cid, (False, False, False))
    return (e or cid in kev), w, p


def build(window, bt, kev, cwe_name, window_label):
    cell = defaultdict(lambda: [0, 0, 0, 0])  # cves, exploited, weaponized, poc
    fam = defaultdict(lambda: {"cves": 0, "with_cwe": 0, "exploited": 0, "weaponized": 0, "poc": 0, "basis": Counter(), "ex_cwe": 0})
    for cid, f, basis, ids in window:
        e, w, p = outcome(cid, bt, kev)
        for key in (f, ALL):
            s = fam[key]
            s["cves"] += 1
            s["exploited"] += e
            s["weaponized"] += w
            s["poc"] += p
            if key == f:
                s["basis"][basis or "none"] += 1
            if ids:
                s["with_cwe"] += 1
                s["ex_cwe"] += e
        if not ids:
            continue
        for c in ids:
            for key in ((f, c), (ALL, c)):
                if key[0] == F.UNCLASSIFIED:
                    continue
                x = cell[key]
                x[0] += 1
                x[1] += e
                x[2] += w
                x[3] += p
    rates, index = [], {}
    for (f, c), (n, e, w, p) in cell.items():
        fs = fam[f]
        base = fs["ex_cwe"] / fs["with_cwe"] if fs["with_cwe"] else None
        rate = e / n
        lo, hi = wilson(e, n)
        row = {"family": f, "cwe": c, "cwe_name": cwe_name.get(c, ""), "cves": n, "share": r5(n / fs["with_cwe"]) if fs["with_cwe"] else None,
               "exploited": e, "exploited_rate": r5(rate), "exploited_lo": r5(lo), "exploited_hi": r5(hi), "weaponized_rate": r5(w / n),
               "poc_rate": r5(p / n), "lift": round(rate / base, 2) if base else None, "small": n < MIN_N, "weaponized": w, "poc": p}
        index[(f, c)] = row
        if n >= KEEP_N:
            rates.append(row)
    for f in {r["family"] for r in rates}:
        ranked = sorted((r for r in rates if r["family"] == f), key=lambda r: (-r["cves"], r["cwe"]))
        for i, r in enumerate(ranked, 1):
            r["rank"] = i
    rates.sort(key=lambda r: (r["family"] != ALL, F.FAMILY_ORDER.index(r["family"]) if r["family"] in F.FAMILY_ORDER else 99, r["rank"]))
    fams = []
    for f in [ALL] + F.FAMILY_ORDER + [F.UNCLASSIFIED]:
        s = fam.get(f)
        if not s:
            continue
        top = sorted((r for r in rates if r["family"] == f), key=lambda r: -r["cves"])[:3]
        fams.append({"family": f, "family_rate": r5(s["ex_cwe"] / s["with_cwe"]) if s["with_cwe"] else None, "note": "Every CVE in the window" if f == ALL else ("Matched by no family rule; counted only in All families" if f == F.UNCLASSIFIED else F.FAMILY_NOTES.get(f, "")),
                     "cves": s["cves"], "with_cwe": s["with_cwe"], "cwe_coverage": r5(s["with_cwe"] / s["cves"]) if s["cves"] else None,
                     "exploited": s["exploited"], "exploited_rate": r5(s["exploited"] / s["cves"]) if s["cves"] else None,
                     "weaponized_rate": r5(s["weaponized"] / s["cves"]) if s["cves"] else None, "poc_rate": r5(s["poc"] / s["cves"]) if s["cves"] else None,
                     "top_cwes": ", ".join(f"{r['cwe']} ({r['share']:.0%})" for r in top if r["share"] is not None),
                     "basis": ", ".join(f"{k} {v}" for k, v in s["basis"].most_common()) if f != ALL else "", "window": window_label,
                     "order": -1 if f == ALL else (F.FAMILY_ORDER.index(f) if f in F.FAMILY_ORDER else 99)})
    return rates, fams, index


def per_cve(targets, wanted, index, cwe_name):
    out = []
    for t in targets:
        cid = t["cve"]
        rec = wanted.get(cid, {})
        if t.get("from") == "kev":
            fam, ec, basis = F.classify(t.get("vendor", ""), t.get("product", ""), t.get("name", ""))
            if fam == F.UNCLASSIFIED and rec:
                fam, basis = rec["family"], rec["basis"]
        else:
            fam, basis = rec.get("family", F.UNCLASSIFIED), rec.get("basis", "")
        ids = rec.get("cwes") or [c.strip().upper() for c in str(t.get("cwes") or "").split(",") if CWE_RX.match(c.strip().upper())]
        cwe = ids[0] if ids else ""
        base, scope = None, "none"
        if cwe:
            cand = index.get((fam, cwe))
            if cand and cand["cves"] >= MIN_N and fam != F.UNCLASSIFIED:
                base, scope = cand, "family"
            else:
                cand = index.get((ALL, cwe))
                if cand and cand["cves"] >= MIN_N:
                    base, scope = cand, "all families"
        out.append({"cve": cid, "family": fam, "cwe": cwe, "more_cwes": len(ids) - 1 if ids else 0, "base_scope": scope,
                    "base_cves": base["cves"] if base else None, "base_rate": base["exploited_rate"] if base else None,
                    "base_lo": base["exploited_lo"] if base else None, "base_hi": base["exploited_hi"] if base else None, "lift": base["lift"] if base else None})
    return out


def main(raw5, raw, raw2, feeds, today):
    end = today - dt.timedelta(days=LAG_DAYS)
    start = end - dt.timedelta(days=WINDOW_DAYS)
    label = f"CVEs published {start.isoformat()} to {(end - dt.timedelta(days=1)).isoformat()}"
    kevdoc = json.load(open(os.path.join(raw, "kev.json")))
    kev = {v["cveID"] for v in kevdoc.get("vulnerabilities", [])}
    bt = load_bt(os.path.join(raw2, "cvss-bt.csv"))
    targets, seen = [], set()
    for name, src in (("kev.json", "kev"), ("early_warning.json", "ew")):
        p = os.path.join(feeds, name)
        for r in (json.load(open(p)) if os.path.exists(p) else []):
            if r.get("cve") and r["cve"] not in seen:
                seen.add(r["cve"])
                targets.append({**r, "from": src})
    window, wanted, cwe_name = scan(os.path.join(raw5, "cves.zip"), start.isoformat(), end.isoformat(), seen)
    rates, fams, index = build(window, bt, kev, cwe_name, label)
    rows = per_cve(targets, wanted, index, cwe_name)
    meta = {}
    mp = os.path.join(raw5, "cvelist.json")
    if os.path.exists(mp):
        meta = json.load(open(mp))
    for f in fams:
        f["cvelist"] = meta.get("tag", "")
        f["cvelist_as_of"] = meta.get("as_of", "")
    for name, data in (("weakness_rates.json", rates), ("weakness_families.json", fams), ("weakness_cve.json", rows)):
        p = os.path.join(feeds, name)
        with open(p, "w") as fh:
            json.dump(data, fh, separators=(",", ":"), ensure_ascii=False)
        print(f"{name}: {len(data)} rows, {os.path.getsize(p) / 1024:.0f} KB")
    scopes = Counter(r["base_scope"] for r in rows)
    print(f"window {label}: {len(window)} CVEs; per-CVE bases {dict(scopes)}; families {len(fams)}")
    return rates, fams, rows


# ---------------------------------------------------------------- self-test on a synthetic archive
def fe_rate(fams):
    return next(f for f in fams if f["family"] == F.EDGE)["family_rate"]


def _self_test():
    tmp = tempfile.mkdtemp(prefix="kti-baserates-")
    raw5, raw, raw2, feeds = (os.path.join(tmp, d) for d in ("raw5", "raw", "raw2", "feeds"))
    for d in (raw5, raw, raw2, feeds):
        os.makedirs(d)
    today = dt.date(2026, 11, 22)
    inwin = "2025-06-01T00:00:00Z"

    def rec(cid, vendor, product, cwes, pub=inwin, cna="acme", state="PUBLISHED", adp=None):
        pt = [{"descriptions": [{"cweId": c, "description": f"{c} Name of {c}", "lang": "en", "type": "CWE"} for c in cwes]}] if cwes else []
        r = {"cveMetadata": {"cveId": cid, "state": state, "datePublished": pub, "assignerShortName": cna},
             "containers": {"cna": {"affected": [{"vendor": vendor, "product": product}], "problemTypes": pt, "descriptions": [{"lang": "en", "value": "x"}]}}}
        if adp:
            r["containers"]["adp"] = [{"problemTypes": [{"descriptions": [{"cweId": c, "description": c} for c in adp]}]}]
        return r
    recs, bt = [], [["cve", "cisa_kev", "vulncheck_kev", "metasploit", "nuclei", "exploitdb", "poc_github"]]
    # 40 Fortinet CWE-787 CVEs, 10 exploited (4 via VulnCheck, 6 via CISA KEV); 40 Fortinet CWE-79, 0 exploited.
    for i in range(40):
        cid = f"CVE-2025-1{i:04d}"
        recs.append(rec(cid, "Fortinet", "FortiOS", ["CWE-787"]))
        bt.append([cid, str(4 <= i < 10), str(i < 4), str(i < 2), "False", "False", "False"])
    for i in range(40):
        cid = f"CVE-2025-2{i:04d}"
        recs.append(rec(cid, "Fortinet", "FortiGate", ["CWE-79"]))
        bt.append([cid, "False", "False", "False", "False", "False", str(i < 3)])
    # 20 browser CWE-787 CVEs (too few for a family cell), 2 exploited; one CVE with two CWEs; one without a CWE.
    for i in range(20):
        cid = f"CVE-2025-3{i:04d}"
        recs.append(rec(cid, "Google", "Chrome", ["CWE-787"], cna="Chrome"))
        bt.append([cid, str(i < 2), "False", "False", "False", "False", "False"])
    recs.append(rec("CVE-2025-40000", "Fortinet", "FortiOS", ["CWE-787", "CWE-79"]))
    recs.append(rec("CVE-2025-40001", "Fortinet", "FortiOS", [], adp=["CWE-787"]))
    recs.append(rec("CVE-2025-40002", "Fortinet", "FortiOS", []))
    # Outside the window: counted nowhere, yet annotated when it is a KEV row. One rejected record is skipped.
    recs.append(rec("CVE-2019-0001", "Google", "Chrome", ["CWE-787"], pub="2019-01-01T00:00:00Z", cna="Chrome"))
    recs.append(rec("CVE-2025-49999", "Fortinet", "FortiOS", ["CWE-787"], state="REJECTED"))
    with zipfile.ZipFile(os.path.join(raw5, "cves.zip"), "w") as z:
        for r in recs:
            cid = r["cveMetadata"]["cveId"]
            z.writestr(f"cves/{cid[4:8]}/x/{cid}.json", json.dumps(r))
    with open(os.path.join(raw2, "cvss-bt.csv"), "w", newline="") as f:
        csv.writer(f).writerows(bt)
    json.dump({"vulnerabilities": [{"cveID": "CVE-2019-0001"}, {"cveID": "CVE-2025-30019"}]}, open(os.path.join(raw, "kev.json"), "w"))
    json.dump([{"cve": "CVE-2019-0001", "vendor": "Google", "product": "Chromium V8", "name": "Google Chromium V8 Type Confusion", "cwes": "CWE-843"},
               {"cve": "CVE-2025-10001", "vendor": "Fortinet", "product": "FortiOS", "name": "Fortinet FortiOS Heap Overflow", "cwes": ""}],
              open(os.path.join(feeds, "kev.json"), "w"))
    json.dump([{"cve": "CVE-2025-40002"}, {"cve": "CVE-2025-30001"}], open(os.path.join(feeds, "early_warning.json"), "w"))
    rates, fams, rows = main(raw5, raw, raw2, feeds, today)
    ok = []

    def check(c, m):
        if not c:
            print("FAIL " + m)
            sys.exit(1)
        ok.append(m)
    by = {(r["family"], r["cwe"]): r for r in rates}
    edge787 = by[(F.EDGE, "CWE-787")]
    # 40 + the two-CWE CVE + the ADP-only CVE = 42; exploited 10 (CISA or VulnCheck, never counted twice).
    check(edge787["cves"] == 42 and edge787["exploited"] == 10 and edge787["weaponized"] == 2, f"edge CWE-787 cell {edge787}")
    check(abs(edge787["exploited_rate"] - 10 / 42) < 1e-4 and edge787["exploited_lo"] < edge787["exploited_rate"] < edge787["exploited_hi"], "rate inside its Wilson interval")
    check(abs(fe_rate(fams) - 10 / 82) < 1e-4, "the family rate counts CWE-known CVEs")
    edge79 = by[(F.EDGE, "CWE-79")]
    check(edge79["cves"] == 41 and edge79["exploited"] == 0 and edge79["poc"] == 3 and edge79["exploited_lo"] == 0.0, f"edge CWE-79 cell {edge79}")
    fe = next(f for f in fams if f["family"] == F.EDGE)
    check(fe["cves"] == 83 and fe["with_cwe"] == 82 and abs(fe["cwe_coverage"] - 82 / 83) < 1e-4, f"family coverage {fe}")
    check(abs(edge787["lift"] - (10 / 42) / (10 / 82)) < 1e-2, f"lift against the family rate {edge787['lift']}")
    check(abs(edge787["share"] - 42 / 82) < 1e-4, "share of the family's CWE-known CVEs")
    allr = by[(ALL, "CWE-787")]
    # The browser cell: two exploited by CVSS-BT and CVE-2025-30019 by the KEV catalog alone.
    check(allr["cves"] == 62 and allr["exploited"] == 13 and by[("Browsers", "CWE-787")]["exploited"] == 3, f"all-families cell {allr}")
    check(by[("Browsers", "CWE-787")]["small"] is True, "a 20-CVE cell is marked small")
    check(not any(r["cwe"] == "CWE-787" and r["cves"] == 63 for r in rates), "out-of-window and rejected records are not counted")
    rc = {r["cve"]: r for r in rows}
    k1 = rc["CVE-2019-0001"]
    check(k1["family"] == "Browsers" and k1["cwe"] == "CWE-787" and k1["base_scope"] == "all families" and k1["base_cves"] == 62,
          f"a KEV CVE outside the window takes its record's CWE, and the all-families base when its family cell is small: {k1}")
    k2 = rc["CVE-2025-10001"]
    check(k2["family"] == F.EDGE and k2["base_scope"] == "family" and k2["base_cves"] == 42, f"family base {k2}")
    e1 = rc["CVE-2025-40002"]
    check(e1["cwe"] == "" and e1["base_scope"] == "none" and e1["base_rate"] is None, f"no CWE, no base {e1}")
    check(rc["CVE-2025-10001"]["more_cwes"] == 0 and abs(k2["base_rate"] - 10 / 42) < 1e-4, "per-CVE base rate")
    check(rc["CVE-2025-30001"]["family"] == "Browsers", "early-warning rows take the record's family")
    check(by[(ALL, "CWE-787")]["cwe_name"] == "Name of CWE-787", "CWE names come from the records' descriptions")
    check(fams[0]["family"] == ALL and fams[0]["cves"] == 103, f"All families counts every in-window CVE {fams[0]['cves']}")
    print(f"PASS {len(ok)} checks (weakness base rates)")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        _self_test()
    else:
        main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], dt.date.fromisoformat(sys.argv[5]) if len(sys.argv) > 5 else dt.date.today())
