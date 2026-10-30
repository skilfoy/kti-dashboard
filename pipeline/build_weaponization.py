#!/usr/bin/env python3
"""Date the risk milestones of each exploited (KEV) and early-warning CVE: published, first public PoC repository,
first weaponization (Nuclei template or Metasploit exploit module added), added to KEV (Automating CTI p344:
discovery, PoC, weaponization, commoditization; risk rises sharply at weaponization).

Inputs (untrusted data, parsed only):
  OUT/kev.json, OUT/early_warning.json     from build_data.py (CVE, vendor, product, published, KEV date, ransomware)
  RAW4/                                    from fetch_weaponization.py
Output: OUT/weaponization.json, one row per CVE, dates as YYYY-MM-DD (UTC) and day lags between milestones, and
OUT/weaponization_sources.json, each source's repository and commit.

What each date is, and is not:
  poc_first     creation of the oldest non-fork GitHub repository PoC-in-GitHub lists for the CVE. A repository can be a
                scanner, a write-up or a fake (fake PoCs carrying malware are a known lure), so this dates the first public
                repository naming the CVE; whether it held a working exploit is unknown. Repositories created more than 365 days before
                the CVE was published are left out as renamed or unrelated.
  nuclei_added  first commit adding a template file named for the CVE, on any path (templates move between folders).
  msf_added     first commit adding a Metasploit exploit module that references the CVE, followed back through exact
                renames to the module's first path.
  weaponized    the earlier of nuclei_added and msf_added.
Run: python3 -I build_weaponization.py RAW4 OUT YYYY-MM-DD
"""
import datetime as dt
import glob
import json
import os
import re
import statistics
import sys
from collections import defaultdict

RAW4, OUT = sys.argv[1], sys.argv[2]
TODAY = dt.date.fromisoformat(sys.argv[3]) if len(sys.argv) > 3 else dt.date.today()
PROV = json.load(open(os.path.join(RAW4, "provenance.json")))
CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def utc_day(stamp):
    """A git %cI or GitHub timestamp as its UTC calendar day."""
    try:
        return dt.datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone(dt.timezone.utc).date()
    except (ValueError, AttributeError):
        return None


def rows(name):
    p = os.path.join(OUT, name)
    if not os.path.exists(p):
        return []
    x = json.load(open(p))
    return x if isinstance(x, list) else x.get("rows", [])


def history(name):
    """(adds: path -> first day, renamed_from: new path -> old path) from a `git log --name-status` listing."""
    adds, ren, day = {}, {}, None
    for line in open(os.path.join(RAW4, f"{name}_added.txt"), encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        if line.startswith("@@"):
            day = utc_day(line[2:].strip())
            continue
        parts = line.split("\t")
        if not day or not parts or not parts[0]:
            continue
        if parts[0] == "A" and len(parts) == 2:
            if parts[1] not in adds or day < adds[parts[1]]:
                adds[parts[1]] = day
        elif parts[0].startswith("R") and len(parts) == 3:
            ren.setdefault(parts[2], parts[1])  # newest log entries come first; the first seen is the latest rename
    return adds, ren


def first_day(path, adds, ren):
    seen, best = 0, adds.get(path)
    while path in ren and seen < 20:
        path, seen = ren[path], seen + 1
        if path in adds and (best is None or adds[path] < best):
            best = adds[path]
    return best


# ---------------------------------------------------------------- Nuclei: first template per CVE, still present at HEAD
n_adds, _ = history("nuclei")
present = {m.group(0).upper() for p in open(os.path.join(RAW4, "nuclei_tree.txt")).read().split() if p.endswith((".yaml", ".yml")) for m in [CVE.search(os.path.basename(p))] if m}
nuclei = {}
for path, day in n_adds.items():
    if not path.endswith((".yaml", ".yml")):
        continue
    m = CVE.search(os.path.basename(path))
    if m and m.group(0).upper() in present:
        c = m.group(0).upper()
        if c not in nuclei or day < nuclei[c]:
            nuclei[c] = day

# ---------------------------------------------------------------- Metasploit: first exploit module per CVE
m_adds, m_ren = history("msf")
meta = json.load(open(os.path.join(RAW4, "msf_metadata.json")))
msf, msf_mod = {}, {}
for key, mod in meta.items():
    if mod.get("type") != "exploit":
        continue
    path = (mod.get("path") or "").lstrip("/")
    day = first_day(path, m_adds, m_ren)
    if not day:
        continue
    for ref in mod.get("references") or []:
        m = CVE.fullmatch(str(ref).strip())
        if m:
            c = m.group(0).upper()
            if c not in msf or day < msf[c]:
                msf[c], msf_mod[c] = day, mod.get("fullname")

# ---------------------------------------------------------------- PoC-in-GitHub: first non-fork repository
poc = {}
for p in glob.glob(os.path.join(RAW4, "poc", "*", "CVE-*.json")):
    c = os.path.basename(p)[:-5].upper()
    try:
        repos = json.load(open(p))
    except Exception:
        continue
    poc[c] = [r for r in repos if isinstance(r, dict) and not r.get("fork") and r.get("created_at")]

# ---------------------------------------------------------------- one row per CVE
kev = {r["cve"]: r for r in rows("kev.json")}
ew = {r["cve"]: r for r in rows("early_warning.json")}
d = lambda a, b: (b - a).days if a and b else None
KEV_LAUNCH = dt.date(2021, 11, 3)
out = []
for c in sorted(set(kev) | set(ew)):
    k, e = kev.get(c), ew.get(c)
    src = k or e
    pub = dt.date.fromisoformat(src["published"]) if src.get("published") else None
    reps = [r for r in poc.get(c, []) if not pub or utc_day(r["created_at"]) >= pub - dt.timedelta(days=365)]
    reps.sort(key=lambda r: r["created_at"])
    pf = utc_day(reps[0]["created_at"]) if reps else None
    nu, ms = nuclei.get(c), msf.get(c)
    wp = min([x for x in (nu, ms) if x], default=None)
    ka = dt.date.fromisoformat(k["date_added"]) if k and k.get("date_added") else None
    first_signal = min([x for x in (pf, wp) if x], default=None)
    out.append({
        "cve": c, "vendor": src.get("vendor"), "product": src.get("product"), "in_kev": "Yes" if k else "No",
        "ransomware": (k or {}).get("ransomware") if k else None, "edge_class": src.get("edge_class"),
        "published": pub.isoformat() if pub else None, "poc_first": pf.isoformat() if pf else None, "poc_repos": len(reps),
        "poc_repo": reps[0]["full_name"] if reps else None,
        "nuclei_added": nu.isoformat() if nu else None, "msf_added": ms.isoformat() if ms else None, "msf_module": msf_mod.get(c),
        "weaponized": wp.isoformat() if wp else None, "kev_added": ka.isoformat() if ka else None,
        "days_pub_to_poc": d(pub, pf), "days_pub_to_weapon": d(pub, wp), "days_pub_to_kev": d(pub, ka),
        # KEV opened on 3 November 2021 with a backfill of older CVEs, so only CVEs published since then measure how
        # public weaponization and CISA's listing race; older ones measure the catalog's start date (Fleurat et al. ch13).
        "cohort": ("Since KEV launch" if pub >= KEV_LAUNCH else "Before KEV launch") if pub else None,
        # Positive lead: public weaponization came that many days before CISA catalogued exploitation.
        "weapon_lead_days": d(wp, ka) if wp and ka else None,
        "weapon_before_kev": ("Yes" if wp < ka else "No") if wp and ka else None,
        "days_since_weapon": (TODAY - wp).days if wp and not k else None,
        "signal_before_kev": ("Yes" if first_signal < ka else "No") if first_signal and ka else None,
        "stage": "Exploited (KEV)" if k else ("Weaponized" if wp else ("PoC public" if pf else "Published")),
    })
# Empty cells are left out: the dashboard reads a file's columns as the union of its rows' keys and a missing cell as null.
json.dump([{k: v for k, v in r.items() if v is not None} for r in out], open(os.path.join(OUT, "weaponization.json"), "w"), ensure_ascii=False, separators=(",", ":"))
SRC = [("S-POCGH", "PoC-in-GitHub", "nomi-sec/PoC-in-GitHub", "poc", len(poc), "No licence stated; dates, counts and repository names only", "GitHub repositories naming each CVE, indexed by nomi-sec; created_at of the oldest non-fork repository."),
       ("S-NUC", "Nuclei templates", "projectdiscovery/nuclei-templates", "nuclei", len(nuclei), "MIT", "First commit adding a template named for each CVE, from the repository history."),
       ("S-MSF", "Metasploit Framework", "rapid7/metasploit-framework", "msf", len(msf), "BSD-3-Clause", "First commit adding an exploit module that references each CVE, followed through exact renames.")]
json.dump([{"source_id": a, "name": b, "repo": c, "commit": PROV.get(k, {}).get("commit"), "commit_date": PROV.get(k, {}).get("commit_date"), "items": n, "terms": t, "note": note,
            "url": "https://github.com/" + c} for a, b, c, k, n, t, note in SRC], open(os.path.join(OUT, "weaponization_sources.json"), "w"), indent=1)

kv = [r for r in out if r["in_kev"] == "Yes"]
med = lambda xs: statistics.median(xs) if xs else None
print(json.dumps({
    "rows": len(out), "kev": len(kv), "early_warning_only": len(out) - len(kv),
    "with_poc": sum(1 for r in out if r["poc_first"]), "with_nuclei": sum(1 for r in out if r["nuclei_added"]), "with_msf": sum(1 for r in out if r["msf_added"]),
    "kev_weapon_before": sum(1 for r in kv if r["weapon_before_kev"] == "Yes"), "kev_weapon_after": sum(1 for r in kv if r["weapon_before_kev"] == "No"),
    "since_launch_before": sum(1 for r in kv if r["cohort"] == "Since KEV launch" and r["weapon_before_kev"] == "Yes"),
    "since_launch_after": sum(1 for r in kv if r["cohort"] == "Since KEV launch" and r["weapon_before_kev"] == "No"),
    "median_lead_since_launch": med([r["weapon_lead_days"] for r in kv if r["cohort"] == "Since KEV launch" and r["weapon_lead_days"] is not None]),
    "median_weapon_lead_kev": med([r["weapon_lead_days"] for r in kv if r["weapon_lead_days"] is not None]),
    "median_pub_to_poc_kev": med([r["days_pub_to_poc"] for r in kv if r["days_pub_to_poc"] is not None]),
    "nuclei_cves": len(nuclei), "msf_cves": len(msf), "poc_files": len(poc), "sources": {k: v.get("commit") for k, v in PROV.items()},
}, indent=1))
