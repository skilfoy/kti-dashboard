#!/usr/bin/env python3
"""Download every machine-collected source for the daily build. Downloads are untrusted data.

Run: python3 -I fetch.py RAW RAW2 YYYY-MM-DD
Only GitHub-hosted mirrors are fetched; the cloud workspace's network allowlist refuses most other hosts.
Each fetch is retried twice; a source that still fails is reported, and the build keeps the last good copy.
"""
import concurrent.futures as cf
import csv
import datetime as dt
import json
import os
import subprocess
import sys

RAW, RAW2 = sys.argv[1], sys.argv[2]
TODAY = dt.date.fromisoformat(sys.argv[3]) if len(sys.argv) > 3 else dt.date.today()
GH = "https://raw.githubusercontent.com"
for d in (RAW, RAW2, os.path.join(RAW, "cve"), os.path.join(RAW, "csafdocs"), os.path.join(RAW2, "cve_ew")):
    os.makedirs(d, exist_ok=True)
failures = []


def get(url, path, timeout=300):
    tmp = path + ".part"
    for _ in range(3):
        r = subprocess.run(["curl", "-sS", "-f", "--max-time", str(timeout), "-o", tmp, url], capture_output=True, text=True)
        if r.returncode == 0 and os.path.getsize(tmp) > 0:
            os.replace(tmp, path)
            return True
    if os.path.exists(tmp):
        os.remove(tmp)
    failures.append(url)
    return False


def many(pairs, workers=16):
    with cf.ThreadPoolExecutor(workers) as ex:
        list(ex.map(lambda p: get(p[0], p[1], 60), pairs))


def cve_url(c):
    y, n = c.split("-")[1], c.split("-")[2]
    return f"{GH}/CVEProject/cvelistV5/main/cves/{y}/{int(n) // 1000}xxx/{c}.json"


# CISA KEV
get(f"{GH}/cisagov/kev-data/develop/known_exploited_vulnerabilities.json", os.path.join(RAW, "kev.json"))
kev = json.load(open(os.path.join(RAW, "kev.json")))
many([(cve_url(v["cveID"]), os.path.join(RAW, "cve", v["cveID"] + ".json")) for v in kev["vulnerabilities"]])

# MITRE ATT&CK: newest and previous Enterprise releases
get(f"{GH}/mitre-attack/attack-stix-data/master/index.json", os.path.join(RAW, "attack_index.json"), 60)
idx = json.load(open(os.path.join(RAW, "attack_index.json")))
ent = next(c for c in idx["collections"] if c["name"] == "Enterprise ATT&CK")
vers = sorted(ent["versions"], key=lambda v: [int(x) for x in v["version"].split(".")], reverse=True)
json.dump({"current": vers[0]["version"], "previous": vers[1]["version"]}, open(os.path.join(RAW, "attack_versions.json"), "w"))
for tag, v in (("current", vers[0]), ("previous", vers[1])):
    target = os.path.join(RAW, f"attack-{tag}.json")
    stamp = os.path.join(RAW, f"attack-{tag}.version")
    if not (os.path.exists(target) and os.path.exists(stamp) and open(stamp).read() == v["version"]):
        if get(v["url"], target, 400):
            open(stamp, "w").write(v["version"])

# CISA ICS advisories (CSAF) from the ROLIE feed, last 120 days
get(f"{GH}/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json", os.path.join(RAW, "csaf_ot_feed.json"), 120)
feed = json.load(open(os.path.join(RAW, "csaf_ot_feed.json")))["feed"]["entry"]
cut = (TODAY - dt.timedelta(days=120)).isoformat()
pairs = []
for e in feed:
    if (e.get("published") or "")[:10] >= cut:
        src = (e.get("content") or {}).get("src", "")
        if src.startswith(GH + "/cisagov/CSAF/"):
            pairs.append((src, os.path.join(RAW, "csafdocs", os.path.basename(src))))
many(pairs)

# Second directory: enrichment and snapshots
get(f"{GH}/t0sche/cvss-bt/main/cvss-bt.csv", os.path.join(RAW2, "cvss-bt.csv"), 400)
get(f"{GH}/MISP/misp-galaxy/main/clusters/threat-actor.json", os.path.join(RAW2, "misp_threat_actor.json"), 120)
# Malpedia malware families with synonyms (the MISP galaxy cluster), for the entity gazetteer (build_gazetteer.py)
get(f"{GH}/MISP/misp-galaxy/main/clusters/malpedia.json", os.path.join(RAW2, "misp_malpedia.json"), 120)
B = f"{GH}/Jam0k/Threat-Intelligence-Datasets/main"
get(f"{B}/ransomware-leak-site-victims/data.jsonl", os.path.join(RAW2, "tc_victims.jsonl"), 200)
get(f"{B}/threat-incident-clusters/data.jsonl", os.path.join(RAW2, "tc_incidents.jsonl"), 300)

# CVE records for pre-KEV early-warning candidates (same rule as build_data.py)
csv.field_size_limit(10_000_000)
ew_cut = (TODAY - dt.timedelta(days=200)).isoformat()
want = []
with open(os.path.join(RAW2, "cvss-bt.csv"), newline="") as f:
    for r in csv.DictReader(f):
        if (r.get("published_date") or "")[:10] < ew_cut or r.get("cisa_kev") == "True":
            continue
        try:
            e = float(r.get("epss") or 0)
        except ValueError:
            e = 0
        if r.get("vulncheck_kev") == "True" or r.get("metasploit") == "True" or r.get("nuclei") == "True" or e >= 0.1:
            want.append(r["cve"])
many([(cve_url(c), os.path.join(RAW2, "cve_ew", c + ".json")) for c in want])

print(json.dumps({"kev": kev.get("catalogVersion"), "attack": [vers[0]["version"], vers[1]["version"]], "csaf_docs": len(pairs),
                  "early_warning_candidates": len(want), "failures": len(failures), "failed_urls": failures[:20]}, indent=1))
