#!/usr/bin/env python3
"""Download the threat-informed defense sources for build_defense.py. Downloads are untrusted data: nothing in RAW3 is run.

Run: python3 -I fetch_defense.py RAW3
Sources (all on GitHub; the cloud workspace reaches GitHub through its proxy):
  SigmaHQ/sigma                 detection rules (Detection Rule License 1.1); tags carry ATT&CK technique ids
  elastic/detection-rules       Elastic Security rules (Elastic License 2.0); [[rule.threat]] blocks carry technique ids
  splunk/security_content       Splunk detections (Apache-2.0); tags.mitre_attack_id
  redcanaryco/atomic-red-team   Atomic tests index (MIT); one row per test
  center-for-threat-informed-defense/top-attack-techniques       choke-point and actionability scores (Apache-2.0)
  center-for-threat-informed-defense/technique-inference-engine  CTI report-to-technique dataset (Apache-2.0)
  center-for-threat-informed-defense/mappings-explorer           KEV, CRI Profile, NIST 800-53 and CIS mappings (Apache-2.0)
Git repositories are cloned shallow and sparse (rule folders only); single files are fetched raw. Each source's commit
(or the file's sha256 when fetched raw) goes into RAW3/provenance.json for the defense_sources dataset.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import datetime as dt

RAW3 = sys.argv[1]
os.makedirs(RAW3, exist_ok=True)
GH = "https://github.com"
RAWGH = "https://raw.githubusercontent.com"
prov, failures = {}, []


def run(args, cwd=None, timeout=900):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def clone(repo, name, sparse):
    dest = os.path.join(RAW3, name)
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    r = run(["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--sparse", f"{GH}/{repo}.git", dest])
    if r.returncode != 0:
        failures.append(f"{repo}: clone failed: {r.stderr.strip()[:200]}")
        return
    r = run(["git", "sparse-checkout", "set", *sparse], cwd=dest)
    if r.returncode != 0:
        failures.append(f"{repo}: sparse checkout failed: {r.stderr.strip()[:200]}")
        return
    log = run(["git", "log", "-1", "--format=%H %cI"], cwd=dest).stdout.split()
    prov[name] = {"repo": repo, "commit": log[0] if log else None, "commit_date": log[1] if len(log) > 1 else None, "fetched": dt.datetime.now(dt.timezone.utc).isoformat()[:19] + "Z"}


def raw(repo, branch, path, out):
    dest = os.path.join(RAW3, out)
    tmp = dest + ".part"
    for _ in range(3):
        r = run(["curl", "-sS", "-f", "--max-time", "300", "-o", tmp, f"{RAWGH}/{repo}/{branch}/{path}"])
        if r.returncode == 0 and os.path.getsize(tmp) > 0:
            os.replace(tmp, dest)
            head = run(["git", "ls-remote", f"{GH}/{repo}.git", "HEAD"]).stdout.split()
            prov[out] = {"repo": repo, "path": path, "commit": head[0] if head else None, "sha256": hashlib.sha256(open(dest, "rb").read()).hexdigest(),
                         "fetched": dt.datetime.now(dt.timezone.utc).isoformat()[:19] + "Z"}
            return
    if os.path.exists(tmp):
        os.remove(tmp)
    failures.append(f"{repo}/{path}: download failed")


clone("SigmaHQ/sigma", "sigma", ["rules", "rules-emerging-threats", "rules-threat-hunting", "rules-compliance", "rules-dfir"])
clone("elastic/detection-rules", "elastic", ["rules"])
clone("splunk/security_content", "splunk", ["detections"])
clone("center-for-threat-informed-defense/mappings-explorer", "mappings-explorer", ["mappings"])
raw("redcanaryco/atomic-red-team", "master", "atomics/Indexes/Indexes-CSV/index.csv", "art_index.csv")
raw("center-for-threat-informed-defense/top-attack-techniques", "main", "src/data/Techniques.json", "ctid_top_techniques.json")
raw("center-for-threat-informed-defense/top-attack-techniques", "main", "src/stores/calculator.store.ts", "ctid_top_calculator.ts")
raw("center-for-threat-informed-defense/technique-inference-engine", "main", "data/combined_dataset_full_frequency.json", "tie_dataset.json")
json.dump(prov, open(os.path.join(RAW3, "provenance.json"), "w"), indent=1)
print(json.dumps({"sources": sorted(prov), "failures": failures}, indent=1))
sys.exit(1 if failures and len(failures) == 8 else 0)
