#!/usr/bin/env python3
"""Download what build_weaponization.py needs to date each exploited or early-warning CVE's public PoC and weaponization.
Downloads are untrusted data: nothing in RAW4 is run, and the clones carry commit history without working trees.

Run: python3 -I fetch_weaponization.py RAW4 OUT      (OUT holds kev.json and early_warning.json from build_data.py)
Sources (GitHub, reached through the workspace proxy):
  nomi-sec/PoC-in-GitHub              per-CVE lists of GitHub repositories naming the CVE, with created_at (no stated licence;
                                      the build keeps dates, counts and the first repository's link only)
  projectdiscovery/nuclei-templates   Nuclei templates (MIT); commit history dates when each CVE template was added
  rapid7/metasploit-framework         Metasploit modules (BSD-3-Clause); commit history dates when each module was added,
                                      db/modules_metadata_base.json maps modules to CVEs
The two tool repositories are cloned blobless with full history, so `git log` can list file additions without
downloading file contents. PoC-in-GitHub is cloned at depth 1 and sparse-checked-out for the CVEs in OUT only.
"""
import datetime as dt
import json
import os
import shutil
import subprocess
import sys

RAW4, OUT = sys.argv[1], sys.argv[2]
os.makedirs(RAW4, exist_ok=True)
GH = "https://github.com"
failures, prov = [], {}
now = lambda: dt.datetime.now(dt.timezone.utc).isoformat()[:19] + "Z"


def run(args, cwd=None, stdin=None, out=None, timeout=1200):
    return subprocess.run(args, cwd=cwd, input=stdin, stdout=out or subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)


def fresh(name):
    d = os.path.join(RAW4, name)
    if os.path.isdir(d):
        shutil.rmtree(d)
    return d


def head(d):
    x = run(["git", "log", "-1", "--format=%H %cI"], cwd=d).stdout.split()
    return (x[0], x[1]) if len(x) > 1 else (None, None)


# Tool histories: every file addition with its commit date (exact renames kept, so a moved file keeps its first date)
for repo, name, paths in (("projectdiscovery/nuclei-templates", "nuclei", []), ("rapid7/metasploit-framework", "msf", ["modules/"])):
    d = fresh(name)
    r = run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", f"{GH}/{repo}.git", d])
    if r.returncode:
        failures.append(f"{repo}: clone failed: {r.stderr.strip()[:200]}")
        continue
    with open(os.path.join(RAW4, f"{name}_added.txt"), "w") as fh:
        r = run(["git", "log", "--diff-filter=AR", "-M100%", "--format=@@%cI", "--name-status", "HEAD", "--", *paths], cwd=d, out=fh)
    if r.returncode:
        failures.append(f"{repo}: log failed: {r.stderr.strip()[:200]}")
        continue
    with open(os.path.join(RAW4, f"{name}_tree.txt"), "w") as fh:
        run(["git", "ls-tree", "-r", "--name-only", "HEAD"], cwd=d, out=fh)
    c, cd = head(d)
    prov[name] = {"repo": repo, "commit": c, "commit_date": cd, "fetched": now()}
    if name == "msf":
        with open(os.path.join(RAW4, "msf_metadata.json"), "w") as fh:
            r = run(["git", "show", "HEAD:db/modules_metadata_base.json"], cwd=d, out=fh)
        if r.returncode:
            failures.append(f"{repo}: metadata read failed: {r.stderr.strip()[:200]}")

# PoC-in-GitHub: the files for the CVEs the dashboard holds
want = set()
for f, key in (("kev.json", "cve"), ("early_warning.json", "cve")):
    p = os.path.join(OUT, f)
    if os.path.exists(p):
        rows = json.load(open(p))
        want |= {r[key] for r in (rows if isinstance(rows, list) else rows.get("rows", [])) if r.get(key)}
d = fresh("poc")
r = run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", "--depth", "1", f"{GH}/nomi-sec/PoC-in-GitHub.git", d])
if r.returncode:
    failures.append(f"nomi-sec/PoC-in-GitHub: clone failed: {r.stderr.strip()[:200]}")
else:
    tree = run(["git", "ls-tree", "-r", "--name-only", "HEAD"], cwd=d).stdout.split()
    paths = ["/" + p for p in tree if os.path.basename(p)[:-5] in want]
    run(["git", "sparse-checkout", "init", "--no-cone"], cwd=d)
    r = run(["git", "sparse-checkout", "set", "--no-cone", "--stdin"], cwd=d, stdin="\n".join(paths) + "\n")
    r2 = run(["git", "checkout", "-q"], cwd=d)
    if r.returncode or r2.returncode:
        failures.append(f"nomi-sec/PoC-in-GitHub: sparse checkout failed: {(r.stderr or r2.stderr).strip()[:200]}")
    c, cd = head(d)
    prov["poc"] = {"repo": "nomi-sec/PoC-in-GitHub", "commit": c, "commit_date": cd, "fetched": now(), "indexed_cves": len(tree), "wanted": len(want), "checked_out": len(paths)}
json.dump(prov, open(os.path.join(RAW4, "provenance.json"), "w"), indent=1)
print(json.dumps({"sources": prov, "failures": failures}, indent=1))
sys.exit(1 if len(failures) >= 3 else 0)
