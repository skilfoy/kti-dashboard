#!/usr/bin/env python3
"""Download the CVE List V5 daily archive (every CVE record as of midnight UTC) for the weakness base rates.

Run: python3 -I fetch_cvelist.py RAW5 YYYY-MM-DD
The CVE Program publishes each day's full set as a release asset of CVEProject/cvelistV5: release cve_<DAY>_0000Z
carries <DAY-1>_all_CVEs_at_midnight.zip.zip (about 670 MB in November 2026), a zip holding cves.zip. The newest of the
last three days that answers is taken; RAW5/cvelist.json records which. Downloads are untrusted data: the archive is
only read by build_baserates.py, never executed.
"""
import datetime as dt
import json
import os
import subprocess
import sys
import zipfile

RAW5 = sys.argv[1]
TODAY = dt.date.fromisoformat(sys.argv[2]) if len(sys.argv) > 2 else dt.date.today()
os.makedirs(RAW5, exist_ok=True)
BASE = "https://github.com/CVEProject/cvelistV5/releases/download"
outer = os.path.join(RAW5, "cvelist_all.zip")
inner = os.path.join(RAW5, "cves.zip")


def asset(day):
    prev = day - dt.timedelta(days=1)
    return f"cve_{day.isoformat()}_0000Z", f"{BASE}/cve_{day.isoformat()}_0000Z/{prev.isoformat()}_all_CVEs_at_midnight.zip.zip", prev.isoformat()


got = None
for back in range(3):
    tag, url, as_of = asset(TODAY - dt.timedelta(days=back))
    tmp = outer + ".part"
    r = subprocess.run(["curl", "-sS", "-f", "-L", "--retry", "2", "--max-time", "900", "-o", tmp, url], capture_output=True, text=True)
    if r.returncode == 0 and os.path.exists(tmp) and os.path.getsize(tmp) > 50_000_000:
        os.replace(tmp, outer)
        got = {"tag": tag, "url": url, "as_of": as_of, "bytes": os.path.getsize(outer)}
        break
    if os.path.exists(tmp):
        os.remove(tmp)
    print(f"{tag}: not available ({(r.stderr or '').strip()[:160] or 'too small'})", flush=True)
if not got:
    sys.exit("no CVE List V5 midnight archive in the last three days")
with zipfile.ZipFile(outer) as z:
    names = z.namelist()
    if "cves.zip" not in names:
        sys.exit(f"unexpected archive layout: {names[:5]}")
    z.extract("cves.zip", RAW5)
os.remove(outer)
with zipfile.ZipFile(inner) as z:
    got["records"] = sum(1 for n in z.namelist() if n.endswith(".json") and "/CVE-" in n)
json.dump(got, open(os.path.join(RAW5, "cvelist.json"), "w"), indent=1)
print(json.dumps(got))
