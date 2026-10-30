#!/usr/bin/env python3
"""Turn AutoRecon results for the operator's own estate into the dashboard's `assets` dataset.

AutoRecon writes nmap XML per target under results/<target>/scans/xml/ (for example _full_tcp_nmap.xml and
_top_100_udp_nmap.xml). This script reads those files, keeps open ports with a service fingerprint, and joins
each host to a scope file that the operator maintains. A host that is not in the scope file is dropped and
reported: the dashboard only carries assets the operator owns or is authorized to test.

    python3 -I ingest_autorecon.py --results <AutoRecon results dir> --scope scope.csv --out out/assets.json

scope.csv columns (header row required): address,exposure,site[,hostname][,note]
    address    IPv4/IPv6 address or hostname as AutoRecon used it for the target
    exposure   Internet-facing | Internal
    site       free text (data center, branch, cloud account)

The output rows match build/authored_residual.py ASSETS (sample:false), so the page's KEV and early-warning
join, residual-risk calc and tables work unchanged.
"""
import argparse
import csv
import datetime as dt
import json
import os
import sys
import xml.etree.ElementTree as ET

EXPOSURES = {"Internet-facing", "Internal"}


def load_scope(path):
    scope = {}
    with open(path, newline="", encoding="utf-8") as f:
        for i, row in enumerate(csv.DictReader(f), start=2):
            addr = (row.get("address") or "").strip()
            exp = (row.get("exposure") or "").strip()
            if not addr:
                continue
            if exp not in EXPOSURES:
                sys.exit(f"scope.csv line {i}: exposure must be one of {sorted(EXPOSURES)}, got {exp!r}")
            scope[addr.lower()] = {"exposure": exp, "site": (row.get("site") or "").strip(),
                                   "hostname": (row.get("hostname") or "").strip(), "note": (row.get("note") or "").strip()}
    if not scope:
        sys.exit("scope.csv has no rows; refusing to ingest without an authorized scope")
    return scope


def xml_files(results):
    for target in sorted(os.listdir(results)):
        xdir = os.path.join(results, target, "scans", "xml")
        if not os.path.isdir(xdir):
            continue
        for name in sorted(os.listdir(xdir)):
            if name.endswith(".xml"):
                yield target, os.path.join(xdir, name)


def vendor_from_cpe(cpe):
    # cpe:/a:vendor:product:version or cpe:2.3:a:vendor:product:...
    parts = cpe.replace("cpe:2.3:", "cpe:/").split(":")
    return parts[2].replace("_", " ") if len(parts) > 2 else ""


def product_label(svc):
    product = (svc.get("product") or "").strip()
    cpes = [c.text for c in svc.findall("cpe") if c.text]
    cpe = cpes[0] if cpes else ""
    vendor = vendor_from_cpe(cpe)
    # Lead with the vendor so the page's vendor-first join to KEV has something to match.
    if vendor and product and not product.lower().startswith(vendor.split(" ")[0].lower()):
        product = f"{vendor.title()} {product}"
    return product, cpe


def parse(path):
    # nmap XML from the operator's own scans; ElementTree does not resolve external entities.
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as e:
        print(f"skip {path}: {e}", file=sys.stderr)
        return
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addrs = [a.get("addr") for a in host.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")]
        names = [n.get("name") for n in host.findall("hostnames/hostname") if n.get("name")]
        for port in host.findall("ports/port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = port.find("service")
            if svc is None:
                continue
            product, cpe = product_label(svc)
            yield {
                "ip": addrs[0] if addrs else "", "names": names, "port": int(port.get("portid")), "protocol": port.get("protocol"),
                "service": svc.get("name") or "", "product": product, "version": (svc.get("version") or "").strip(), "cpe": cpe,
            }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--min-fingerprint", action="store_true", help="drop ports nmap could not fingerprint (no product)")
    a = ap.parse_args()

    scope = load_scope(a.scope)
    rows, dropped, seen = [], set(), set()
    for target, path in xml_files(a.results):
        first_seen = dt.date.fromtimestamp(os.path.getmtime(path)).isoformat()
        for r in parse(path):
            keys = [target.lower(), r["ip"].lower()] + [n.lower() for n in r["names"]]
            sc = next((scope[k] for k in keys if k in scope), None)
            if sc is None:
                dropped.add(target)
                continue
            if a.min_fingerprint and not r["product"]:
                continue
            k = (r["ip"] or target, r["port"], r["protocol"])
            if k in seen:
                continue
            seen.add(k)
            rows.append({
                "host": sc["hostname"] or (r["names"][0] if r["names"] else target), "ip": r["ip"], "port": r["port"],
                "protocol": r["protocol"], "service": r["service"], "product": r["product"] or r["service"],
                "version": r["version"], "cpe": r["cpe"], "exposure": sc["exposure"], "site": sc["site"], "note": sc["note"],
                "first_seen": first_seen, "source": "AutoRecon", "sample": False,
            })
    if dropped:
        print(f"dropped {len(dropped)} target(s) not in scope.csv: {', '.join(sorted(dropped))}", file=sys.stderr)
    if not rows:
        sys.exit("no in-scope open services found; leaving the current assets dataset in place")
    # The page keys asset rows by host; make host unique per service.
    counts = {}
    for r in rows:
        counts[r["host"]] = counts.get(r["host"], 0) + 1
    for r in rows:
        if counts[r["host"]] > 1:
            r["host"] = f'{r["host"]}:{r["port"]}/{r["protocol"]}'
    rows.sort(key=lambda r: (r["exposure"] != "Internet-facing", r["host"]))
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=1)
    print(f"wrote {len(rows)} asset rows from {len(seen)} services to {a.out}")


if __name__ == "__main__":
    main()
