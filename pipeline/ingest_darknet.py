#!/usr/bin/env python3
"""Turn darknet-mcp-server results about the operator's own organization into the `exposure_darkweb` dataset.

Run the darknet-mcp-server tools against your own domains, accounts and egress IPs (in Claude with the server
connected, or from a script) and save the raw tool results in one bundle file:

{
  "org": "example.com",
  "observed": "2026-10-17",
  "domains": ["example.com"],
  "egress_ips": ["198.51.100.1"],
  "results": {
    "breachList":        [ <breach objects for the domain, from breachList {domain}> ],
    "breachSearch":      { "<account>": [ <breach objects> ], ... },
    "stealer_domain":    { "<domain>": { "total": N, "stealers": [ ... ] } },
    "ransomwareSearch":  { "<org term>": [ <victim objects> ] },
    "ransomlookRecent":  [ <post objects> ],
    "intelx_phonebook":  { "<term>": { "selectors": [ ... ] } },
    "greynoise_ip":      { "<ip>": { "classification": "benign|malicious|unknown", ... } },
    "abuseipdb_check":   { "<ip>": { "abuseConfidenceScore": 0-100, "totalReports": N, ... } },
    "tor_search_onion":  { "<query>": [ <result objects> ] }
  }
}

    python3 -I ingest_darknet.py bundle.json out/exposure_darkweb.json

Only counts, dates, family names and categories leave this script. Credentials, passwords, cookie data, machine
names, victim names and email addresses in the raw results are never copied into the dataset.
"""
import datetime as dt
import json
import re
import sys

EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def row(kind, tool, metric, detail, severity, csf, observed):
    detail = EMAIL.sub("[address]", detail)
    return {"kind": kind, "source_tool": tool, "metric": int(metric), "detail": detail, "severity": severity,
            "csf": csf, "observed": observed, "source": "darknet-mcp-server", "sample": False}


def days_ago(s, today):
    try:
        return (today - dt.date.fromisoformat(str(s)[:10])).days
    except ValueError:
        return None


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    b = json.load(open(sys.argv[1], encoding="utf-8"))
    res = b.get("results") or {}
    org = b.get("org") or "the organization"
    observed = b.get("observed") or dt.date.today().isoformat()
    today = dt.date.fromisoformat(observed)
    out = []

    # Leaked credentials: distinct accounts seen in any breach, plus domain-level breaches.
    accounts = {k for k, v in (res.get("breachSearch") or {}).items() if v}
    dom_breaches = res.get("breachList") or []
    recent_pw = [x for x in dom_breaches if "Passwords" in (x.get("DataClasses") or []) and (days_ago(x.get("BreachDate"), today) or 9999) <= 365]
    n = len(accounts)
    sev = "High" if n >= 100 or recent_pw else "Medium" if n or dom_breaches else "Low"
    out.append(row("Leaked credentials", "breachList + breachSearch (HIBP)", n,
                   f"{n} monitored account{'' if n == 1 else 's'} in known breach corpuses; {len(dom_breaches)} breach{'' if len(dom_breaches) == 1 else 'es'} list {org}, {len(recent_pw)} with passwords in the last year",
                   sev, "PR.AA", observed))

    # Infostealer infections: Hudson Rock stealer logs by domain. Counts and recency only.
    total, recent, newest = 0, 0, ""
    for v in (res.get("stealer_domain") or {}).values():
        total += int(v.get("total") or len(v.get("stealers") or []))
        for s in v.get("stealers") or []:
            d = str(s.get("date_compromised") or "")[:10]
            if d > newest:
                newest = d
            if (days_ago(d, today) or 9999) <= 180:
                recent += 1
    sev = "High" if recent else "Medium" if total else "Low"
    out.append(row("Infostealer infections", "stealer_domain (Hudson Rock)", total,
                   f"{total} infected machines carry {org} credentials in stealer logs; {recent} compromised in the last 180 days" + (f", newest {newest}" if newest else ""),
                   sev, "PR.AA", observed))

    # Ransomware mention: any leak-site listing that names the organization.
    hits = sum(len(v or []) for v in (res.get("ransomwareSearch") or {}).values())
    sev = "Critical" if hits else "Low"
    out.append(row("Ransomware mention", "ransomwareSearch + ransomlookRecent", hits,
                   f"{hits} leak-site listings match the organization's search terms" if hits else "No current leak-site listing names the organization",
                   sev, "DE.AE", observed))

    # Exposed secrets / selectors in leak and paste data (IntelligenceX phonebook).
    sel = sum(len((v or {}).get("selectors") or []) for v in (res.get("intelx_phonebook") or {}).values())
    out.append(row("Exposed secrets", "intelx_phonebook + intelx_search", sel,
                   f"{sel} selectors (addresses, hostnames, URLs) tied to {org} in leak and paste data",
                   "Medium" if sel else "Low", "PR.DS", observed))

    # Flagged egress IPs: GreyNoise malicious classification or AbuseIPDB confidence of 50 or more.
    gn = {ip for ip, v in (res.get("greynoise_ip") or {}).items() if (v or {}).get("classification") == "malicious"}
    ab = {ip for ip, v in (res.get("abuseipdb_check") or {}).items() if int((v or {}).get("abuseConfidenceScore") or 0) >= 50}
    flagged = gn | ab
    out.append(row("Flagged egress IP", "greynoise_ip + abuseipdb_check", len(flagged),
                   f"{len(flagged)} of {len(b.get('egress_ips') or [])} egress IPs flagged ({len(gn)} GreyNoise malicious, {len(ab)} AbuseIPDB score 50+)",
                   "Medium" if flagged else "Low", "DE.CM", observed))

    # Actor chatter on onion services that references the organization or sector.
    chatter = sum(len(v or []) for v in (res.get("tor_search_onion") or {}).values())
    out.append(row("Actor chatter", "tor_search_onion + intelx_search", chatter,
                   f"{chatter} onion-service results for the organization's monitoring queries",
                   "Medium" if chatter >= 10 else "Low", "ID.RA", observed))

    json.dump(out, open(sys.argv[2], "w", encoding="utf-8"), indent=1)
    print(f"wrote {len(out)} exposure rows to {sys.argv[2]}")


if __name__ == "__main__":
    main()
