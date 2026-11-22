#!/usr/bin/env python3
"""Normalize public CTI sources into dashboard datasets.

Inputs (downloaded to data/raw, treated as untrusted data):
  kev.json                 CISA KEV catalog (github.com/cisagov/kev-data)
  cve/*.json               CVE JSON 5 records (github.com/CVEProject/cvelistV5)
  attack-current.json      MITRE ATT&CK Enterprise STIX, newest release (attack-20.0.json accepted)
  attack-previous.json     MITRE ATT&CK Enterprise STIX, previous release, for diffs (attack-19.2.json accepted)
  csafdocs/*.json          CISA ICS advisories in CSAF 2.0 (github.com/cisagov/CSAF)
Second input directory (RAW2, also untrusted data):
  cvss-bt.csv              CVSS-BT enrichment (github.com/t0sche/cvss-bt): EPSS, CISA/VulnCheck KEV,
                           Exploit-DB, Metasploit, Nuclei and GitHub PoC flags for every CVE
  cve_ew/*.json            CVE JSON 5 records for the pre-KEV early-warning candidates
  misp_threat_actor.json   MISP galaxy threat-actor cluster (github.com/MISP/misp-galaxy), carries CFR tracker fields
  tc_victims.jsonl         ThreatCluster ransomware leak-site victims snapshot (github.com/Jam0k/Threat-Intelligence-Datasets)
  tc_incidents.jsonl       ThreatCluster multi-outlet incident clusters snapshot (same repository)
Outputs (out/*.json): row arrays ready to attach as dashboard files.
Run: python3 -I build_data.py RAW RAW2 OUT YYYY-MM-DD
"""
import csv, json, os, re, sys, glob, datetime as dt
from collections import Counter, defaultdict

RAW = sys.argv[1]
RAW2 = sys.argv[2]
OUT = sys.argv[3]
TODAY = dt.date.fromisoformat(sys.argv[4]) if len(sys.argv) > 4 else dt.date.today()
os.makedirs(OUT, exist_ok=True)
csv.field_size_limit(10_000_000)

# CVSS-BT index: one row per CVE with exploitation and weaponization signals
BT = {}
with open(os.path.join(RAW2, "cvss-bt.csv"), newline="") as f:
    for r in csv.DictReader(f):
        BT[r["cve"]] = r


def flag(r, k):
    return bool(r) and r.get(k) == "True"


def epss_of(r):
    try:
        return round(float(r.get("epss") or 0), 5)
    except (TypeError, ValueError):
        return None


def dump(name, rows):
    p = os.path.join(OUT, name)
    with open(p, "w") as f:
        json.dump(rows, f, separators=(",", ":"), ensure_ascii=False)
    print(f"{name}: {len(rows)} rows, {os.path.getsize(p)/1024:.0f} KB")


def clean(s, n=None):
    if not s:
        return ""
    s = re.sub(r"\(Citation:[^)]*\)", "", s)
    s = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", s)
    s = re.sub(r"<[^>]+>", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    if n and len(s) > n:
        cut = s[:n]
        s = cut[: cut.rfind(" ")] + "…"
    return s


def first_sentences(s, k=2, n=420):
    s = clean(s)
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z])", s)
    return clean(" ".join(parts[:k]), n)


# ---------------------------------------------------------------- KEV + CVE
# The edge-device classes (EDGE_RULES, edge_class) live in families.py, which also holds the product families of the
# weakness base rates (build_baserates.py), so every vulnerability row on the site uses one taxonomy.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # this folder only: the product families module
from families import EDGE_RULES, edge_class  # noqa: E402,F401


def cvss_from(record):
    """Return (score, version, severity, source) preferring CNA then ADP, newest version first."""
    order = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]
    pools = []
    cna = record.get("containers", {}).get("cna", {})
    pools.append(("CNA", cna.get("metrics", [])))
    for adp in record.get("containers", {}).get("adp", []) or []:
        src = adp.get("providerMetadata", {}).get("shortName", "ADP")
        pools.append((src, adp.get("metrics", [])))
    for key in order:
        for src, metrics in pools:
            for m in metrics or []:
                if key in m:
                    c = m[key]
                    return (c.get("baseScore"), key.replace("cvssV", "").replace("_", "."), c.get("baseSeverity", ""), src)
    return (None, "", "", "")


def ssvc_from(record):
    for adp in record.get("containers", {}).get("adp", []) or []:
        for m in adp.get("metrics", []) or []:
            other = m.get("other", {})
            if other.get("type") == "ssvc":
                opts = {}
                for o in other.get("content", {}).get("options", []):
                    opts.update(o)
                return opts.get("Exploitation", ""), opts.get("Automatable", ""), opts.get("Technical Impact", "")
    return "", "", ""


def poc_from(record):
    urls = []
    for cont in [record.get("containers", {}).get("cna", {})] + (record.get("containers", {}).get("adp", []) or []):
        for r in cont.get("references", []) or []:
            tags = [t.lower() for t in r.get("tags", []) or []]
            u = r.get("url", "")
            if "exploit" in tags or "exploit-db.com" in u or "packetstormsecurity" in u:
                urls.append(u)
    return urls


def cwe_from(record):
    out = []
    for cont in [record.get("containers", {}).get("cna", {})] + (record.get("containers", {}).get("adp", []) or []):
        for pt in cont.get("problemTypes", []) or []:
            for d in pt.get("descriptions", []) or []:
                if d.get("cweId"):
                    out.append(d["cweId"])
    return sorted(set(out))


kev = json.load(open(os.path.join(RAW, "kev.json")))
kev_rows = []
for v in kev["vulnerabilities"]:
    cid = v["cveID"]
    rec = {}
    p = os.path.join(RAW, "cve", cid + ".json")
    if os.path.exists(p):
        try:
            rec = json.load(open(p))
        except Exception:
            rec = {}
    meta = rec.get("cveMetadata", {})
    published = (meta.get("datePublished") or "")[:10]
    score, ver, sev, src = cvss_from(rec) if rec else (None, "", "", "")
    expl, auto, impact = ssvc_from(rec) if rec else ("", "", "")
    poc = poc_from(rec) if rec else []
    cwes = sorted(set(v.get("cwes", []) or []) | set(cwe_from(rec) if rec else []))
    added = v["dateAdded"]
    due = v.get("dueDate", "")
    lag = None
    if published:
        lag = (dt.date.fromisoformat(added) - dt.date.fromisoformat(published)).days
    ransomware = v.get("knownRansomwareCampaignUse", "Unknown")
    milestone = "Commoditized (ransomware)" if ransomware == "Known" else "Exploited (KEV)"
    ec = edge_class(v["vendorProject"], v["product"], v["vulnerabilityName"])
    past_due = bool(due) and dt.date.fromisoformat(due) < TODAY
    missing = []
    if score is None:
        missing.append("CVSS")
    elif ver.startswith("2"):
        missing.append("CVSS v3+")
    if not cwes or cwes == ["NVD-CWE-noinfo"] or cwes == ["NVD-CWE-Other"]:
        missing.append("CWE")
    if not expl:
        missing.append("SSVC")
    bt = BT.get(cid, {})
    msf, nuc = flag(bt, "metasploit"), flag(bt, "nuclei")
    edb, ghp = flag(bt, "exploitdb"), flag(bt, "poc_github")
    window = (dt.date.fromisoformat(due) - dt.date.fromisoformat(added)).days if due else None
    kev_rows.append({
        "cve": cid,
        "vendor": v["vendorProject"],
        "product": v["product"],
        "name": v["vulnerabilityName"],
        "date_added": added,
        "due_date": due,
        "past_due": "Yes" if past_due else "No",
        "ransomware": ransomware,
        "milestone": milestone,
        "poc_public": "Yes" if (poc or edb or ghp) else "No",
        "weaponized": "Yes" if (msf or nuc) else "No",
        "metasploit": "Yes" if msf else "No",
        "nuclei": "Yes" if nuc else "No",
        "vulncheck_kev": "Yes" if flag(bt, "vulncheck_kev") else "No",
        "epss": epss_of(bt) if bt else None,
        "remediation_days": window,
        "published": published,
        "publish_to_kev_days": lag,
        "cvss": score,
        "cvss_version": ver,
        "cvss_severity": sev.title() if sev else "",
        "cvss_source": src,
        "ssvc_exploitation": expl,
        "ssvc_automatable": auto,
        "ssvc_technical_impact": impact,
        "cwes": ", ".join(cwes),
        "edge_class": ec or "Other",
        "data_gaps": ", ".join(missing) if missing else "None",
        "description": clean(v.get("shortDescription", ""), 400),
        "required_action": clean(v.get("requiredAction", ""), 240),
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cid}",
    })
kev_rows.sort(key=lambda r: (r["date_added"], r["cve"]), reverse=True)
dump("kev.json", kev_rows)

catalog = [{
    "catalog": "CISA KEV",
    "version": kev["catalogVersion"],
    "released": kev["dateReleased"][:19] + "Z",
    "count": kev["count"],
}]

# ---------------------------------------------------------------- ATT&CK

def load_attack(path):
    b = json.load(open(path))
    objs = [o for o in b["objects"] if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_id = {o["id"]: o for o in objs}
    coll = next((o for o in b["objects"] if o["type"] == "x-mitre-collection"), {})
    return objs, by_id, coll


def ext_id(o):
    for r in o.get("external_references", []) or []:
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id", "")
    return ""


def ext_url(o):
    for r in o.get("external_references", []) or []:
        if r.get("source_name") == "mitre-attack":
            return r.get("url", "")
    return ""


# fetch.py names the newest and previous Enterprise releases attack-current / attack-previous
_cur = os.path.join(RAW, "attack-current.json")
_prev = os.path.join(RAW, "attack-previous.json")
cur, cur_by, cur_coll = load_attack(_cur if os.path.exists(_cur) else os.path.join(RAW, "attack-20.0.json"))
prev, prev_by, prev_coll = load_attack(_prev if os.path.exists(_prev) else os.path.join(RAW, "attack-19.2.json"))

catalog.append({
    "catalog": "MITRE ATT&CK Enterprise",
    "version": cur_coll.get("x_mitre_version", "20.0"),
    "released": (cur_coll.get("modified") or "")[:19] + "Z",
    "count": sum(1 for o in cur if o["type"] == "attack-pattern"),
})

TACTIC_ORDER = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence",
                "privilege-escalation", "defense-evasion", "credential-access", "discovery",
                "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"]
TACTIC_LABEL = {t: t.replace("-", " ").title().replace("And", "and") for t in TACTIC_ORDER}

techs = {o["id"]: o for o in cur if o["type"] == "attack-pattern"}


def tactics_of(t):
    return [p["phase_name"] for p in t.get("kill_chain_phases", []) or [] if p.get("kill_chain_name") == "mitre-attack"]


def pairs(objs, by_id, src_type, tgt_type, rel="uses"):
    out = set()
    for o in objs:
        if o["type"] == "relationship" and o.get("relationship_type") == rel:
            s, t = by_id.get(o["source_ref"]), by_id.get(o["target_ref"])
            if s and t and s["type"] == src_type and t["type"] == tgt_type:
                out.add((ext_id(s), ext_id(t)))
    return out


gt_cur = pairs(cur, cur_by, "intrusion-set", "attack-pattern")
gt_prev = pairs(prev, prev_by, "intrusion-set", "attack-pattern")
gs_cur = pairs(cur, cur_by, "intrusion-set", "malware") | pairs(cur, cur_by, "intrusion-set", "tool")
camp_attr = pairs(cur, cur_by, "campaign", "intrusion-set", rel="attributed-to")
new_gt = gt_cur - gt_prev
groups_prev_ids = {ext_id(o) for o in prev if o["type"] == "intrusion-set"}
tech_by_ext = {ext_id(t): t for t in techs.values()}

COUNTRY_RX = [
    ("Russia", r"\bRussia|\bRussian|\bGRU\b|\bSVR\b|\bFSB\b"),
    ("China", r"\bChina\b|\bChinese\b|People's Republic of China|\bPRC\b|\bMSS\b|People's Liberation Army|\bPLA\b"),
    ("Iran", r"\bIran\b|\bIranian\b|\bIRGC\b|\bMOIS\b"),
    ("North Korea", r"North Korea|\bDPRK\b|Democratic People's Republic of Korea|Reconnaissance General Bureau|\bRGB\b"),
    ("Vietnam", r"\bVietnam"),
    ("Pakistan", r"\bPakistan"),
    ("India", r"\bIndia\b|\bIndian\b"),
    ("Belarus", r"\bBelarus"),
    ("Lebanon", r"\bLebanon|Hezbollah"),
    ("South Korea", r"South Korea(?!n)"),
    ("Turkey", r"\bTurkey\b|\bTürkiye"),
    ("UAE", r"United Arab Emirates|\bUAE\b"),
    ("Gaza / Hamas", r"\bHamas\b|\bGaza\b"),
]
ATTR_RX = r"attribut|sponsor|state-backed|state-sponsored|nation-state|government|intelligence|military|linked to|associated with|operat\w* (?:on behalf|in support)|unit \d|directorate|ministry"


def sponsor_statement(desc):
    """Country nexus exactly as ATT&CK's description states it (defining sentence first)."""
    sents = re.split(r"(?<=[.!?])\s+(?=[A-Z])", clean(desc))
    cands = sents[:1] + [x for x in sents[1:4] if re.search(r"attribut|sponsor|assessed|subordinate|on behalf|originat|based in|operat\w+ (?:from|out of)|regime|in association with|affiliat|work(?:ed|s|ing)? for|ministry of|intelligence service|security bureau", x, re.I)]
    for sent in cands:
        for country, rx in COUNTRY_RX:
            for m in re.finditer(rx, sent):
                pre = sent[max(0, m.start() - 70):m.start()].lower()
                if re.search(r"target|against|victim|organi[sz]ations in|entities in|focus(?:ed|ing)? on", pre):
                    continue
                return country, clean(sent, 300)
    return "", ""


def state_link(stmt, desc):
    d = clean(desc)
    if re.search(r"cybercriminal|financially[- ]motivated|ransomware-as-a-service|\bRaaS\b", d[:300], re.I) and not re.search(r"state-sponsored|state-backed|attributed to", d[:300], re.I):
        return "Criminal"
    if not stmt:
        return "Not stated"
    if re.search(r"state-sponsored|state-backed|state sponsored|attributed to|subordinate|regime|ministry|intelligence (?:service|directorate)|military unit|\bunit \d|general staff|guard corps|bureau", stmt, re.I):
        return "Suspected state" if re.search(r"suspected|possibly|likely|assessed", stmt, re.I) and not re.search(r"attributed to", stmt, re.I) else "State-attributed"
    if re.search(r"suspected|possibly|likely", stmt, re.I):
        return "Suspected state"
    return "Country nexus only"


def motivation(desc):
    d = clean(desc).lower()
    m = []
    if re.search(r"espionage|intelligence collection|information theft|steal(?:ing)? (?:information|data|intellectual)|cyber ?espionage", d):
        m.append("Espionage")
    if re.search(r"financial(?:ly)? motivated|financial gain|cybercrim|ransomware|extortion|theft of funds|cryptocurrency|bank|carding|fraud", d):
        m.append("Financial")
    if re.search(r"destructive|wiper|sabotage|disrupt", d):
        m.append("Destructive / disruptive")
    if re.search(r"hacktivis|ideolog|influence operation|information operation|propaganda", d):
        m.append("Ideological / influence")
    return ", ".join(m) if m else "Not stated"


group_rows = []
gt_by_group = defaultdict(set)
for g, t in gt_cur:
    gt_by_group[g].add(t)
gs_by_group = defaultdict(set)
for g, s in gs_cur:
    gs_by_group[g].add(s)
camps_by_group = defaultdict(list)
camp_objs = {ext_id(o): o for o in cur if o["type"] == "campaign"}
for c, g in camp_attr:
    camps_by_group[g].append(c)

for o in cur:
    if o["type"] != "intrusion-set":
        continue
    gid = ext_id(o)
    tset = gt_by_group.get(gid, set())
    tac_counts = Counter()
    for t in tset:
        to = tech_by_ext.get(t)
        if to:
            for ph in tactics_of(to):
                tac_counts[ph] += 1
    gaps = [TACTIC_LABEL[t] for t in TACTIC_ORDER if tac_counts.get(t, 0) == 0]
    country, stmt = sponsor_statement(o.get("description", ""))
    link = state_link(stmt, o.get("description", ""))
    if link == "Criminal" and country == "North Korea":
        link = "Suspected state"  # DPRK runs revenue crime as statecraft (Tiepolo & Sorensen p60)
    camps = sorted(camps_by_group.get(gid, []), key=lambda c: (camp_objs.get(c, {}).get("last_seen") or ""), reverse=True)
    last_camp = camp_objs.get(camps[0]) if camps else None
    row = {
        "group_id": gid,
        "name": o.get("name", ""),
        "aliases": ", ".join(a for a in (o.get("aliases") or []) if a != o.get("name"))[:300],
        "nexus": country or "Not stated",
        "state_link": link,
        "attribution_as_stated": stmt or "ATT&CK description carries no sponsor statement.",
        "motivation": motivation(o.get("description", "")),
        "summary": first_sentences(o.get("description", ""), 2, 420),
        "techniques": len(tset),
        "software": len(gs_by_group.get(gid, set())),
        "campaigns": len(camps),
        "latest_campaign": (last_camp or {}).get("name", ""),
        "latest_campaign_last_seen": ((last_camp or {}).get("last_seen") or "")[:10],
        "new_in_release": len({t for (g, t) in new_gt if g == gid}),
        "new_group": "Yes" if gid not in groups_prev_ids else "No",
        "tactic_gaps": ", ".join(gaps) if gaps else "None",
        "modified": (o.get("modified") or "")[:10],
        "url": ext_url(o),
    }
    for t in TACTIC_ORDER:
        row["t_" + t.replace("-", "_")] = tac_counts.get(t, 0)
    group_rows.append(row)
group_rows.sort(key=lambda r: (-r["techniques"], r["name"]))

# Second curator: the MISP threat-actor galaxy, which carries the Council on Foreign Relations
# cyber-operations tracker fields. ATT&CK and MISP are maintained separately, so agreement between
# them is two curated origins, and disagreement is shown side by side (Tiepolo & Sorensen p502-529; Arici 6.5).
ISO_NAME = {"CN": "China", "RU": "Russia", "IR": "Iran", "KP": "North Korea", "VN": "Vietnam", "PK": "Pakistan",
            "IN": "India", "BY": "Belarus", "LB": "Lebanon", "KR": "South Korea", "TR": "Turkey", "AE": "UAE",
            "PS": "Gaza / Hamas", "US": "United States", "UA": "Ukraine", "IL": "Israel", "BR": "Brazil",
            "NG": "Nigeria", "ID": "Indonesia", "TN": "Tunisia", "RO": "Romania", "FR": "France", "ES": "Spain",
            "GB": "United Kingdom", "KZ": "Kazakhstan", "SY": "Syria"}
CFR_NAME = {"China": "China", "People's Republic of China": "China", "Iran (Islamic Republic of)": "Iran",
            "Russian Federation": "Russia", "Korea (Democratic People's Republic of)": "North Korea",
            "Korea (Republic of)": "South Korea", "United States": "United States", "US": "United States",
            "Palestine": "Gaza / Hamas", "Pakistan": "Pakistan", "India": "India", "Belarus": "Belarus",
            "France": "France", "United Arab Emirates": "UAE", "Vietnam": "Vietnam", "Spain": "Spain",
            "Israel": "Israel", "Lebanon": "Lebanon"}
misp_values = json.load(open(os.path.join(RAW2, "misp_threat_actor.json")))["values"]
misp_by_gid = {}
for v in misp_values:
    m = v.get("meta", {}) or {}
    ids = {s for s in (m.get("synonyms") or []) if re.fullmatch(r"G\d{4}", s)}
    for ref in m.get("refs") or []:
        mm = re.search(r"attack\.mitre\.org/groups/(G\d{4})", ref)
        if mm:
            ids.add(mm.group(1))
    for i in ids:
        misp_by_gid.setdefault(i, v)


def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


for row in group_rows:
    v = misp_by_gid.get(row["group_id"])
    m = (v or {}).get("meta", {}) or {}
    misp_c = ISO_NAME.get(m.get("country") or "", m.get("country") or "")
    cfr = CFR_NAME.get(m.get("cfr-suspected-state-sponsor") or "", "")
    other = cfr or misp_c
    if not v:
        agree = "No MISP entry"
    elif row["nexus"] == "Not stated" and other:
        agree = "ATT&CK silent"
    elif row["nexus"] == "Not stated":
        agree = "Both silent"
    elif not other:
        agree = "MISP silent"
    elif other == row["nexus"] and (not cfr or not misp_c or cfr == misp_c):
        agree = "Agree"
    else:
        agree = "Diverge"
    row["misp_country"] = misp_c or ""
    row["cfr_sponsor"] = cfr
    row["cfr_incident_type"] = ", ".join(as_list(m.get("cfr-type-of-incident")))
    row["cfr_target_categories"] = ", ".join(as_list(m.get("cfr-target-category")))[:160]
    row["cfr_victim_countries"] = len(as_list(m.get("cfr-suspected-victims")))
    row["attribution_agreement"] = agree
    row["misp_url"] = f"https://github.com/MISP/misp-galaxy/blob/main/clusters/threat-actor.json#{v['uuid']}" if v else ""
dump("attack_groups.json", group_rows)

# technique prevalence
country_of = {r["group_id"]: r["nexus"] for r in group_rows}
users = defaultdict(set)
for g, t in gt_cur:
    users[t].add(g)
tech_rows = []
for t in techs.values():
    tid = ext_id(t)
    if not tid:
        continue
    us = users.get(tid, set())
    parent = tid.split(".")[0]
    tech_rows.append({
        "technique_id": tid,
        "name": t.get("name", ""),
        "parent_id": parent,
        "is_sub": "Yes" if "." in tid else "No",
        "tactics": ", ".join(TACTIC_LABEL[x] for x in tactics_of(t) if x in TACTIC_LABEL),
        "groups_using": len(us),
        "groups_russia": sum(1 for g in us if country_of.get(g) == "Russia"),
        "groups_china": sum(1 for g in us if country_of.get(g) == "China"),
        "groups_iran": sum(1 for g in us if country_of.get(g) == "Iran"),
        "groups_dprk": sum(1 for g in us if country_of.get(g) == "North Korea"),
        "new_users_in_release": sum(1 for (g, x) in new_gt if x == tid),
        "platforms": ", ".join(t.get("x_mitre_platforms", []) or []),
        "url": ext_url(t),
    })
tech_rows.sort(key=lambda r: (-r["groups_using"], r["technique_id"]))
dump("attack_techniques.json", tech_rows)

# group-technique pairs (for drill-down), with new flag
gname = {r["group_id"]: r["name"] for r in group_rows}
pair_rows = []
for g, t in sorted(gt_cur):
    to = tech_by_ext.get(t)
    if not to or g not in gname:
        continue
    pair_rows.append({
        "pair": f"{g}:{t}",
        "group_id": g,
        "group": gname[g],
        "technique_id": t,
        "technique": to.get("name", ""),
        "tactics": ", ".join(TACTIC_LABEL[x] for x in tactics_of(to) if x in TACTIC_LABEL),
        "new_in_release": "Yes" if (g, t) in new_gt else "No",
    })
dump("attack_group_techniques.json", pair_rows)

camp_rows = []
for cid, c in camp_objs.items():
    attributed = sorted(gname.get(g, g) for (cc, g) in camp_attr if cc == cid)
    camp_rows.append({
        "campaign_id": cid,
        "name": c.get("name", ""),
        "first_seen": (c.get("first_seen") or "")[:10],
        "last_seen": (c.get("last_seen") or "")[:10],
        "attributed_to": ", ".join(attributed) if attributed else "Unattributed in ATT&CK",
        "summary": first_sentences(c.get("description", ""), 2, 380),
        "url": ext_url(c),
    })
camp_rows.sort(key=lambda r: r["last_seen"], reverse=True)
dump("attack_campaigns.json", camp_rows)

# ---------------------------------------------------------------- CISA ICS advisories (CSAF)
kev_set = {r["cve"] for r in kev_rows}
ics_rows = []
for p in sorted(glob.glob(os.path.join(RAW, "csafdocs", "*.json"))):
    try:
        d = json.load(open(p))
    except Exception:
        continue
    doc = d.get("document", {})
    tr = doc.get("tracking", {})
    adv_id = tr.get("id", os.path.basename(p)[:-5].upper())
    notes = {n.get("title", ""): n.get("text", "") for n in doc.get("notes", []) or []}
    sectors = notes.get("Critical infrastructure sectors", "")
    countries = notes.get("Countries/areas deployed", "")
    hq = notes.get("Company headquarters location", "")
    vendors, products = [], []

    def walk(branches, vend=None):
        for b in branches or []:
            cat, name = b.get("category"), b.get("name", "")
            if cat == "vendor":
                vendors.append(name)
                walk(b.get("branches"), name)
            elif cat == "product_name":
                products.append(name)
                walk(b.get("branches"), vend)
            else:
                walk(b.get("branches"), vend)

    walk(d.get("product_tree", {}).get("branches", []))
    vulns = d.get("vulnerabilities", []) or []
    cves = sorted({v.get("cve") for v in vulns if v.get("cve")})
    maxs = None
    for v in vulns:
        for s in v.get("scores", []) or []:
            for k in ("cvss_v4", "cvss_v3", "cvss_v2"):
                if k in s and s[k].get("baseScore") is not None:
                    sc = s[k]["baseScore"]
                    maxs = sc if maxs is None or sc > maxs else maxs
    lower = adv_id.lower()
    ics_rows.append({
        "advisory_id": adv_id,
        "title": clean(doc.get("title", ""), 200),
        "published": (tr.get("initial_release_date") or "")[:10],
        "revised": (tr.get("current_release_date") or "")[:10],
        "vendor": ", ".join(sorted(set(vendors)))[:120] or "Unspecified",
        "products": ", ".join(sorted(set(products)))[:200],
        "cve_count": len(cves),
        "cves": ", ".join(cves)[:300],
        "in_kev": "Yes" if any(c in kev_set for c in cves) else "No",
        "max_cvss": maxs,
        "sectors": clean(sectors, 200) or "Not stated",
        "deployed": clean(countries, 120) or "Not stated",
        "vendor_hq": clean(hq, 80) or "Not stated",
        "medical": "Yes" if lower.startswith("icsma") else "No",
        "url": f"https://www.cisa.gov/news-events/ics-advisories/{lower}",
    })
ics_rows.sort(key=lambda r: (r["published"], r["advisory_id"]), reverse=True)
dump("ics_advisories.json", ics_rows)

dump("catalogs.json", catalog)
print("new group-technique relationships in release:", len(new_gt))

# ---------------------------------------------------------------- Vulnerability milestone ladder and early warning
# Ladder rungs (Automating CTI p344, extended with a weaponization rung from CVSS-BT signals):
#   Published -> PoC public -> Weaponized (Metasploit / Nuclei) -> Exploited (CISA or VulnCheck KEV) -> Commoditized (ransomware)
kev_by_cve = {r["cve"]: r for r in kev_rows}
WINDOW_START = (TODAY - dt.timedelta(days=365)).isoformat()


def rung(cve, r):
    k = kev_by_cve.get(cve)
    if k and k["ransomware"] == "Known":
        return 5
    if flag(r, "cisa_kev") or flag(r, "vulncheck_kev") or k:
        return 4
    if flag(r, "metasploit") or flag(r, "nuclei"):
        return 3
    if flag(r, "exploitdb") or flag(r, "poc_github"):
        return 2
    return 1


RUNG_LABEL = {1: "Published only", 2: "PoC public", 3: "Weaponized", 4: "Exploited", 5: "Commoditized (ransomware)"}
ladder = Counter()
bands = defaultdict(Counter)


def band(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "Not scored"
    if s >= 9:
        return "9.0-10 Critical"
    if s >= 7:
        return "7.0-8.9 High"
    if s >= 4:
        return "4.0-6.9 Medium"
    return "0.1-3.9 Low"


for cve, r in BT.items():
    if (r.get("published_date") or "")[:10] >= WINDOW_START:
        ladder[rung(cve, r)] += 1
        bands[band(r.get("base_score"))]["all_cves_12m"] += 1
for k in kev_rows:
    b = band(k["cvss"])
    bands[b]["kev_all"] += 1
    if k["ransomware"] == "Known":
        bands[b]["kev_ransomware"] += 1
ladder_rows = [{"rung": n, "stage": RUNG_LABEL[n], "cves": ladder.get(n, 0), "window": f"CVEs published {WINDOW_START} to {TODAY.isoformat()}"} for n in range(1, 6)]
dump("vuln_ladder.json", ladder_rows)
BAND_ORDER = ["9.0-10 Critical", "7.0-8.9 High", "4.0-6.9 Medium", "0.1-3.9 Low", "Not scored"]
band_rows = [{"band": b, "order": i, "all_cves_12m": bands[b]["all_cves_12m"], "kev_all": bands[b]["kev_all"], "kev_ransomware": bands[b]["kev_ransomware"]} for i, b in enumerate(BAND_ORDER)]
dump("cvss_bands.json", band_rows)

# Pre-KEV early warning: recent CVEs that CISA has not listed but that carry exploitation or weaponization evidence.
EW_START = (TODAY - dt.timedelta(days=200)).isoformat()
ew_rows = []
for cve, r in BT.items():
    pub = (r.get("published_date") or "")[:10]
    if pub < EW_START or flag(r, "cisa_kev"):
        continue
    e = epss_of(r) or 0
    vk, msf, nuc, edb, ghp = (flag(r, x) for x in ("vulncheck_kev", "metasploit", "nuclei", "exploitdb", "poc_github"))
    if not (vk or msf or nuc or e >= 0.1):
        continue
    rec = {}
    p = os.path.join(RAW2, "cve_ew", cve + ".json")
    if os.path.exists(p):
        try:
            rec = json.load(open(p))
        except Exception:
            rec = {}
    cna = rec.get("containers", {}).get("cna", {})
    aff = (cna.get("affected") or [{}])[0] if cna else {}
    vendor = clean(aff.get("vendor", "") or "", 60)
    product = clean(aff.get("product", "") or "", 80)
    desc = ""
    for d in cna.get("descriptions", []) or []:
        if d.get("lang", "").startswith("en"):
            desc = d.get("value", "")
            break
    score, ver, sev, src = cvss_from(rec) if rec else (None, "", "", "")
    expl, auto, impact = ssvc_from(rec) if rec else ("", "", "")
    signals = []
    if vk:
        signals.append("VulnCheck KEV")
    if msf:
        signals.append("Metasploit")
    if nuc:
        signals.append("Nuclei")
    if edb:
        signals.append("Exploit-DB")
    if ghp:
        signals.append("GitHub PoC")
    if e >= 0.1:
        signals.append("EPSS>=0.10")
    top = 4 if vk else 3 if (msf or nuc) else 2 if (edb or ghp) else 1
    ew_rows.append({
        "cve": cve,
        "vendor": vendor or "Not stated",
        "product": product or "Not stated",
        "published": pub,
        "epss": e,
        "stage": RUNG_LABEL[top],
        "signals": ", ".join(signals),
        "signal_count": len(signals),
        "vulncheck_kev": "Yes" if vk else "No",
        "metasploit": "Yes" if msf else "No",
        "nuclei": "Yes" if nuc else "No",
        "poc_public": "Yes" if (edb or ghp) else "No",
        "cvss": score if score is not None else (float(r["base_score"]) if (r.get("base_score") or "").replace(".", "", 1).isdigit() else None),
        "cvss_version": ver or (r.get("cvss_version") if r.get("cvss_version") not in ("", "N/A") else ""),
        "ssvc_exploitation": expl,
        "ssvc_automatable": auto,
        "edge_class": edge_class(vendor, product, desc[:200]) or "Other",
        "record": "Yes" if rec else "Missing",
        "description": clean(desc, 300),
        "url": f"https://www.cve.org/CVERecord?id={cve}",
    })
ew_rows.sort(key=lambda x: (-["Published only", "PoC public", "Weaponized", "Exploited"].index(x["stage"]) if x["stage"] in ("Published only", "PoC public", "Weaponized", "Exploited") else 0, -x["epss"], x["cve"]))
dump("early_warning.json", ew_rows)

# KEV additions per month with remediation window, for the trend and the BOD 26-04 window change
kev_month = defaultdict(lambda: {"added": 0, "ransomware_known": 0, "edge": 0, "window_sum": 0, "window_n": 0})
for k in kev_rows:
    m = k["date_added"][:7]
    if m < (TODAY.replace(day=1) - dt.timedelta(days=730)).isoformat()[:7]:
        continue
    x = kev_month[m]
    x["added"] += 1
    x["ransomware_known"] += k["ransomware"] == "Known"
    x["edge"] += k["edge_class"] != "Other"
    if k["remediation_days"] is not None:
        x["window_sum"] += k["remediation_days"]
        x["window_n"] += 1
kev_month_rows = [{"month": m, "added": v["added"], "ransomware_known": v["ransomware_known"], "edge_devices": v["edge"],
                   "median_window_days": None, "mean_window_days": round(v["window_sum"] / v["window_n"], 1) if v["window_n"] else None}
                  for m, v in sorted(kev_month.items())]
for row in kev_month_rows:
    ws = sorted(k["remediation_days"] for k in kev_rows if k["date_added"][:7] == row["month"] and k["remediation_days"] is not None)
    row["median_window_days"] = ws[len(ws) // 2] if ws else None
dump("kev_monthly.json", kev_month_rows)

# ---------------------------------------------------------------- Ransomware leak-site claims (ThreatCluster snapshot)
# Aggregates only: victim names are left out on purpose (the dataset card asks users not to profile the injured parties).
# The publisher switched sector taxonomies in mid-July 2026; the newer labels are mapped back onto the
# earlier ones so the 90-day comparison measures activity rather than relabelling.
SECTOR_NORM = {"Financial": "Financial Services", "Finance": "Financial Services", "Energy & Utilities": "Energy",
               "Hospitality": "Hospitality and Tourism", "Transportation": "Transportation/Logistics",
               "Professional Services": "Business Services", "Retail & E-Commerce": "Consumer Services",
               "Retail": "Consumer Services", "Government & Defense": "Government", "Public Sector": "Government",
               "Healtcare": "Healthcare", "Manufacturer": "Manufacturing", "Consumer services": "Consumer Services",
               "Food and Agriculture": "Agriculture and Food Production", "Communication": "Telecommunication"}
victims = []
with open(os.path.join(RAW2, "tc_victims.jsonl")) as f:
    for line in f:
        try:
            v = json.loads(line)
        except Exception:
            continue
        if v.get("is_headline_style"):
            continue
        sec = (v.get("sector") or "").strip()
        if sec not in SECTOR_NORM and (len(sec) > 40 or "," in sec or sec in ("", "Not Found", "Other")):
            sec = "Not identified"
        v["_sector"] = SECTOR_NORM.get(sec, sec)
        v["_country"] = (v.get("country") or "").strip() or "Not identified"
        v["_group"] = (v.get("group_name") or "unknown").strip().lower()
        victims.append(v)
snap = max(v["discovered"] for v in victims if v.get("discovered"))
snap_d = dt.date.fromisoformat(snap)
p90 = (snap_d - dt.timedelta(days=90)).isoformat()
p180 = (snap_d - dt.timedelta(days=180)).isoformat()
last90 = [v for v in victims if v["discovered"] > p90]
prior90 = [v for v in victims if p180 < v["discovered"] <= p90]
g_last, g_prior = Counter(v["_group"] for v in last90), Counter(v["_group"] for v in prior90)
first_seen, last_seen, g_total = {}, {}, Counter()
for v in victims:
    g = v["_group"]
    g_total[g] += 1
    first_seen[g] = min(first_seen.get(g, v["discovered"]), v["discovered"])
    last_seen[g] = max(last_seen.get(g, v["discovered"]), v["discovered"])
grp_rows = []
for g in set(g_last) | set(g_prior):
    vs = [v for v in last90 if v["_group"] == g]
    secs = Counter(v["_sector"] for v in vs if v["_sector"] != "Not identified")
    ctry = Counter(v["_country"] for v in vs if v["_country"] != "Not identified")
    grp_rows.append({
        "group": g,
        "claims_last_90d": g_last.get(g, 0),
        "claims_prior_90d": g_prior.get(g, 0),
        "change": g_last.get(g, 0) - g_prior.get(g, 0),
        "status": "New in window" if first_seen[g] > p90 else ("Silent in window" if g_last.get(g, 0) == 0 else "Active"),
        "first_seen": first_seen[g],
        "last_seen": last_seen[g],
        "claims_all_time": g_total[g],
        "top_sector": secs.most_common(1)[0][0] if secs else "Not identified",
        "top_country": ctry.most_common(1)[0][0] if ctry else "Not identified",
        "us_share": round(sum(1 for v in vs if v["_country"] == "US") / len(vs), 3) if vs else None,
        "financial_claims_90d": sum(1 for v in vs if v["_sector"] == "Financial Services"),
    })
grp_rows.sort(key=lambda r: (-r["claims_last_90d"], r["group"]))
dump("ransomware_groups.json", grp_rows)

top_groups = [r["group"] for r in grp_rows[:10]]
month_rows = []
months = sorted({v["discovered"][:7] for v in victims if v["discovered"] >= "2024-07"})
mc = Counter((v["discovered"][:7], v["_group"] if v["_group"] in top_groups else "all other groups") for v in victims)
for m in months:
    for g in top_groups + ["all other groups"]:
        month_rows.append({"month": m, "group": g, "claims": mc.get((m, g), 0), "partial_month": "Yes" if m == snap[:7] else "No"})
dump("ransomware_monthly.json", month_rows)

sec_rows = []
s_last, s_prior = Counter(v["_sector"] for v in last90), Counter(v["_sector"] for v in prior90)
for s in sorted(set(s_last) | set(s_prior), key=lambda s: -s_last.get(s, 0)):
    sec_rows.append({"sector": s, "claims_last_90d": s_last.get(s, 0), "claims_prior_90d": s_prior.get(s, 0)})
dump("ransomware_sectors.json", sec_rows)
c_last, c_prior = Counter(v["_country"] for v in last90), Counter(v["_country"] for v in prior90)
ctry_rows = [{"country": c, "claims_last_90d": c_last.get(c, 0), "claims_prior_90d": c_prior.get(c, 0)}
             for c in sorted(set(c_last) | set(c_prior), key=lambda c: -c_last.get(c, 0))[:40]]
dump("ransomware_countries.json", ctry_rows)

# ---------------------------------------------------------------- Vector baseline (ThreatCluster multi-outlet incident clusters)
VECTOR_RULES = [
    ("Phishing & social engineering", r"phishing|social engineering|business email compromise|spear|smishing|vishing|callback"),
    ("Ransomware & malware", r"ransomware|malware|trojan|worm|wiper|infostealer|stealer|backdoor|rootkit|spyware|extortion"),
    ("DDoS", r"ddos|denial[- ]of[- ]service|\bdos\b"),
    ("Exploitation & edge devices", r"zero-day|exploit|remote code execution|sql injection|command injection|authentication bypass|path traversal|privilege escalation|code execution|ssrf|server-side request|deserializ"),
    ("Identity & valid accounts", r"credential stuffing|brute force|account takeover|credential theft|session hijack|mfa|token theft|password spray"),
    ("Supply chain", r"supply chain"),
    ("Insider", r"insider|treason"),
    ("Fraud", r"fraud|scam|flash loan|cross-chain|sextortion|identity fraud|money mule|carding"),
]
WEEKS = 26
wk_end = None
inc_rows = []
with open(os.path.join(RAW2, "tc_incidents.jsonl")) as f:
    for line in f:
        try:
            c = json.loads(line)
        except Exception:
            continue
        ents = c.get("entities") or {}
        at = " | ".join(ents.get("attack_type", []) or []).lower()
        if not at:
            continue
        vecs = [name for name, rx in VECTOR_RULES if re.search(rx, at)]
        if not vecs:
            continue
        inds = [i for i in ents.get("industry", []) or []]
        inc_rows.append((c.get("first_reported") or "", vecs, inds))
tc_snap = max(d for d, _, _ in inc_rows)
tc_end = dt.date.fromisoformat(tc_snap)
week0 = tc_end - dt.timedelta(days=tc_end.weekday())  # Monday of the snapshot week
vb = Counter()
for d, vecs, inds in inc_rows:
    try:
        dd = dt.date.fromisoformat(d)
    except ValueError:
        continue
    wk = dd - dt.timedelta(days=dd.weekday())
    if wk < week0 - dt.timedelta(weeks=WEEKS - 1) or wk > week0:
        continue
    fin = any(re.search(r"financ|bank|insurance|payment", i, re.I) for i in inds)
    for vname in vecs:
        vb[(wk.isoformat(), vname, "all")] += 1
        if fin:
            vb[(wk.isoformat(), vname, "financial")] += 1
vb_rows = []
for i in range(WEEKS):
    wk = (week0 - dt.timedelta(weeks=WEEKS - 1 - i)).isoformat()
    for vname, _ in VECTOR_RULES:
        vb_rows.append({"week": wk, "vector": vname, "incidents": vb.get((wk, vname, "all"), 0),
                        "financial_sector": vb.get((wk, vname, "financial"), 0), "partial_week": "Yes" if wk == week0.isoformat() else "No"})
dump("vector_baseline.json", vb_rows)

catalog.append({"catalog": "CVSS-BT (EPSS + exploit signals)", "version": max((r.get("published_date") or "")[:10] for r in BT.values()), "released": "", "count": len(BT)})
catalog.append({"catalog": "MISP galaxy threat actors", "version": str(json.load(open(os.path.join(RAW2, "misp_threat_actor.json"))).get("version", "")), "released": "", "count": len(misp_values)})
catalog.append({"catalog": "ThreatCluster leak-site claims", "version": snap, "released": snap, "count": len(victims)})
catalog.append({"catalog": "ThreatCluster incident clusters", "version": tc_snap, "released": tc_snap, "count": len(inc_rows)})
dump("catalogs.json", catalog)
