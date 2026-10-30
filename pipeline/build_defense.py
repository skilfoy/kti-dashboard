#!/usr/bin/env python3
"""Threat-informed defense datasets: what public detection and validation content exists for each ATT&CK technique,
how often CTI reporting observes it, which techniques co-occur, which KEV vulnerabilities lead to it, and which
financial-sector (CRI Profile) and NIST 800-53 controls mitigate it.

Inputs (untrusted data, parsed only):
  RAW/attack-current.json   MITRE ATT&CK Enterprise STIX, current release (from fetch.py)
  RAW/kev.json              CISA KEV catalog (from fetch.py)
  RAW2/misp_threat_actor.json  MISP galaxy threat-actor cluster (from fetch.py; RAW2 is the raw2 folder beside RAW)
  RAW3/...                  from fetch_defense.py: Sigma, Elastic and Splunk rule folders, the Atomic Red Team index,
                            CTID Top ATT&CK Techniques, CTID Technique Inference Engine dataset, CTID Mappings Explorer
Outputs (OUT/*.json, row arrays of primitives):
  defense_techniques  one row per current ATT&CK technique and sub-technique
  defense_cooccur     for each technique, the techniques CTI reports most often observe with it (TIE dataset)
  kev_attack          KEV CVEs mapped to ATT&CK exploitation and impact techniques (CTID KEV mappings)
  cri_crosswalk       CRI Profile v2.1 diagnostic statements and the techniques each mitigates (CTID mappings)
  defense_group_sectors  per ATT&CK group, the verticals whose sector its ATT&CK description or MISP targeted-sector names
  defense_telemetry   per technique, the ATT&CK data components its detection analytics read, with log source names
  defense_content     per technique, the top three Sigma, Elastic and Splunk rules and Atomic Red Team tests, titles and links
  defense_sources     each source's repository, commit, item count and terms
Older ATT&CK ids in the mappings are carried to the current release through ATT&CK's revoked-by relationships;
an id deprecated without a replacement is dropped and counted in defense_sources.
Run: python3 -I build_defense.py RAW RAW3 OUT YYYY-MM-DD
"""
import csv
import glob
import json
import math
import os
import re
import sys
import tomllib
import datetime as dt
from collections import Counter, defaultdict

import yaml

RAW, RAW3, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
TODAY = dt.date.fromisoformat(sys.argv[4]) if len(sys.argv) > 4 else dt.date.today()
os.makedirs(OUT, exist_ok=True)
PROV = json.load(open(os.path.join(RAW3, "provenance.json")))
TID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def dump(name, rows):
    json.dump(rows, open(os.path.join(OUT, name + ".json"), "w"), ensure_ascii=False, separators=(",", ":"))


# ---------------------------------------------------------------- ATT&CK current release
bundle = json.load(open(os.path.join(RAW, "attack-current.json")))
objs = bundle["objects"]
by_id = {o["id"]: o for o in objs}
ext = lambda o: next((r.get("external_id") for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
version = next((o.get("x_mitre_version") for o in objs if o["type"] == "x-mitre-collection"), None)
live = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")
tech = {}  # tid -> record
for o in objs:
    if o["type"] != "attack-pattern" or not live(o):
        continue
    t = ext(o)
    if not t or not TID.match(t):
        continue
    tech[t] = {"stix": o["id"], "name": o["name"], "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"],
               "is_sub": bool(o.get("x_mitre_is_subtechnique")), "platforms": o.get("x_mitre_platforms", []), "url": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}"}
stix2t = {v["stix"]: k for k, v in tech.items()}
tactic_name = {o["x_mitre_shortname"]: o["name"] for o in objs if o["type"] == "x-mitre-tactic" and live(o)}
# Old ids carried forward: revoked attack-patterns point at their replacement.
revoked_to = {}
for o in objs:
    if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by":
        s, t = by_id.get(o["source_ref"]), by_id.get(o["target_ref"])
        if s and t and s["type"] == "attack-pattern" and t["type"] == "attack-pattern" and ext(s) and ext(t):
            revoked_to[ext(s)] = ext(t)
dropped = Counter()


def cur(t, src):
    """An ATT&CK id from any release, as the current release names it (None when deprecated or unknown)."""
    t = (t or "").strip().upper()
    seen = 0
    while t in revoked_to and t not in tech and seen < 5:
        t, seen = revoked_to[t], seen + 1
    if t in tech:
        return t
    dropped[src] += 1
    return None


parent = lambda t: t.split(".")[0]
groups_by_t, mit_by_t, det_by_t, an_by_t = defaultdict(set), defaultdict(set), defaultdict(set), defaultdict(int)
live_groups = {o["id"] for o in objs if o["type"] == "intrusion-set" and live(o)}
for o in objs:
    if o["type"] != "relationship" or not live(o):
        continue
    rt, s, t = o.get("relationship_type"), o["source_ref"], o["target_ref"]
    if t not in stix2t:
        continue
    tid = stix2t[t]
    if rt == "uses" and s in live_groups:
        groups_by_t[tid].add(s)
    elif rt == "mitigates" and s.startswith("course-of-action--") and live(by_id.get(s, {})):
        mit_by_t[tid].add(s)
    elif rt == "detects" and s.startswith("x-mitre-detection-strategy--") and live(by_id.get(s, {})):
        det_by_t[tid].add(s)
        an_by_t[tid] += len(by_id[s].get("x_mitre_analytic_refs", []))

# ---------------------------------------------------------------- sector targeting stated for each group
# Sector relevance is the first test for choosing what to emulate (Tiepolo and Sorensen p573) and for which adversaries
# to map (Bhardwaj p142-143). A group counts as targeting a vertical's sector when ATT&CK's own description of it names
# that sector, or the MISP galaxy's targeted-sector field does. The evidence is the matched phrase, quoted short.
SECTOR_RX = {
    "financial": r"\bfinance\b|\bfinancial\b(?![- ](?:gain|motivat\w*|profit|theft|crime))|\bbanks?\b|banking|fintech|payment card|payment (?:systems?|processors?)|\bATMs?\b|SWIFT|cryptocurrency (?:exchanges?|firms?|compan\w*)|insurance|investment firms?",
    "energy": r"energy|\boil\b|natural gas|\bgas\b (?:compan|sector|industr)\w*|petro\w*|electric\w*|power (?:grid|plants?|compan\w*|sector|utilit\w*)|utilit(?:y|ies) (?:sector|compan\w*|providers?)|nuclear|pipelines?",
    "water": r"\bwater\b",
    "healthcare": r"health\w*|hospitals?\b|medical|pharma\w*|biotech\w*",
    "telecom": r"telecom\w*|internet service providers?|\bISPs?\b|mobile (?:network )?operators?",
    "government": r"government\w*|diplomat\w*|ministr(?:y|ies)|embass(?:y|ies)|military|defen[cs]e (?:sector|industr\w*|contractors?|organi[sz]ations?|ministr\w*)|public sector|law enforcement",
    "manufacturing": r"manufactur\w*|industrial|aerospace|automotive|semiconductor\w*|engineering|chemical\w*",
    "transportation": r"transport\w*|logistic\w*|aviation|airlines?|airports?|shipping|maritime|railways?|freight",
}
MISP_SECTOR = {
    "financial": {"Finance", "Bank", "Payment", "Investment"}, "energy": {"Energy", "Electric", "Gas", "Oil"}, "healthcare": {"Health", "Pharmacy"},
    "telecom": {"Telecoms"}, "government": {"Government, Administration", "Government Administration", "Defense", "Military", "Diplomacy", "Intelligence", "Security Service", "Justice"},
    "manufacturing": {"Manufacturing", "Industrial", "Aerospace", "Engineering", "Chemical", "Electronic"}, "transportation": {"Maritime"},
}
misp_path = os.path.join(os.path.dirname(os.path.abspath(RAW)), "raw2", "misp_threat_actor.json")
misp_by_gid = {}
if os.path.exists(misp_path):
    for mv in json.load(open(misp_path)).get("values", []):
        mm = mv.get("meta", {}) or {}
        gids = {s for s in (mm.get("synonyms") or []) if re.fullmatch(r"G\d{4}", str(s))}
        for ref in mm.get("refs") or []:
            hit = re.search(r"attack\.mitre\.org/groups/(G\d{4})", str(ref))
            if hit:
                gids.add(hit.group(1))
        for gid in gids:
            misp_by_gid.setdefault(gid, mm)
sector_rows = []
for o in objs:
    if o["type"] != "intrusion-set" or not live(o) or not ext(o):
        continue
    gid = ext(o)
    desc = re.sub(r"\(Citation:[^)]*\)", "", o.get("description") or "")
    desc = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", desc)
    # The group's own names come out first: Trend Micro's "Water ..." and "Earth ..." names are not targets.
    for alias in sorted({o.get("name") or ""} | set(o.get("aliases") or []), key=len, reverse=True):
        if alias:
            desc = desc.replace(alias, "the group")
    ms = set((misp_by_gid.get(gid) or {}).get("targeted-sector") or [])
    for vid, rx in SECTOR_RX.items():
        hit = re.search(rx, desc, re.I)
        misp_hit = sorted(ms & MISP_SECTOR.get(vid, set()))
        if not hit and not misp_hit:
            continue
        ev = None
        if hit:
            a, b = max(0, hit.start() - 70), min(len(desc), hit.end() + 70)
            ev = ("…" if a else "") + desc[a:b].replace("\n", " ").strip() + ("…" if b < len(desc) else "")
        sector_rows.append({"key": f"{gid}|{vid}", "group_id": gid, "vertical_id": vid, "source": " and ".join(x for x in ("ATT&CK description" if hit else None, "MISP targeted-sector" if misp_hit else None) if x),
                            "matched": hit.group(0) if hit else ", ".join(misp_hit), "evidence": ev or ("MISP galaxy targeted-sector: " + ", ".join(misp_hit))})

# ---------------------------------------------------------------- telemetry: the data components ATT&CK's analytics read
# Each detection strategy lists analytics; each analytic names the log sources it reads and the data component each one
# belongs to. One row per technique and data component: how many of the technique's analytics read that component, on
# which platforms, through which named log sources. This is the public half of a DeTT&CT visibility assessment: which
# telemetry a technique's detection depends on; the organization's own visibility score for each component is the half
# only its log owners can supply (Bhardwaj p179-182).
dc_name = {o["id"]: (ext(o), o["name"]) for o in objs if o["type"] == "x-mitre-data-component" and live(o)}
tele = defaultdict(lambda: {"analytics": 0, "logs": Counter(), "plat": set()})
for tid, strategies in det_by_t.items():
    for s in strategies:
        for a in by_id[s].get("x_mitre_analytic_refs", []):
            an = by_id.get(a)
            if not an or not live(an):
                continue
            seen_dc = set()
            for ref in an.get("x_mitre_log_source_references", []) or []:
                d = ref.get("x_mitre_data_component_ref")
                if d not in dc_name:
                    continue
                rec = tele[(tid, d)]
                if d not in seen_dc:
                    rec["analytics"] += 1
                    seen_dc.add(d)
                if ref.get("name"):
                    rec["logs"][ref["name"]] += 1
                rec["plat"].update(an.get("x_mitre_platforms", []) or [])
tele_rows = []
for (tid, d), rec in tele.items():
    dcid, dname = dc_name[d]
    tele_rows.append({"key": f"{tid}|{dcid}", "technique_id": tid, "dc_id": dcid, "data_component": dname, "analytics": rec["analytics"],
                      "log_sources": ", ".join(n for n, _ in rec["logs"].most_common(3)), "platforms": ", ".join(sorted(rec["plat"]))})
strategy_ref = {}
for tid, strategies in det_by_t.items():
    lst = sorted((ext(by_id[s]), by_id[s]["name"]) for s in strategies if ext(by_id[s]))
    if lst:
        strategy_ref[tid] = lst

# ---------------------------------------------------------------- detection content
def counts_rollup(c):
    """Parent rows include their sub-techniques; sub-technique rows count only themselves."""
    out = Counter()
    for t, n in c.items():
        out[t] += n
        if "." in t:
            out[parent(t)] += n
    return out


def blob_base(name):
    """The link prefix for files at the commit fetch_defense.py read, so a link shows what was counted. Rows carry the
    path only; defense_sources carries the prefix (blob_base) and the page joins them."""
    p = PROV.get(name, {})
    return f"https://github.com/{p.get('repo')}/blob/{p.get('commit') or 'HEAD'}/"


blob = lambda name, rel: rel.replace(os.sep, "/")


# Content catalog: per technique (its own tags, not rolled up) the strongest few items from each source, by the source's
# own status and severity fields, with a link to the file. Titles and links only; rule bodies stay in their repositories.
catalog = defaultdict(list)  # (technique, source) -> [(sort key, row)]
SIG_STATUS = {"stable": 0, "test": 1, "experimental": 2}
SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
sigma, sigma_stable, sigma_high, sigma_files = Counter(), Counter(), Counter(), 0
for path in glob.glob(os.path.join(RAW3, "sigma", "rules*", "**", "*.yml"), recursive=True):
    try:
        docs = list(yaml.safe_load_all(open(path, encoding="utf-8")))
    except Exception:
        continue
    for d in docs:
        if not isinstance(d, dict) or not isinstance(d.get("tags"), list):
            continue
        status, level = str(d.get("status", "")).lower(), str(d.get("level", "")).lower()
        if status in ("deprecated", "unsupported"):
            continue
        sigma_files += 1
        ids = {cur(m.group(1).upper(), "sigma") for m in (re.match(r"^attack\.(t\d{4}(?:\.\d{3})?)$", str(x).lower()) for x in d["tags"]) if m}
        ls = d.get("logsource") if isinstance(d.get("logsource"), dict) else {}
        logsrc = " / ".join(str(ls[k]) for k in ("product", "category", "service") if ls.get(k)) or None
        for t in filter(None, ids):
            sigma[t] += 1
            if status == "stable":
                sigma_stable[t] += 1
            if level in ("high", "critical"):
                sigma_high[t] += 1
            catalog[(t, "Sigma")].append(((SIG_STATUS.get(status, 3), SEV.get(level, 5), str(d.get("title"))),
                                          {"id": str(d.get("id") or path), "title": str(d.get("title") or os.path.basename(path)), "level": level or None, "status": status or None,
                                           "logsource": logsrc, "url": blob("sigma", os.path.relpath(path, os.path.join(RAW3, "sigma")))}))

elastic, elastic_files = Counter(), 0
for path in glob.glob(os.path.join(RAW3, "elastic", "rules", "**", "*.toml"), recursive=True):
    if "_deprecated" in path.split(os.sep):
        continue
    try:
        d = tomllib.load(open(path, "rb"))
    except Exception:
        continue
    if str((d.get("metadata") or {}).get("maturity", "")).lower() == "deprecated":
        continue
    elastic_files += 1
    rule = d.get("rule") or {}
    ids = set()
    for th in rule.get("threat", []) or []:
        for te in th.get("technique", []) or []:
            ids.add(te.get("id"))
            for st in te.get("subtechnique", []) or []:
                ids.add(st.get("id"))
    sev = str(rule.get("severity", "")).lower()
    for t in filter(None, (cur(x, "elastic") for x in ids if x)):
        elastic[t] += 1
        catalog[(t, "Elastic")].append(((0, SEV.get(sev, 5), -(rule.get("risk_score") or 0), str(rule.get("name"))),
                                        {"id": str(rule.get("rule_id") or path), "title": str(rule.get("name") or os.path.basename(path)), "level": sev or None,
                                         "status": str((d.get("metadata") or {}).get("maturity") or "") or None, "logsource": str(rule.get("type") or "") or None,
                                         "url": blob("elastic", os.path.relpath(path, os.path.join(RAW3, "elastic")))}))

splunk, splunk_files = Counter(), 0
SPL_TYPE = {"ttp": 0, "anomaly": 1, "hunting": 2, "correlation": 3}
for path in glob.glob(os.path.join(RAW3, "splunk", "detections", "**", "*.yml"), recursive=True):
    if "deprecated" in path.split(os.sep):
        continue
    try:
        d = yaml.safe_load(open(path, encoding="utf-8"))
    except Exception:
        continue
    if not isinstance(d, dict) or str(d.get("status", "")).lower() == "deprecated":
        continue
    splunk_files += 1
    # The 2026 layout keeps mitre_attack_id at the top level; older releases nested it under tags.
    tags = d.get("tags") if isinstance(d.get("tags"), dict) else {}
    ids = set(d.get("mitre_attack_id") or tags.get("mitre_attack_id") or [])
    typ = str(d.get("type", "")).lower()
    srcs = d.get("data_source") if isinstance(d.get("data_source"), list) else []
    for t in filter(None, (cur(x, "splunk") for x in ids if x)):
        splunk[t] += 1
        catalog[(t, "Splunk")].append(((0 if str(d.get("status", "")).lower() == "production" else 1, SPL_TYPE.get(typ, 4), str(d.get("name"))),
                                       {"id": str(d.get("id") or path), "title": str(d.get("name") or os.path.basename(path)), "level": typ or None,
                                        "status": str(d.get("status") or "") or None, "logsource": ", ".join(str(x) for x in srcs[:2]) or None,
                                        "url": blob("splunk", os.path.relpath(path, os.path.join(RAW3, "splunk")))}))

atomic, atomic_rows = Counter(), 0
with open(os.path.join(RAW3, "art_index.csv"), newline="", encoding="utf-8") as f:
    seen = set()
    for r in csv.DictReader(f):
        guid = r.get("Test GUID")
        if not guid or guid in seen:
            continue  # the index repeats a test under each tactic it serves
        seen.add(guid)
        t = cur(r.get("Technique #"), "atomic")
        if t:
            atomic[t] += 1
            atomic_rows += 1
            src_t = (r.get("Technique #") or "").strip()
            try:
                num = int(r.get("Test #") or 0)
            except ValueError:
                num = 0
            catalog[(t, "Atomic Red Team")].append(((num,), {"id": guid, "title": r.get("Test Name") or guid, "level": r.get("Executor Name") or None, "status": f"Test {num}" if num else None,
                                                             "logsource": None, "url": blob("art_index.csv", f"atomics/{src_t}/{src_t}.md")}))
CAT_KEEP = 3
content_rows = []
for (t, source), lst in catalog.items():
    lst.sort(key=lambda z: z[0])
    seen_ids = set()
    for k, row in lst:
        if row["id"] in seen_ids:
            continue
        seen_ids.add(row["id"])
        content_rows.append({"key": f"{t}|{source[0]}{len(seen_ids)}", "technique_id": t, "source": source, "rank": len(seen_ids), "total": len(lst),
                             **{x: row[x] for x in ("title", "level", "status", "logsource")}, "path": row["url"]})
        if len(seen_ids) >= CAT_KEEP:
            break

S, E, SP, A = counts_rollup(sigma), counts_rollup(elastic), counts_rollup(splunk), counts_rollup(atomic)
SST, SHI = counts_rollup(sigma_stable), counts_rollup(sigma_high)

# ---------------------------------------------------------------- CTID Top ATT&CK Techniques: choke points
ctid = json.load(open(os.path.join(RAW3, "ctid_top_techniques.json")))
choke, ctid_seen = {}, 0
for r in ctid:
    for x in [r] + (r.get("subtechniques") or []):
        t = cur(x.get("tid"), "ctid_top")
        if t and x.get("choke_point_score") is not None:
            choke[t] = max(choke.get(t, 0), float(x["choke_point_score"]))
            ctid_seen += 1
calc_src = open(os.path.join(RAW3, "ctid_top_calculator.ts"), encoding="utf-8").read()
m = re.search(r'id:\s*"ransomware".*?techniques:\s*\[(.*?)\]', calc_src, re.S)
ransom_top10 = [cur(x, "ctid_top") for x in re.findall(r'"(T\d{4}(?:\.\d{3})?)"', m.group(1))] if m else []
ransom_top10 = [x for x in ransom_top10 if x]

# ---------------------------------------------------------------- CTID TIE: report frequency and co-occurrence
tie = json.load(open(os.path.join(RAW3, "tie_dataset.json")))
reports = []
for r in tie.get("reports", []):
    ts = {cur(t, "tie") for t in (r.get("mitre_techniques") or {})}
    ts.discard(None)
    if len(ts) >= 2:
        reports.append(ts)
NREP = len(reports)
n_t = Counter(t for ts in reports for t in ts)
pair = Counter()
for ts in reports:
    s = sorted(ts)
    for i in range(len(s)):
        for j in range(i + 1, len(s)):
            pair[(s[i], s[j])] += 1
co = defaultdict(list)
MIN_BOTH = 15
for (a, b), n in pair.items():
    if n < MIN_BOTH:
        continue
    for x, y in ((a, b), (b, a)):
        p = n / n_t[x]
        lift = p / (n_t[y] / NREP)
        co[x].append((y, n, p, lift))
cooc_rows = []
for t, lst in co.items():
    # Rank by p x ln(lift): how often the pair appears together, discounted when the related technique is common everywhere
    # (Obfuscated Files, Ingress Tool Transfer). Pairs at lift 1.2 or below are no better than chance and are left out.
    keep = sorted((z for z in lst if z[3] > 1.2), key=lambda z: -(z[2] * math.log(z[3])))[:6]
    for rank, (y, n, p, lift) in enumerate(keep, 1):
        cooc_rows.append({"key": f"{t}|{y}", "technique_id": t, "related_id": y, "related_name": tech[y]["name"], "both": n, "reports_with": n_t[t],
                          "p_related": round(p, 3), "lift": round(lift, 2), "score": round(p * math.log(lift), 3), "rank": rank})

# ---------------------------------------------------------------- CTID Mappings Explorer
MX = os.path.join(RAW3, "mappings-explorer", "mappings")


def latest(framework, domain="enterprise"):
    """The newest mapping file for a framework: highest ATT&CK version, then newest framework version folder."""
    def vkey(p):
        av = re.search(r"attack-(\d+)\.(\d+)", p)
        return (int(av.group(1)), int(av.group(2))) if av else (0, 0), p
    files = sorted(glob.glob(os.path.join(MX, framework, "attack-*", "*", domain, "*.json")), key=vkey)
    return files[-1] if files else None


def mapping(framework):
    p = latest(framework)
    if not p:
        return None, []
    d = json.load(open(p))
    return d.get("metadata", {}), d.get("mapping_objects", [])


kev = json.load(open(os.path.join(RAW, "kev.json")))
kev_by = {v["cveID"]: v for v in kev["vulnerabilities"]}
kmeta, kmap = mapping("kev")
kev_rows, kev_exp, kev_ran, kev_ids = [], defaultdict(set), defaultdict(set), defaultdict(list)
groups_k = kmeta.get("capability_groups", {}) if kmeta else {}
for x in kmap:
    if x.get("status") not in (None, "complete") or not x.get("attack_object_id"):
        continue
    t = cur(x["attack_object_id"], "kev_map")
    if not t:
        continue
    c = x.get("capability_id")
    k = kev_by.get(c, {})
    ran = (k.get("knownRansomwareCampaignUse") or "") == "Known"
    kev_rows.append({"key": f"{c}|{x.get('mapping_type')}|{t}", "cve": c, "vendor": k.get("vendorProject") or None, "product": k.get("product") or None,
                     "mapping_type": x.get("mapping_type"), "technique_id": t, "technique_name": tech[t]["name"],
                     "capability": groups_k.get(x.get("capability_group") or "", None) or x.get("capability_group") or None, "ransomware": "Known" if ran else ("Unknown" if k else None),
                     "date_added": k.get("dateAdded") or None, "in_kev": "Yes" if k else "No"})
    if x.get("mapping_type") == "exploitation_technique":
        for tt in {t, parent(t)}:
            kev_exp[tt].add(c)
            if ran:
                kev_ran[tt].add(c)

cmeta, cmap = mapping("cri_profile")
cri_by_t, cri_rows = defaultdict(set), {}
cri_groups = cmeta.get("capability_groups", {}) if cmeta else {}
for x in cmap:
    if x.get("mapping_type") != "mitigates" or not x.get("attack_object_id"):
        continue
    t = cur(x["attack_object_id"], "cri_map")
    if not t:
        continue
    cid = x["capability_id"]
    cri_by_t[t].add(cid)
    r = cri_rows.setdefault(cid, {"cri_id": cid, "function_id": x.get("capability_group"), "function_name": cri_groups.get(x.get("capability_group") or "", None),
                                  "statement": x.get("capability_description"), "techniques": set()})
    r["techniques"].add(t)
cri_out = [{"cri_id": r["cri_id"], "function_id": r["function_id"], "function_name": r["function_name"], "function": (r["function_id"] or "")[:2],
            "statement": r["statement"], "techniques": len(r["techniques"]), "technique_ids": ",".join(sorted(r["techniques"])),
            "mapping_version": cmeta.get("mapping_framework_version"), "attack_version": cmeta.get("attack_version")} for r in cri_rows.values()]
cri_out.sort(key=lambda r: r["cri_id"])

nmeta, nmap = mapping("nist_800_53")
nist_by_t = defaultdict(set)
for x in nmap:
    if x.get("mapping_type") == "mitigates" and x.get("attack_object_id"):
        t = cur(x["attack_object_id"], "nist_map")
        if t:
            nist_by_t[t].add(x["capability_id"])
smeta, smap = mapping("cis")
cis_by_t = defaultdict(set)
for x in smap:
    if x.get("attack_object_id") and x.get("mapping_type") not in ("non_mappable",):
        t = cur(x["attack_object_id"], "cis_map")
        if t:
            cis_by_t[t].add(x["capability_id"])

# ---------------------------------------------------------------- technique rows
rows = []
for t, r in sorted(tech.items()):
    det = S[t] + E[t] + SP[t]
    rows.append({
        "technique_id": t, "name": r["name"], "parent_id": parent(t) if r["is_sub"] else None, "is_sub": "Yes" if r["is_sub"] else "No",
        "tactics": ", ".join(tactic_name.get(x, x) for x in r["tactics"]), "platforms": ", ".join(r["platforms"]), "url": r["url"],
        "groups": len(groups_by_t[t]), "tie_reports": n_t[t], "tie_share": round(n_t[t] / NREP, 4) if NREP else 0,
        "choke": choke.get(t), "ransom_top10": "Yes" if t in ransom_top10 else "No",
        "mitigations": len(mit_by_t[t]), "attack_strategies": len(det_by_t[t]), "attack_analytics": an_by_t[t],
        "sigma": S[t], "sigma_stable": SST[t], "sigma_high": SHI[t], "elastic": E[t], "splunk": SP[t], "community": det, "atomic": A[t],
        "kev_cves": len(kev_exp[t]), "kev_ransomware": len(kev_ran[t]), "kev_ids": ",".join(sorted(kev_exp[t])[:8]) or None,
        "cri": len(cri_by_t[t]), "cri_ids": ",".join(sorted(cri_by_t[t])) or None, "nist": len(nist_by_t[t]), "cis": len(cis_by_t[t]),
        "strategy_ids": ",".join(x for x, _ in strategy_ref.get(t, [])[:4]) or None, "strategy": strategy_ref[t][0][1] if t in strategy_ref else None,
        "strategy_url": f"https://attack.mitre.org/detectionstrategies/{strategy_ref[t][0][0]}" if t in strategy_ref else None,
    })
dump("defense_techniques", rows)
dump("defense_cooccur", sorted(cooc_rows, key=lambda r: (r["technique_id"], r["rank"])))
dump("kev_attack", sorted(kev_rows, key=lambda r: (r["cve"], r["mapping_type"])))
dump("cri_crosswalk", cri_out)
dump("defense_group_sectors", sorted(sector_rows, key=lambda r: (r["group_id"], r["vertical_id"])))
dump("defense_telemetry", sorted(tele_rows, key=lambda r: (r["technique_id"], -r["analytics"], r["dc_id"])))
dump("defense_content", sorted(content_rows, key=lambda r: (r["technique_id"], r["source"], r["rank"])))

src = [
    ("S-ATT", "MITRE ATT&CK Enterprise", "mitre-attack/attack-stix-data", f"v{version}", None, len(tech), "ATT&CK Terms of Use", "Techniques, group use, mitigations, detection strategies and analytics."),
    ("S-SIGMA", "Sigma detection rules", "SigmaHQ/sigma", PROV.get("sigma", {}).get("commit"), PROV.get("sigma", {}).get("commit_date"), sigma_files, "Detection Rule License 1.1 (counts and links only)", "Rules counted per ATT&CK tag; deprecated and unsupported rules left out."),
    ("S-ELASTIC", "Elastic detection rules", "elastic/detection-rules", PROV.get("elastic", {}).get("commit"), PROV.get("elastic", {}).get("commit_date"), elastic_files, "Elastic License 2.0 (counts and links only)", "Production rules; the _deprecated folder left out."),
    ("S-SPLUNK", "Splunk security content", "splunk/security_content", PROV.get("splunk", {}).get("commit"), PROV.get("splunk", {}).get("commit_date"), splunk_files, "Apache-2.0", "Detections counted per mitre_attack_id; deprecated left out."),
    ("S-ART", "Atomic Red Team tests", "redcanaryco/atomic-red-team", PROV.get("art_index.csv", {}).get("commit"), None, atomic_rows, "MIT", "One row per test GUID from the atomics index."),
    ("S-CTID-TOP", "CTID Top ATT&CK Techniques", "center-for-threat-informed-defense/top-attack-techniques", PROV.get("ctid_top_techniques.json", {}).get("commit"), None, ctid_seen, "Apache-2.0", "Choke-point scores and the curated ransomware top 10 (scored on ATT&CK 14.1, carried forward)."),
    ("S-CTID-TIE", "CTID Technique Inference Engine dataset", "center-for-threat-informed-defense/technique-inference-engine", PROV.get("tie_dataset.json", {}).get("commit"), tie.get("update_date"), NREP, "Apache-2.0", f"CTI reports with two or more techniques (ATT&CK {tie.get('attack_version')}); co-occurring pairs kept at {MIN_BOTH}+ shared reports and lift above 1."),
    ("S-CTID-MAP", "CTID Mappings Explorer", "center-for-threat-informed-defense/mappings-explorer", PROV.get("mappings-explorer", {}).get("commit"), PROV.get("mappings-explorer", {}).get("commit_date"), len(kmap) + len(cmap) + len(nmap) + len(smap), "Apache-2.0",
     f"KEV {kmeta.get('mapping_framework_version')} on ATT&CK {kmeta.get('attack_version')}; CRI Profile {cmeta.get('mapping_framework_version')} on ATT&CK {cmeta.get('attack_version')}; NIST 800-53 {nmeta.get('mapping_framework_version')} on ATT&CK {nmeta.get('attack_version')}; CIS {smeta.get('mapping_framework_version')} on ATT&CK {smeta.get('attack_version')}."),
]
BASES = {"S-SIGMA": blob_base("sigma"), "S-ELASTIC": blob_base("elastic"), "S-SPLUNK": blob_base("splunk"), "S-ART": blob_base("art_index.csv")}
dump("defense_sources", [{"source_id": a, "name": b, "repo": c, "version": d, "version_date": e, "items": f, "terms": g, "note": h, "url": "https://github.com/" + c, "blob_base": BASES.get(a),
                          "dropped_ids": sum(v for k, v in dropped.items() if k.startswith({"S-SIGMA": "sigma", "S-ELASTIC": "elastic", "S-SPLUNK": "splunk", "S-ART": "atomic", "S-CTID-TOP": "ctid_top", "S-CTID-TIE": "tie", "S-CTID-MAP": ("kev_map", "cri_map", "nist_map", "cis_map")}.get(a, "-")) if isinstance(k, str))} for a, b, c, d, e, f, g, h in src])

print(json.dumps({"attack": version, "techniques": len(rows), "with_community_detection": sum(1 for r in rows if r["community"]), "with_atomic": sum(1 for r in rows if r["atomic"]),
                  "with_attack_strategy": sum(1 for r in rows if r["attack_strategies"]), "sigma_rules": sigma_files, "elastic_rules": elastic_files, "splunk": splunk_files, "atomic_tests": atomic_rows,
                  "tie_reports": NREP, "cooccur_rows": len(cooc_rows), "sector_rows": len(sector_rows), "telemetry_rows": len(tele_rows), "content_rows": len(content_rows), "kev_rows": len(kev_rows), "kev_cves": len({r['cve'] for r in kev_rows}), "cri_statements": len(cri_out),
                  "ransom_top10": ransom_top10, "dropped": dict(dropped)}, indent=1))
