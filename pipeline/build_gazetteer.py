#!/usr/bin/env python3
"""Build the entity gazetteer the collector's entities job matches against collected reporting.

Run: python3 -I pipeline/build_gazetteer.py RAW RAW2 FEEDS [YYYY-MM-DD]
Reads (all public, all already fetched by fetch.py):
  RAW/attack-current.json     MITRE ATT&CK Enterprise STIX: groups, malware, tools, campaigns and their relationships
  RAW/kev.json                CISA KEV: CVEs with vendor and product
  RAW2/misp_threat_actor.json MISP galaxy threat-actor cluster: actors, synonyms, attributed country
  RAW2/misp_malpedia.json     MISP galaxy Malpedia cluster: malware families and synonyms
  FEEDS/ransomware_groups.json  extortion groups seen on leak sites (built earlier in the same run by build_data.py)
Writes FEEDS/entity_gazetteer.json.

Every entity carries the names it is reported under, each with a match mode the collector applies:
  i  any case, anywhere (names of two or more words, or with a digit: "Volt Typhoon", "APT28", "CVE-2024-3400")
  s  a single plain word, counted only when written with a capital ("Kimsuky", "Akira"); the collector also asks for a
     cyber cue next to it when the word turns up often in general news
  w  a single plain word too short or too common to stand alone ("Play", "Gold"): counted only with a cue word next to it
  v  a product name counted only when its vendor is named in the same entry ("Exchange Server" beside "Microsoft")
Two entities that share a name collapse when they are the same thing (an ATT&CK group and the MISP actor that cites
it; a leak-site group and the Malpedia family of the same name). A name shared by different things goes to one of
them by type (actor, extortion group, malware, tool, campaign, vendor, product); the others keep their other names.
Curated relationships come with the sources: ATT&CK uses and attributed-to, MISP uses, attributed country, and KEV
vendor and product. The collector adds the co-mention edges it observes; the two are kept apart by basis.
"""
import datetime as dt
import json
import os
import re
import sys


# Bump when a mode or ownership rule changes: the collector re-derives every mention under the new rules.
RULES = 2


def self_test():
    """Build from tiny fixtures and check the merges, name ownership and modes. python3 -I build_gazetteer.py --self-test"""
    import subprocess
    import tempfile
    d = tempfile.mkdtemp()
    raw, raw2, feeds = (os.path.join(d, x) for x in ("raw", "raw2", "feeds"))
    for x in (raw, raw2, feeds):
        os.makedirs(x)
    ref = lambda i, kind="groups": [{"source_name": "mitre-attack", "external_id": i, "url": f"https://attack.mitre.org/{kind}/{i}"}]
    attack = {"objects": [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": "20.1"},
        {"type": "intrusion-set", "id": "intrusion-set--1", "name": "APT28", "aliases": ["APT28", "Fancy Bear", "Sofacy"], "external_references": ref("G0007"), "description": "APT28 is a group. More."},
        {"type": "intrusion-set", "id": "intrusion-set--2", "name": "Lazarus Group", "aliases": ["Lazarus Group", "HIDDEN COBRA"], "external_references": ref("G0032")},
        {"type": "intrusion-set", "id": "intrusion-set--3", "name": "Magic Hound", "aliases": ["Magic Hound", "Charming Kitten"], "external_references": ref("G0059")},
        {"type": "intrusion-set", "id": "intrusion-set--4", "name": "Akira", "aliases": ["Akira"], "external_references": ref("G1024")},
        {"type": "malware", "id": "malware--1", "name": "X-Agent", "x_mitre_aliases": ["X-Agent", "CHOPSTICK"], "external_references": ref("S0161", "software")},
        {"type": "malware", "id": "malware--2", "name": "LockBit 3.0", "x_mitre_aliases": ["LockBit 3.0"], "external_references": ref("S1202", "software")},
        {"type": "malware", "id": "malware--3", "name": "Gone", "revoked": True, "external_references": ref("S9999", "software")},
        {"type": "relationship", "id": "relationship--1", "relationship_type": "uses", "source_ref": "intrusion-set--1", "target_ref": "malware--1"},
    ]}
    ta = {"values": [
        {"uuid": "u1", "value": "APT 28", "meta": {"refs": ["https://attack.mitre.org/groups/G0007/"], "synonyms": ["Pawn Storm"], "country": "RU"}},
        {"uuid": "u2", "value": "Moonstone Sleet", "meta": {"synonyms": ["Lazarus Group"], "country": "KP"}},
        {"uuid": "u3", "value": "Charming Kitten", "meta": {"synonyms": ["Phosphorus"], "country": "IR"}},
        {"uuid": "u4", "value": "n0n", "meta": {}},
        {"uuid": "u5", "value": "Earth Lusca", "meta": {"synonyms": ["Chromium"]}},
    ]}
    mp = {"values": [{"uuid": "m1", "value": "LockBit", "meta": {"synonyms": ["ABCD Ransomware"], "refs": ["https://malpedia.caad.fkie.fraunhofer.de/details/win.lockbit"]}},
                     {"uuid": "m2", "value": "Derusbi", "meta": {"synonyms": ["PHOTO", "Clean Up", "CleanUp"]}}]}
    rg = [{"group": "lockbit5", "status": "Active"}, {"group": "akira", "status": "Active"}]
    kev = {"catalogVersion": "t", "count": 3, "vulnerabilities": [
        {"cveID": "CVE-2023-23397", "vendorProject": "Microsoft", "product": "Outlook", "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2024-3400", "vendorProject": "Palo Alto Networks", "product": "PAN-OS", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2025-6554", "vendorProject": "Google", "product": "Chromium", "knownRansomwareCampaignUse": "Unknown"}]}
    for path, obj in ((os.path.join(raw, "attack-current.json"), attack), (os.path.join(raw, "kev.json"), kev), (os.path.join(raw2, "misp_threat_actor.json"), ta),
                      (os.path.join(raw2, "misp_malpedia.json"), mp), (os.path.join(feeds, "ransomware_groups.json"), rg)):
        json.dump(obj, open(path, "w"))
    r = subprocess.run([sys.executable, "-I", os.path.abspath(__file__), raw, raw2, feeds, "2026-11-19"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    g = json.load(open(os.path.join(feeds, "entity_gazetteer.json")))
    E = {e["id"]: e for e in g["entities"]}
    names = lambda i: {n: m for n, m in E[i]["a"]}
    checks = [
        ("MISP entry citing G0007 merged, synonyms kept", "Pawn Storm" in names("actor:G0007") and E["actor:G0007"]["src"] == ["attack", "misp"]),
        ("modes: digit any-case, capitalized word", names("actor:G0007")["APT28"] == "i" and names("actor:G0007")["Sofacy"] == "s"),
        ("a stray synonym does not fuse two actors", "actor:G0032" in E and "Lazarus Group" in names("actor:G0032") and "Lazarus Group" not in names("actor:misp:u2")),
        ("an entry named after one group's alias is that group", "actor:misp:u3" not in E and "Phosphorus" in names("actor:G0059")),
        ("a leak-site group tracked by ATT&CK keeps the G id", E["actor:G1024"]["t"] == "extortion" and E["actor:G1024"]["m"]["leak"] == "akira" and "extortion:akira" not in E),
        ("the leak-site group absorbs the family of its name", E["extortion:lockbit5"]["n"] == "LockBit" and "ABCD Ransomware" in names("extortion:lockbit5") and "malware:mp:m1" not in E),
        ("versioned ATT&CK software linked by name", ["extortion:lockbit5", "malware:S1202", "uses", "name"] in g["edges"]),
        ("revoked objects are left out", "malware:S9999" not in E),
        ("curated relationships", ["actor:G0007", "malware:S0161", "uses", "attack"] in g["edges"] and ["actor:G0007", "country:RU", "attributed-to", "misp"] in g["edges"]),
        ("KEV vendor, product and CVE", names("product:microsoft:outlook").get("Outlook") == "v" and ["cve:CVE-2024-3400", "product:paloaltonetworks:panos", "affects", "kev"] in g["edges"]
         and E["cve:CVE-2024-3400"]["m"]["ransomware"] is True),
        ("ATT&CK description first sentence", E["actor:G0007"]["m"]["d"] == "APT28 is a group."),
        ("everyday words need a cue", names("malware:mp:m2") == {"Derusbi": "s", "PHOTO": "w", "Clean Up": "w"} and names("actor:misp:u4") == {"n0n": "w"}),
        ("distinctive names stand alone", names("extortion:lockbit5")["LockBit"] == "s" and names("actor:G0007")["Fancy Bear"] == "i"),
        ("a KEV product name outranks another entity's alias", "Chromium" not in names("actor:misp:u5") and names("product:google:chromium").get("Chromium") == "v"),
        ("rules version", g["rules"] == RULES),
    ]
    bad = [n for n, c in checks if not c]
    assert not bad, bad
    print(f"PASS {len(checks)} checks (entity gazetteer)")
    sys.exit(0)


if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
    self_test()
RAW, RAW2, FEEDS = sys.argv[1], sys.argv[2], sys.argv[3]
DAY = sys.argv[4] if len(sys.argv) > 4 else dt.date.today().isoformat()
OUT = os.path.join(FEEDS, "entity_gazetteer.json")

PRIORITY = {"actor": 0, "extortion": 1, "malware": 2, "tool": 3, "campaign": 4, "vendor": 5, "product": 6}
# English words that are also the name of a tool, family, group or vendor somewhere in the sources. A name in this
# list, or of four letters or fewer, only counts next to a cue word. The collector adds the words that its own corpus
# shows are common in general news, so this list only has to hold the words that are common everywhere.
COMMON = set("""
able about above access account action active adam advanced agent alpha amber anchor android angel apex apollo apple
archer arrow artemis ash atlas aurora avenger axis azure badger bandit banshee baron basic beacon bear bee bishop black
blade blaze blind blink blob blue bolt bond boot boss bounty brain bravo breeze bridge bright bronze buffalo bug cabin
camel candy canvas captain cardinal carbon castle cat cerberus chaos charger charlie check cherry chimera circle citadel
clipper cloud cobalt cobra comet commander condor control copper coral core crab crane crash crawler crimson cronos crow
crown crystal cuba cube cyclops dagger dark dawn delta demon desert diamond dino dirty dragon dream drop duck duke dust
eagle earth echo eclipse edge electric element ember emerald empire energy engine epic equation everest evil exchange
explorer express eye falcon fancy fast fire flame flash flight fluent focus forest fox freedom frost fury galaxy gamma
garden gate gemini genesis ghost giant glass global globe goblin gold golden goose gorilla grace graphite gray green grey
griffin guard hades hammer harbor harvest hawk hello helix hermes hero hidden hive hollow honey horizon hornet hunter
hunters hydra ice impact indigo inferno infinity iron island ivory jaguar jasmine jet joker jupiter karma key king kitten
knight lab lake lantern laser lazarus legion leopard liberty light lightning lime lion lotus lucky luna lynx machete magic
magnet mamba mango marble mars matrix maze medusa mercury merlin meteor midnight mint mirage mist monitor monkey monster
moon mosaic mustang mystic neptune nexus night ninja noble nomad nova oasis ocean octopus office olympus omega onyx opal
oracle orange orbit orchid origin outlaw owl oxygen panda panther paper paradise patriot peach pearl pegasus pepper
phantom phoenix pink pioneer pirate pixel planet platinum play plum polar poseidon power prime prism progress prometheus
proxy pulse puma pyramid python quantum queen radar rain rainbow raven razor rebel red reef relay rhino ripple river
robin rock rocket rogue royal ruby rust saber safe sage salt sapphire saturn scarlet scorpion scout sea secret sentinel
serpent shade shadow shark sharp shell shield signal silent silver skull sky slate smoke snake snow solar sonic spark
sparrow spectre spectrum sphinx spider spirit spring spy squid star steel sting stone storm strike sugar summit sun
sunrise swan sword tank target tempest thor thunder tiger titan torch tornado tower trident trinity triton turtle twilight
typhoon unicorn union united valkyrie vampire vector velvet venom venus viking viper virtual vision volcano vortex vulture
warrior wasp water wave web whale white wild wind winter wolf wood worm xenon yellow zero zeus zombie
""".split())
# Everyday words: a name made only of these and of COMMON words ("Clean Up", "Do Not", "Photo", "Silicon", "Global")
# needs a cue word beside it. Measured on the first live run (19 November 2026), where such aliases from MISP and
# Malpedia (Derusbi's "PHOTO", Sea Turtle's "SILICON", DONOT matching "do not") led the false matches.
STOP = set("""
a about after all also an and any app apps are as at back be best big book box but by calendar call can card case cash center centre chain chat
clean cleanup client code college company control country data day do door down email every file files first for free from game games get go
good government great group guard he health help her high his home house how if in industry is it its just key keys kit lab labs last law life
link links login logon long low mail man market may message mobile money more my net not network new news next no note notes now of off office oil
old on one online open or order our out over page party pay people phone photo photos plan police policy price program project report research
rule rules safe school science search secure security server service services setup she sign silicon so start state story student supply system
systems team test than that the then there these they this those time to too tool tools top trade trust two union university up update us user
users very video was we web what when where who why will window windows with world year yes you your
""".split())
TOK = re.compile(r"[\w][\w.\-]*[\w]|[\w]", re.UNICODE)


def squash(s):
    return re.sub(r"[^0-9a-z]+", "", str(s).lower())


def clean(s):
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    s = re.sub(r"\s*\((?:android|ios|windows|linux|macos|osx|elf|apk|js|python|php|win)\)$", "", s, flags=re.I)
    return s


def mode_for(name, etype):
    toks = TOK.findall(name)
    if not toks:
        return None
    sq = squash(name)
    if len(sq) < 3:
        return None
    plain = lambda t: t.lower() in COMMON or t.lower() in STOP or len(t) <= 2
    if len(sq) <= 4:
        return "w"  # "Play", "ZINC", "n0n"
    if len(toks) >= 2:
        # Two vivid words make a name ("Fancy Bear", "Sea Turtle"); everyday words do not ("Clean Up", "Do Not").
        return "w" if all(t.lower() in STOP or len(t) <= 2 for t in toks) else "i"
    if re.search(r"\d", name):
        return "i"  # APT28, TA505 (also matched when written "APT 28")
    return "w" if plain(toks[0]) else "s"  # an all-caps or camel-case word is still a word: "PHOTO", "CleanUp"


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        if default is not None:
            return default
        raise


class Book:
    def __init__(self):
        self.ent = {}       # id -> entity
        self.by_key = {}    # squashed name -> set of ids
        self.edges = set()  # (src, dst, rel, basis)

    def add(self, eid, etype, name, aliases=(), meta=None, source=""):
        e = self.ent.get(eid)
        if not e:
            e = self.ent[eid] = {"id": eid, "t": etype, "n": clean(name), "names": [], "m": {}, "src": []}
        if source and source not in e["src"]:
            e["src"].append(source)
        for a in [name, *aliases]:
            a = clean(a)
            if a and squash(a) and a not in e["names"] and len(a) <= 60:
                e["names"].append(a)
                self.by_key.setdefault(squash(a), set()).add(eid)
        for k, v in (meta or {}).items():
            if v not in (None, "", [], {}) and k not in e["m"]:
                e["m"][k] = v
        return e

    def merge(self, keep, drop):
        if keep == drop or drop not in self.ent or keep not in self.ent:
            return
        d = self.ent.pop(drop)
        k = self.ent[keep]
        for n in d["names"]:
            if n not in k["names"]:
                k["names"].append(n)
            self.by_key.setdefault(squash(n), set()).discard(drop)
            self.by_key[squash(n)].add(keep)
        for s in d["src"]:
            if s not in k["src"]:
                k["src"].append(s)
        for key, v in d["m"].items():
            k["m"].setdefault(key, v)
        k.setdefault("merged", []).append(drop)
        self.edges = {(keep if a == drop else a, keep if b == drop else b, r, s) for a, b, r, s in self.edges}

    def find(self, name, types):
        ids = self.by_key.get(squash(name), set())
        return [i for i in ids if i in self.ent and self.ent[i]["t"] in types]


B = Book()
stats = {}

# ---------------------------------------------------------------- ATT&CK
att = load(os.path.join(RAW, "attack-current.json"))
objs = [o for o in att["objects"] if not o.get("revoked") and not o.get("x_mitre_deprecated")]
coll = next((o for o in att["objects"] if o["type"] == "x-mitre-collection"), {})


def ext(o):
    for r in o.get("external_references", []) or []:
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id", ""), r.get("url", "")
    return "", ""


def first_sentence(s, n=220):
    s = re.sub(r"\(Citation:[^)]*\)", "", str(s or "")).replace("\n", " ")
    s = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", s)
    s = re.sub(r"\s+", " ", s).strip()
    m = re.match(r"(.+?[.!?])(\s|$)", s)
    s = m.group(1) if m else s
    return s if len(s) <= n else s[: n - 1].rsplit(" ", 1)[0] + "…"


stix2id = {}
for o in objs:
    t = {"intrusion-set": "actor", "malware": "malware", "tool": "tool", "campaign": "campaign"}.get(o["type"])
    if not t:
        continue
    xid, url = ext(o)
    if not xid:
        continue
    aliases = o.get("aliases") or o.get("x_mitre_aliases") or []
    meta = {"attack": xid, "url": url, "d": first_sentence(o.get("description"))}
    if t == "campaign":
        meta.update({"first": (o.get("first_seen") or "")[:10], "last": (o.get("last_seen") or "")[:10]})
    eid = f"{t}:{xid}"
    B.add(eid, t, o["name"], aliases, meta, "attack")
    stix2id[o["id"]] = eid
for o in objs:
    if o["type"] != "relationship":
        continue
    a, b = stix2id.get(o.get("source_ref")), stix2id.get(o.get("target_ref"))
    if a and b and o.get("relationship_type") in ("uses", "attributed-to"):
        B.edges.add((a, b, o["relationship_type"], "attack"))
stats["attack"] = {"version": coll.get("x_mitre_version") or att.get("x_mitre_version"), "entities": len(B.ent)}

# ---------------------------------------------------------------- MISP threat actors
ISO = {}
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
except Exception:
    pass
ta = load(os.path.join(RAW2, "misp_threat_actor.json"), {"values": []})
misp_uuid = {}
n_ta = 0
for v in ta.get("values", []):
    m = v.get("meta", {}) or {}
    gid = None
    for ref in m.get("refs", []) or []:
        mm = re.search(r"attack\.mitre\.org/groups/(G\d{4})", ref)
        if mm:
            gid = mm.group(1)
            break
    cc = m.get("country") if isinstance(m.get("country"), str) and re.fullmatch(r"[A-Z]{2}", m.get("country") or "") else None
    meta = {"cc": cc, "misp": v.get("uuid")}
    syn = [s for s in (m.get("synonyms") or []) if isinstance(s, str)]
    if gid and f"actor:{gid}" in B.ent:
        eid = f"actor:{gid}"
        B.add(eid, "actor", B.ent[eid]["n"], [v["value"], *syn], meta, "misp")
    else:
        eid = f"actor:misp:{v['uuid']}"
        meta["d"] = first_sentence(v.get("description"), 200)
        B.add(eid, "actor", v["value"], syn, meta, "misp")
        n_ta += 1
    misp_uuid[v["uuid"]] = eid
    if cc:
        B.edges.add((eid, f"country:{cc}", "attributed-to", "misp"))
stats["misp_threat_actor"] = {"values": len(ta.get("values", [])), "version": ta.get("version")}

# ---------------------------------------------------------------- Malpedia families (MISP galaxy cluster)
mp = load(os.path.join(RAW2, "misp_malpedia.json"), {"values": []})
for v in mp.get("values", []):
    m = v.get("meta", {}) or {}
    url = next((r for r in m.get("refs", []) or [] if "malpedia.caad.fkie.fraunhofer.de/details/" in r), "")
    B.add(f"malware:mp:{v['uuid']}", "malware", v["value"], [s for s in (m.get("synonyms") or []) if isinstance(s, str)], {"malpedia": url}, "malpedia")
    misp_uuid[v["uuid"]] = f"malware:mp:{v['uuid']}"
for v in ta.get("values", []):
    for r in v.get("related", []) or []:
        if r.get("type") == "uses" and r.get("dest-uuid") in misp_uuid and v["uuid"] in misp_uuid:
            B.edges.add((misp_uuid[v["uuid"]], misp_uuid[r["dest-uuid"]], "uses", "misp"))
stats["misp_malpedia"] = {"values": len(mp.get("values", [])), "version": mp.get("version")}

# ---------------------------------------------------------------- extortion groups seen on leak sites
rg = load(os.path.join(FEEDS, "ransomware_groups.json"), [])
for g in rg:
    name = str(g.get("group") or "").strip()
    if not name:
        continue
    pretty = name if re.search(r"[A-Z]", name) else " ".join(w.capitalize() for w in re.split(r"[\s_]+", name))
    B.add(f"extortion:{squash(name)}", "extortion", pretty, [name], {"status": g.get("status"), "first": g.get("first_seen"), "last": g.get("last_seen")}, "leaksites")
stats["leaksites"] = {"groups": len(rg)}

# ---------------------------------------------------------------- KEV vendors, products and CVEs
kev = load(os.path.join(RAW, "kev.json"))
VENDOR_FIX = {"microsoft corporation": "Microsoft", "apple inc": "Apple"}
for v in kev.get("vulnerabilities", []):
    vend = clean(VENDOR_FIX.get(str(v.get("vendorProject", "")).lower(), v.get("vendorProject", "")))
    prod = clean(v.get("product", ""))
    cve = str(v.get("cveID", "")).upper()
    if not vend or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
        continue
    vid = f"vendor:{squash(vend)}"
    B.add(vid, "vendor", vend, [], {}, "kev")
    B.add(f"cve:{cve}", "cve", cve, [], {"kev": v.get("dateAdded"), "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known" or None, "vendor": vend, "product": prod}, "kev")
    B.edges.add((f"cve:{cve}", vid, "affects", "kev"))
    if prod and not re.fullmatch(r"(?i)(multiple|various|unspecified)( products?)?", prod) and squash(prod) != squash(vend):
        pid = f"product:{squash(vend)}:{squash(prod)}"
        names = [prod]
        if not prod.lower().startswith(vend.lower()):
            names.append(f"{vend} {prod}")
        B.add(pid, "product", prod if prod.lower().startswith(vend.lower()) else f"{vend} {prod}", names, {"vendor": vid}, "kev")
        B.edges.add((f"cve:{cve}", pid, "affects", "kev"))
        B.edges.add((pid, vid, "made-by", "kev"))
stats["kev"] = {"version": kev.get("catalogVersion"), "count": kev.get("count")}

# ---------------------------------------------------------------- collapse duplicates
# An ATT&CK group and a MISP-only actor that share a name are one actor; so are an ATT&CK family and a Malpedia
# family, and a leak-site group and the family of the same name (the extortion entity keeps both).
def curated(i):
    return i.startswith(("actor:G", "malware:S", "tool:S", "campaign:C"))


# Two ATT&CK objects never merge. A MISP or Malpedia entry merges into another entity only on a canonical name,
# so a stray synonym (MISP lists "Lazarus Group" under several DPRK clusters) does not fuse two different actors.
for key, ids in list(B.by_key.items()):
    if len(key) < 4:
        continue
    for t in ("actor", "malware"):
        live = [i for i in B.by_key.get(key, set()) if i in B.ent and B.ent[i]["t"] == t]
        if len(live) < 2:
            continue
        canon = sorted((i for i in live if squash(B.ent[i]["n"]) == key), key=lambda i: (not curated(i), i))
        cur = [i for i in live if curated(i)]
        # A MISP or Malpedia entry named after one ATT&CK object's alias ("Charming Kitten", an alias of Magic Hound
        # G0059) is that object.
        keep = cur[0] if len(cur) == 1 else (canon[0] if canon else None)
        if not keep:
            continue
        for d in live:
            if d != keep and not curated(d) and squash(B.ent[d]["n"]) == key:
                B.merge(keep, d)
# A leak-site group is the operation behind the family of the same name: the group absorbs the MISP actor entry and
# the family ("lockbit5" on the leak sites absorbs LockBit), and links to the versioned ATT&CK software by name.
for gid in [i for i, e in B.ent.items() if e["t"] == "extortion"]:
    key = gid.split(":", 1)[1]
    base = re.sub(r"\d+$", "", key) or key
    # ATT&CK tracks some of these operations as groups (Akira G1024, Play G1040): the group keeps its ATT&CK id,
    # takes the extortion type and the leak-site key, and the leak-site entry folds into it.
    grp = sorted(d for k in (key, base) for d in B.by_key.get(k, set()) if d in B.ent and d.startswith("actor:G") and squash(B.ent[d]["n"]) == k)
    if grp:
        B.merge(grp[0], gid)
        gid = grp[0]
        B.ent[gid]["t"] = "extortion"
        B.ent[gid]["m"]["leak"] = key
    for k in {key, base}:
        for d in list(B.by_key.get(k, set())):
            if d in B.ent and d != gid and B.ent[d]["t"] in ("actor", "malware") and squash(B.ent[d]["n"]) == k and not d.startswith("actor:G"):
                if squash(B.ent[gid]["n"]) == key and B.ent[gid]["n"][1:] == B.ent[gid]["n"][1:].lower():
                    B.ent[gid]["n"] = B.ent[d]["n"]  # the family's own spelling ("LockBit", "INC Ransom") reads better
                B.merge(gid, d)
    if len(base) >= 4:
        for i, e in list(B.ent.items()):
            if e["t"] == "malware" and i.startswith("malware:S") and squash(e["n"]).startswith(base):
                B.edges.add((gid, i, "uses", "name"))

# ---------------------------------------------------------------- names and modes
owner = {}
for key, ids in B.by_key.items():
    # The entity whose own name it is comes first; then a KEV vendor or product name, which is a literal product name,
    # over another entity's alias ("Chromium" is Google's browser, not Earth Lusca); then the type order.
    live = sorted((i for i in ids if i in B.ent), key=lambda i: (0 if squash(B.ent[i]["n"]) == key else 1, 0 if B.ent[i]["t"] in ("vendor", "product") else 1, PRIORITY.get(B.ent[i]["t"], 9), i))
    if live:
        owner[key] = live[0]
shadowed = 0
entities = []
for e in B.ent.values():
    names, seen = [], set()
    for n in e["names"]:
        k = squash(n)
        if k in seen:
            continue
        seen.add(k)
        if e["t"] == "cve":
            names.append([n, "i"])
            continue
        if owner.get(k) != e["id"]:
            shadowed += 1
            continue
        md = mode_for(n, e["t"])
        if e["t"] == "product" and md != "i":
            md = "v"
        if e["t"] == "product" and md == "i" and not n.lower().startswith(e["n"].split(" ")[0].lower()) and len(TOK.findall(n)) < 3 and not re.search(r"[a-z][A-Z]|[A-Z]{2,}|\d", n):
            md = "v"  # "Exchange Server" alone could be any exchange's server; it counts beside "Microsoft"
        if md:
            names.append([n, md])
    if not names:
        continue
    row = {"id": e["id"], "t": e["t"], "n": e["n"], "a": names}
    if e["m"]:
        row["m"] = e["m"]
    if len(e["src"]) > 1 or e["src"][:1] != [e["id"].split(":")[0]]:
        row["src"] = e["src"]
    entities.append(row)
entities.sort(key=lambda r: (PRIORITY.get(r["t"], 9), r["n"].lower()))
ids = {r["id"] for r in entities}
edges = sorted({(a, b, r, s) for a, b, r, s in B.edges if a in ids and (b in ids or b.startswith("country:")) and a != b})

doc = {
    "version": 1, "rules": RULES, "date": DAY, "generated": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "sources": stats,
    "modes": {"i": "any case", "s": "capitalized single word", "w": "single word that needs a cue word beside it", "v": "product name that needs its vendor in the same entry"},
    "counts": {t: sum(1 for r in entities if r["t"] == t) for t in PRIORITY | {"cve": 9}}, "names": sum(len(r["a"]) for r in entities), "shadowed_names": shadowed,
    "entities": entities, "edges": [list(x) for x in edges],
    "terms": "MITRE ATT&CK (c) The MITRE Corporation, reproduced under the ATT&CK terms of use; MISP galaxy clusters CC0 1.0 or BSD-2-Clause; "
             "Malpedia family names via the MISP galaxy Malpedia cluster (CC BY-SA 4.0, Fraunhofer FKIE); CISA KEV public domain; leak-site group names from the ThreatCluster snapshot (CC BY 4.0).",
}
tmp = OUT + ".part"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(doc, f, ensure_ascii=False, separators=(",", ":"))
os.replace(tmp, OUT)
print(json.dumps({"entities": len(entities), "counts": doc["counts"], "names": doc["names"], "shadowed": shadowed, "edges": len(edges), "bytes": os.path.getsize(OUT)}))
