# Entity graph (3.4.0)

The entity graph links the actors, extortion groups, malware, tools, campaigns, CVEs, vendors, products and countries that the platform's collection names. It is the layer the later work builds on: standing requirements and change alerts watch entities, the cyber-physical correlation joins entities to outages and conflict events, and the accuracy scorecard counts what the graph saw first.

## What it reads

- **Gazetteer** (`pipeline/build_gazetteer.py`, daily in the site build, published at `/data/entity_gazetteer.json`):
  - MITRE ATT&CK Enterprise: groups, malware, tools and campaigns with their aliases, and the `uses` and `attributed-to` relationships.
  - MISP galaxy threat-actor cluster: actors, synonyms, attributed country and `uses` links to Malpedia families.
  - MISP galaxy Malpedia cluster: malware families and synonyms.
  - Leak-site extortion groups, from the ThreatCluster snapshot already used by the Ransomware page.
  - CISA KEV: vendors, products and CVEs, with `affects` and `made-by` links.
- **Collection** (collector job `entities`, every 15 minutes after the sources job): every entry in `ti.item` (title and publisher summary) and every advisory in `ti.advisory` (title and the feed's own CVE list), each read once through a keyset watermark on `(seen_at, link)`.

## How names become entities

Two entities that are the same thing collapse into one in the gazetteer:

- A MISP entry that cites an ATT&CK group, or is named after one ATT&CK group's alias ("Charming Kitten" for Magic Hound, G0059), is that group.
- A leak-site group that ATT&CK tracks as a group (Akira G1024, Play G1040) keeps the ATT&CK id and takes the extortion type.
- A leak-site group absorbs the Malpedia family of its name ("lockbit5" on the leak sites is LockBit), and links to the versioned ATT&CK software by name.
- Two ATT&CK objects never merge, and a stray synonym never fuses two actors: merges happen only on a canonical name.

When different things share a name, the name goes to one owner. An entity whose canonical name it is comes first, then the type order actor, extortion group, malware, tool, campaign, vendor, product. The others keep their remaining names.

Each name carries a match mode:

| Mode | Rule | Examples |
|---|---|---|
| `i` | Any case. Used for names of two or more words and names with a digit. A letters-only name matches exactly its own number of words. | Volt Typhoon, APT28 (also "APT 28") |
| `s` | A single word (all-caps and camel-case included), counted only when capitalized. It also needs a cue word within three words when the collection shows it is common in general news. | Kimsuky, Akira, LockBit |
| `w` | A name of four letters or fewer, a common English word, or a name made only of everyday words. Counted only with a cue word beside it. | Play, ZINC, Cuba, PHOTO, Clean Up |
| `v` | A product name of one or two plain words, counted only when its vendor is named in the same entry. | Exchange Server beside Microsoft |

- **Cue words** are typed by entity:
  - Threat names need a threat word: ransomware, malware, gang, group, hackers, actor, APT, backdoor, stealer, loader, botnet, affiliate, extortion, leak.
  - Vendors and products need a vulnerability word: vulnerability, flaw, patch, zero-day, exploit, advisory, CVE, update, fix.
  - Words that sit beside everything in a cyber headline (security, cyber, attack, campaign, operation) are not cues.
- **Rules versions**: `RULES` in the builder and `MATCH_V` in the collector. A change of either makes the next run re-derive every mention.
- **Ambiguity** is measured daily over the collection with `ts_stat`. A single-word name is ambiguous when it appears in 40 or more general-news entries (geopolitics, theater, maritime, think-tank, defense and government feeds). It is also ambiguous when it appears in at least 4 of them at more than twice its rate in the cyber feeds.
- **Countries** are matched from country names, demonyms ("Russian", "North Korean") and exact-case forms ("US", "U.S.", "UK", "DPRK", "PRC"). They are kept only beside another entity, so the geopolitical stream gives cyber entities their country context without turning into a country index. A single word that is both a family and a country ("Cuba") is the family beside a cue word and the country otherwise.
- **CVEs** are matched by pattern in any case. A CVE that is not in KEV becomes an entity on its first mention.
- **Products** named with their vendor also name the vendor.

No model is involved: the same entry always gives the same entities, and the job costs nothing per entry.

## Store

| Table | Holds | Kept |
|---|---|---|
| `ti.entity` | The gazetteer's entities, plus CVEs and countries added on first mention. Rewritten only when the gazetteer's content hash changes (`ti.kv entities:gaz`). | |
| `ti.erel` | Curated relationships (`a`, `b`, `rel`, `basis`: attack, misp, kev, name). | |
| `ti.mdoc` | Each entry that named at least one entity: title, host, date, source, category. This lets the graph outlive the 45-day entry store. | 400 days |
| `ti.mention` | One row per entity an entry names, with the words that named it (`via`). | 400 days |

Other state:

- `ti.kv entities:mark` holds the watermark per source.
- `ti.kv entities:amb` holds the ambiguous words.
- `ti.kv entities:doc` records when the summary was last written.
- The bucket keeps the last gazetteer read from the site (`ref/entity_gazetteer.json.gz`). The job falls back to it when the site does not answer.

## Outputs

- **`docs/entities`**, rebuilt at most hourly when there are new mentions. Served at `/api/graph` and as the `live_graph` dataset (`/api/context?type=entities`). Its rows come in three kinds:
  - `entity` rows: counts for 1, 7 and 30 days, publishers for 7 and 30 days, first and last seen, a rise score, `rising` and `new` flags, and a rank among the most named of their type.
  - `edge` rows: co-mentions over 30 days. Each needs two publishers and is ranked by entries times normalized PMI. Country-to-country pairs are left out.
  - `rel` rows: curated relationships among the entities the document carries.
- **Rising**: a Poisson z of 3 or more for the last 7 days against the 23 before them, with at least 5 entries from 3 publishers.
- **New**: first named in the last 7 days, by 2 or more publishers.
- **`/api/graph?id=<entity>&days=7..400`**: the entity, its names, mentions per day, co-mentioned entities (entries, publishers, normalized PMI, last date), curated relationships with direction, and the 30 latest entries with the words that named it.
- **`/api/graph?a=<id>&b=<id>`**: the entries that name both, and any curated relationship between them.
- **`/api/graph?q=<name>&t=<type>`**: entities by name or alias.
- **TAXII 2.1** collection "KTI entity graph":
  - Objects: intrusion-set, malware, tool, campaign, vulnerability, identity (vendors), software (products) and location (countries).
  - Relationships: curated ones as `uses`, `originates-from` or `attributed-to`, the rest as `related-to` with the source's own term in `x_kti_relationship`. Co-mentions are `related-to` with `x_kti_basis: observed` and their counts.
  - Ids are deterministic. A CVE has the same vulnerability id as in the advisories collection.
- **Search**: each hit lists the entities its entry names, linked to the Graph page.

## Reading it

Co-mention is association in reporting. "APT28 and Cobalt Strike, 12 entries from 8 publishers" says the press wrote about them together; the curated relationships say who uses what.

Normalized PMI separates a real pairing from two entities that are simply everywhere: 1 means they always appear together, 0 means no more often than chance.

Recall is limited by the gazetteer. An actor named only in its newest vendor name stays invisible until ATT&CK, MISP or Malpedia lists that name. Non-Latin names do not match. Russian, Chinese and Arabic entries still give CVEs and Latin-script names.

## Operating

- First run after the deploy: the job backfills the stored entries at 3,000 a batch for up to 100 seconds a run. On 19 November 2026 that was about 63,000 entries, so a few runs.
- Re-reading everything after a gazetteer rule change: `/api/admin?op=run&job=entities` with `reprocess`. This resets the watermarks. Mentions already stored are kept (`ON CONFLICT DO NOTHING`), so a rule that removes a match needs `DELETE FROM ti.mention` first. Ask Sean before running it.
- Precision check: sample `ti.mention` rows for a single-word entity (`SELECT via, title FROM ti.mention m JOIN ti.mdoc d USING (link) WHERE eid = $1 ORDER BY random() LIMIT 30`). A wrong match is fixed in the gazetteer (`COMMON` or the mode rules), never by deleting the entity.
