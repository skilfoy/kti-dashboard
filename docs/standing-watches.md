# Standing watches and change alerts (3.5.0)

Standing watches are the machine half of the priority intelligence requirements. They turn each requirement's elements of information into rules over the [entity graph](entity-graph.md) and CISA KEV. When a rule fires it opens a change alert. Alerts are leads: they are built from entry titles, and the reassessment opens the entries and cites the publishers.

Watches name public threat entities and topics only, never an organization's assets.

## The watches

`data/watches.json` holds the watches. It is published at `/data/watches.json`, and the site build refuses a watch that names an unknown PIR, kind or term list.

| Watch | PIR | Fires when |
|---|---|---|
| W-1A | PIR-1 | An actor attributed to Russia, China, Iran or North Korea is named in a title with financial-sector words |
| W-1B | PIR-1 | An actor, extortion group or malware is named with financial-sector words by two or more publishers |
| W-1C | PIR-1 | An actor or extortion group is named for the first time by two or more publishers (after the baseline) |
| W-2A | PIR-2 | A CVE is added to CISA KEV, with how many days earlier the collection named it |
| W-2B | PIR-2 | A CVE outside KEV is reported by three or more publishers in 72 hours |
| W-3A | PIR-3 | An extortion group is named with a financial-services victim |
| W-3B | PIR-3 | An extortion group is named far above its own baseline (z of 3 or more, three publishers; after the baseline) |
| W-4A | PIR-4 | Two or more of an internet outage, a conflict surge and threat reporting are elevated together in one country (cyber-physical coincidences, hourly) |
| W-5A | PIR-5 | A state-attributed actor is named with critical-infrastructure words |
| W-5B | PIR-5 | A government or CERT publication names a state-attributed actor |
| W-6A | PIR-6 | An identity-abuse technique (vishing, help desk, MFA, SIM swap, deepfake, IT workers) is in three or more publishers' titles in three days |
| W-6B | PIR-6 | An actor or extortion group is named with an identity-abuse technique |
| W-7A | PIR-7 | A takedown, arrest, indictment, extradition or sanction names a threat entity, by two or more publishers |

PIR-4's theater warning indicators keep their own rules. W-4A adds the cyber-physical coincidence across all countries.

**Term lists.** The term lists (`financial`, `critical`, `identity`, `disruption`) are word-bounded Postgres regular expressions over entry titles.

**State attribution.** It comes from the graph's curated `attributed-to` relationships, which are MISP's country and the ATT&CK groups MISP cites.

## How alerts are kept

**Evaluation.** The collector's `watch` job (`neon/parts/37l-watch.mjs`) runs after the `entities` job in every slot. It re-evaluates each watch over its window.

**One alert per subject.** It keeps one alert per watch and subject (an entity, a CVE or a term). New entries update the open alert: counts, latest entries, last date. A subject quiet for 14 days opens a new alert the next time it fires.

**Baseline.** First-seen and surge watches wait until the collection has run 14 days.

**Retention.** Alerts are kept 120 days after their last entry (`ti.alert`).

## Where alerts go

- **Requirements page:** the "Change alerts" card, filterable by PIR, with an Atom feed link.
- **API:**
  - `/api/alerts` (JSON). `?pir=PIR-2` filters by requirement; `&format=atom` gives an Atom feed.
  - `/api/context?type=alerts` (the `live_alerts` dataset).
- **TAXII 2.1:** the "KTI change alerts" collection. Each alert is a STIX report naming the watched entity, with the latest entries as external references.

## A visitor's watchlist

On the Graph page, "Watch" adds an entity to a list kept in that browser only (up to 25 entities). Each visit shows what changed since the last one:

- entries that name each entity;
- entities named with it for the first time;
- CVEs added to KEV for a watched vendor or product;
- change alerts on it.

`/api/watch?ids=a,b&since=ISO` answers the same as JSON, and `&format=atom` as a feed. The list travels in the URL, so a feed reader follows it with no account, and the platform stores nothing about who watches what.

## Reading alerts

An alert says that publishers' titles put a watched entity next to a watched topic. It does not say the topic is true of the entity. "APT28 named with financial-sector terms" can be a bank's own advisory about APT28 or a story that mentions both.

The KEV lead time is the strongest signal: how many days before CISA listed a CVE the collection was already naming it. The accuracy scorecard will build on it.
