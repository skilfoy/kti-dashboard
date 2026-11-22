# Source reconciliation

Checked on 3 November 2026 against this repository: what became of each source named in the earlier KTI planning, with
the file or dataset that proves it. Statuses: **live** (collected or used now), **known_gap** (collected but refused or
frozen upstream, documented), **held** (deliberately unused pending a decision), **not implemented** (no code reads it),
**declined** (decided against). The planning list itself predates this repository and is not in it; the names below are
the ones Sean listed, and each status comes from the repository alone. The same statuses are carried into
`data/data_sources.json` (row id in brackets).

## Meridian-era list

| Source | Status | Proof, or the reason it is not live |
| --- | --- | --- |
| ACLED | not implemented; candidate | No code reads it. Its name appears only in cited items and indicator text (`data/authored/items.json`, `theater_indicators.json`) through other outlets. Needs registration and its EULA [cand-acled]. |
| ReliefWeb | not implemented; candidate | No code reads it. The API needs a pre-approved appname on every request [cand-reliefweb]. |
| GDACS | not implemented; candidate | No code reads it; reuse terms unverified [cand-gdacs]. |
| USGS earthquakes | not implemented; candidate | No code reads it (earthquakes appear only as cited items). USGS-authored data is U.S. public domain [cand-usgs-earthquakes]. |
| NVD | not implemented | CVE data comes from CVE List V5 records and CVSS-BT (`pipeline/fetch.py`); NVD is only a link target on vulnerability rows (`pipeline/build_data.py`, `nvd_url`) [nvd]. |
| AlienVault OTX | not implemented | No code reads it [plan-otx]. |
| OpenSky | not implemented | No code reads it [plan-opensky]. |
| AISStream | not implemented; candidate | No code reads it. A WebSocket stream needs a persistent connection, which a 15-minute scheduled collector does not hold; API key required [cand-aisstream]. |
| NOTAM feeds | not implemented | No code reads them [plan-notam]. |
| GPSJam | not implemented | No code reads it. GNSS interference is read from NGA navigational warnings, a known gap [plan-gpsjam, nga-navwarn]. |
| State Department advisories | not implemented as a feed | Travel advisories are not collected; State Department statements are cited as items under S-STATE (`data/authored/sources.json`) [plan-state-advisories]. |
| MalwareBazaar | live | On-demand enrichment analyzer `mbazaar` with the abuse.ch Auth-Key (`neon/parts/39-enrich.mjs`, dataset `live_enrich`) [abusech-malwarebazaar]. |
| GitHub Security Advisories | live (3.14.0) | Read through OSV.dev's export of the GitHub-reviewed advisories by the open-source disclosure watch (`neon/parts/37r-osswatch.mjs`, dataset `live_osswatch`) [ghsa, osv-dev]. |
| UKMTO | known_gap | Read hourly by the maritime job; Cloudflare refuses cloud addresses with HTTP 403 since 22 Oct 2026 (`neon/parts/37b-sea.mjs`, `KNOWN_GAPS` in `neon/parts/40-ops.mjs`, dataset `live_maritime`) [ukmto]. |
| MARAD | known_gap | Read hourly; Akamai refuses cloud addresses with HTTP 403 since 22 Oct 2026 (same files) [marad]. |
| Maritime trade press | live (fallback) | Since 3.13.0 the maritime job reads 14 days of maritime-category entries and UKMTO's own feed from the source network and keeps those reporting a security incident, placed in a theater by wording, place names or the feed's theater (`pressIncidents` in `neon/parts/37b-sea.mjs`, source row `PRESS` in `live_maritime`). Counted apart from official notices; never used by the warning indicators. |
| NGA (ASAM and navigational warnings) | known_gap | Both read hourly. ASAM answers nothing current; the warning list answers HTTP 200 but holds nothing issued after 10 May 2024, so both stay off the map (same files) [nga-asam, nga-navwarn]. |

## Forked repositories

None of these is referenced anywhere in this repository (code, data or docs); the forks themselves are outside this
session's GitHub access, so whether any of their ideas were carried over in spirit cannot be shown from here.

| Repository | Status | Proof, or the reason |
| --- | --- | --- |
| IntelOwl | not implemented | No reference. On-demand enrichment is the collector's own (`neon/parts/39-enrich.mjs`). |
| intelmq | not implemented | No reference. Collection is the Neon collector (`neon/parts/`). |
| dfir-threat-intel-platform | not implemented | No reference. |
| Ransomware trackers | partly: a method, not a source | ransomwatch was evaluated and rejected as stale (S-RWATCH, `data/authored/sources.json`) [ransomwatch]. The SEC 8-K job scores filings with Yet Another Ransomware Tracker's weights (`neon/parts/37d-sec.mjs`). Leak-site data comes from ransomware.live and ThreatCluster instead [ransomware-live, threatcluster-api, threatcluster-datasets]. |
| OSINT-BIBLE | not implemented | No reference. The OSINT toolkit on the Sources page is the OSINT Newsletter toolkit (below). |
| CyberThreatIntel | not implemented | No reference. |

## OSINT toolkit (data/authored/osint_tools.json)

All twelve are rows of `osint_tools.json` and their links are checked daily by the links job (`lib/links.json`,
dataset `live_links`).

| Tool | Status | Use (from osint_tools.json) |
| --- | --- | --- |
| Lanes | live | Ingested: relationship temperatures, daily pages, registry and naming (datasets `live_lanes`, `live_lanesreg`) [lanes] |
| HullCipher | live | Linked as a pivot [tool-hullcipher] |
| SearchWebCode | held | Held for decision: searches for look-alikes of an organization [tool-searchwebcode] |
| Soar Atlas | live | Linked as a pivot [tool-soar-atlas] |
| FreezeRadar | live | Reference [tool-freezeradar] |
| cl0q | live | Linked, and an enrichment analyzer with `CLOQ_API_KEY` (`neon/parts/39-enrich.mjs`) [cl0q] |
| SpiderFoot.tools | live | Reference [tool-spiderfoot-tools] |
| ActiveDNS | live | Reference [tool-activedns] |
| SanctionsKit | live | Reference [tool-sanctionskit] |
| PageSource Search | held | Held for decision: the JSON API needs a key [tool-pagesource] |
| VIEW | live | Reference [tool-view-tg] |
| Nations Online | live | Linked as a pivot [tool-nations-online] |

"Reference" and "Linked" tools are listed with their use on the Sources page and are not collected from.

## Books (data/authored/method.json)

Method references, not data sources: each is cited by the design rules shown, on the Method page. All are live in that
sense; none is collected.

| Book | Method rules citing it | First rule ids |
| --- | --- | --- |
| Arici | 23 | A1, A1b, A1c, B1, B2, B3 |
| Thomas | 22 | A1, A1b, A1c, A2, A3, A3b |
| Tiepolo & Sorensen | 22 | A2, A3, A3c, A4, B1, B2 |
| Fleurat et al. | 18 | A1, B1, B2, B3, B3b, B5 |
| Kuhn | 7 | A5, B1, B5, B5b, D2, D3 |
| Skopik | 6 | A3c, A4b, A5, B1, A4c, A4f |
| Bhardwaj | 5 | B1, F7, G2, G4, G8 |
| Suryavanshi | 3 | A6, C4, A6b |
| Automating CTI | 3 | C4, D1, D5 |
| Ransomware Analysis | 2 | B3, D1 |
| AI-Enabled TI | 2 | A3, C4 |
| Gupta & Tennin | 1 | F3 |
| Ali & Bhatti | 1 | D5 |
| Yang et al. (Demystifying AI/ML for CTI) | 1 | B4 |

## Candidates Sean asked to evaluate (not collected)

Terms read from each publisher's own page on 3 November 2026; anything the page did not state is marked unverified.

| Source | Access | Licence and terms | Verified |
| --- | --- | --- | --- |
| Wikidata (cables) | Open (SPARQL) | CC0 for structured data (Wikidata:Licensing) | yes; now collected by the cables job [wikidata-cables] |
| USGS earthquake feed | Open | U.S. Public Domain for USGS-authored data (usgs.gov Copyrights and Credits) | yes |
| GDACS | Open | The terms page holds a disclaimer only; reuse terms not stated | no (unverified) |
| NASA EONET | Open | Not stated on the EONET page | no (unverified) |
| Cloudflare Radar | API token | The about page answered HTTP 403 to this review | no (unverified) |
| OONI | Open | "Content available under a Creative Commons license" (version not stated on the data page) | partly (version unverified) |
| RIPEstat | Open | The terms page answered HTTP 404 | no (unverified) |
| AISStream | API key | "Real-time and for free" with API keys (aisstream.io); licence and commercial terms not stated | partly |
| Global Fishing Watch | API token | Expected non-commercial; the terms are rendered by script and were not in the page text | no (unverified) |
| ReliefWeb | Approved appname | "Every API URL needs a pre-approved appname" (apidoc.reliefweb.int); content licence not stated | partly |
| ACLED | Registration | EULA, Content Usage Terms and Attribution Policy named on the terms page; their contents not read | partly |
| UCDP | Open | "Free of charge and licensed under CC BY 4.0", cite the dataset publications (ucdp.uu.se/downloads) | yes |
