# Submarine cable layer: open data

Status: collected weekly by the `cables` job (`neon/parts/37e-cables.mjs`) on the lease row reserved for it since G26;
served at `/api/context?type=cables` and as the open file `/open-data/cables.geojson`. **Partial coverage.** The map
layer is a follow-on (see the end).

The data source decision is open data only: TeleGeography's geocoded cable data is an annual paid licence, which Sean
will not buy, and its site API is not called for data. Its two `/probe` targets in `neon/parts/50-http.mjs` stay
diagnostic.

## Sources and measured coverage

| Source | Licence | Measured | What it gives |
| --- | --- | --- | --- |
| OpenStreetMap through Overpass | ODbL 1.0, "© OpenStreetMap contributors" | 2 November 2026, Overpass Turbo in Sean's browser: **374 ways** tagged `communication=line` + `location=underwater`, **189 named**; **12 nodes** tagged `telecom=cable_landing_station` | Cable geometry, names, operators; landing stations |
| Wikidata (SPARQL) | CC0 | 3 November 2026: **176 items** of class Q506572 (submarine communications cable), as Sean counted. **112** carry an inception date (P571) in this session's query, against the **86** Sean counted on the same day; the difference is unexplained (the query, a filter on the date's precision, or edits that day) and is recorded rather than resolved. 5 carry service entry (P729), 51 owner (P127), 120 length (P2043) | Owner, length, ready-for-service date |

Both are thin next to the cables in service (several hundred systems). The layer says "partial coverage" wherever it is
shown, and an absent cable means OSM does not map it, not that it does not exist.

## How the job reads them

- Weekly, Sundays at 05:19 UTC, lease `cables` (180 seconds).
- One Overpass request a run:
  ```
  [out:json][timeout:80];(way["communication"="line"]["location"="underwater"];node["telecom"="cable_landing_station"];);out tags geom qt;
  ```
  POST to `overpass-api.de`, then `overpass.private.coffee` only when the first cannot answer. 90-second timeout. A 429
  or 504 ends the attempt with no further request and sets a back-off from Retry-After (or a day) that later runs honour.
- Headers: a User-Agent naming the project and the contact in `SEC_USER_AGENT`, and `Accept: application/json`
  (overpass-api.de answered a bare request with HTTP 406). Without `SEC_USER_AGENT` the job sends nothing.
- Wikidata: one SPARQL request (owner, length, service entry, inception) with the same User-Agent and
  `Accept: application/sparql-results+json`. If it fails, the OSM cables publish unjoined and the document says so.
- Geometry: coordinates validated (finite, latitude within 90, longitude within 180), unwrapped and split at the
  antimeridian into parts that stay within ±180, simplified with Douglas-Peucker to at most 400 points a way and 60,000
  points in all (the tolerance doubles until the total fits).
- Stored: `ti.cable` and `ti.cable_station` (whitelisted tags only; no OSM user, uid, version, changeset or timestamp)
  and `ti.kv` row `cables:meta` (osm_base timestamp, counts, source URL, licence, attribution, back-off).
- Hold-last-good: a new snapshot replaces the old one only when it has at least half the previous way count; otherwise
  the old snapshot stays and the run fails with the reason, as the blogs job does.
- Health: `overpass` and `wikidata` probes every 30 minutes; volume rows `cables_ways` and `cables_stations`; the
  alert workflow judges the job against a weekly cadence (silent after a week plus 90 minutes), and does not raise
  "no run recorded" before its first run.

## The Wikidata join

Exact normalised name only: lower case, accents removed, every run of non-alphanumeric characters made one space. No
suffix is stripped and nothing approximate is used, so "Southern Cross" does not match "Southern Cross Cable". An OSM
name that matches two Wikidata items is ambiguous and stays unmatched. A matched cable carries `wikidata: {qid, owners,
length_km, ready_for_service, ready_for_service_basis, match}`; the basis says whether the date is service entry (P729)
or inception (P571). Unmatched cables carry `wikidata: null`.

## Licence and share-alike

The derived dataset is a database derived from OpenStreetMap, so it is offered under the ODbL 1.0:
`/open-data/cables.geojson` (and `/api/context?type=cables`) carry `licence`, `licence_url`, `attribution` and
`attribution_url`, and `/open-data/cables-LICENSE.txt` states the terms. It is kept out of `data/authored` and out of the
analyst datasets, so the share-alike obligation stays on this derived database alone. Wikidata fields are CC0. The
attribution "© OpenStreetMap contributors" is also in the data sources page's attribution block.

## Production steps before the first run (Sean)

1. Apply the two `CREATE TABLE` statements at the end of `neon/schema.sql` as the owner role (the `cables` lease row
   already exists in production). `ti_app` gets DML through the schema's default privileges; check with
   `has_table_privilege('ti_app', 'ti.cable', 'INSERT')`.
2. Deploy the collector (the auto-deploy workflow, or the manual procedure in runbook section 8).
3. Run `/api/admin?op=run&job=cables` once rather than waiting for Sunday, and check the run detail (counts, mirror,
   Wikidata matches).

## The map layer (3.8.2)

The live map (`public/js/pew.js`) has a Submarine cables layer, off by default. The first time it is switched on, the
page reads `/api/context?type=cables&format=geojson` once. Each stored part is projected and cut where the projection
jumps across the map edge. The cables are drawn beneath the other layers, with hollow landing stations, and hit-tested
per segment. The chip, tooltip and legend carry "© OpenStreetMap contributors" (ODbL), and the tooltip says that
coverage is partial. The globe view does not draw the layer.
