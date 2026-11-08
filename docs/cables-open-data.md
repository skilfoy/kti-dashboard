# Submarine cable layer: open-data spike

Status: research only, no code merged. The lease row `cables` in `neon/schema.sql` is reserved for this layer (KTI work
tracker; earlier G26). The data source decision is open data only: TeleGeography's geocoded cable data is an annual paid
licence, which Sean will not buy, and its site API (`submarinecablemap.com/api`) is not called for data. The two probe
targets of that name in `neon/parts/50-http.mjs` stay diagnostic.

## The query (OpenStreetMap through Overpass)

Run once, read-only, against the public Overpass API (`https://overpass-api.de/api/interpreter`, POST field `data`):

```
[out:json][timeout:300];
(
  way["communication"="line"]["location"="underwater"];
  way["communication"="line"]["submarine"="yes"];
  node["telecom"="cable_landing_station"];
);
out tags center qt;
```

`out tags center` returns each way's tags and one centre point, which is enough for counting and coverage; the ingest
needs `out geom` for the line shapes.

## Result on 3 November 2026: not run from the build session

The session that wrote this file could not reach `overpass-api.de`. Both attempts (05:41 UTC, the second over HTTP/1.1)
were cut off during the TLS handshake by the session's network policy, with no answer from Overpass. So there are no
counts here, and none were estimated. To complete the spike, run the query above from a network that allows the host
(Sean's machine, or a session whose environment allows `overpass-api.de`) and fill in:

| Measure | How |
| --- | --- |
| Cable ways | elements of type `way` (count those carrying both tags once, by id) |
| Named systems | distinct `name` (or `cable_name`, `operator`) values among the ways |
| Ways without a name | ways with no `name` tag |
| Landing stations | elements of type `node` |
| Landing stations with a name | nodes with `name` |
| Sample | ten named systems and five landing stations, with their tags |

Coverage questions to answer honestly from the result:
- Named systems against the operator's own count: TeleGeography's public front page states its system count, which is
  fine to compare against as a single number, without reading its data.
- Gaps by region: OSM mapping of offshore segments is strongest near European and North American coasts; deep-ocean
  segments are often absent or simplified, and Gulf, Red Sea and Horn of Africa segments (the theaters this dashboard
  tracks) need checking specifically.
- Landing stations that no cable way reaches, and named cables that never reach a landing station.
- Tag drift: `submarine=yes` against `location=underwater`, and `communication=line` cables tagged `power=cable` by
  mistake.

## Recommended ingest under the ODbL

OpenStreetMap data is under the Open Database Licence 1.0. The layer would hold a derived database, so:
- Attribution on the page and in the published document: "© OpenStreetMap contributors", linked to
  https://www.openstreetmap.org/copyright.
- Share-alike: the derived database (cable ways, landing stations and the theater mapping derived from them) is offered
  under the ODbL. The simplest compliant form is to publish the derived document itself (for example
  `docs/cables.json.gz` served as `/api/cables`) with a `licence: ODbL-1.0` field and the attribution, and to say on the
  page that the derived data is available under the same licence. Produced works such as the rendered map need only the
  attribution.
- Keep it separate: OSM-derived rows go into their own tables and document, never mixed into analyst datasets
  (`data/authored`), so the share-alike obligation stays on the derived cable database alone.

Collector design, reusing the reserved slot:
- Job `cables`, lease row `cables` (already present), weekly at the :19 run on Sundays, budget 120 seconds. OSM cable
  data changes slowly; a weekly read keeps load on the public Overpass instance negligible. Send a User-Agent naming the
  project and honour HTTP 429 and 504 by backing off to the next week.
- One Overpass request with `out geom qt` for the two way queries and the node query; store raw ways and nodes in
  `ti.cable_way (osm_id, name, operator, tags jsonb, geom jsonb, seen_at)` and `ti.cable_landing (osm_id, name, cc,
  lat, lon, tags jsonb, seen_at)`, with retention of rows unseen for 60 days.
- Derived rows: per cable, the theaters its geometry crosses (the boxes already used by `37b-sea.mjs`), and per landing
  station, its country; publish `cables` with `source`, `licence`, `attribution` and `generated`.
- Health: add `overpass` to the probes with a light status query, and `cables` to the alert workflow's job cadences
  (weekly, plus 90 minutes).
- Guard: as with blogs, hold a document with materially fewer named systems than the last good one.
