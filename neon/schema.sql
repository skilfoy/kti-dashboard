-- Neon project threat-intel (square-breeze-55687399), branch main, database threatintel. Applied by the owner role
-- through the Neon connector; the collector connects as ti_app, which holds DML on schema ti and nothing else.
CREATE SCHEMA IF NOT EXISTS ti;

-- GDELT: one row per 15-minute export processed; aggregates per slot for the armed-actor material-conflict filter.
CREATE TABLE IF NOT EXISTS ti.gdelt_file (slot timestamptz PRIMARY KEY, status text NOT NULL CHECK (status IN ('ok','missing','failed')), scanned int, kept int, ms int,
  processed_at timestamptz NOT NULL DEFAULT now(), attempts int NOT NULL DEFAULT 1);
CREATE INDEX IF NOT EXISTS gdelt_file_processed ON ti.gdelt_file (processed_at);
CREATE TABLE IF NOT EXISTS ti.gdelt_country (slot timestamptz NOT NULL, iso2 text NOT NULL, n int NOT NULL, m int NOT NULL, PRIMARY KEY (slot, iso2));
CREATE INDEX IF NOT EXISTS gdelt_country_iso_slot ON ti.gdelt_country (iso2, slot);
CREATE TABLE IF NOT EXISTS ti.gdelt_cell (slot timestamptz NOT NULL, lat real NOT NULL, lon real NOT NULL, n int NOT NULL, m int NOT NULL, PRIMARY KEY (slot, lat, lon));
CREATE TABLE IF NOT EXISTS ti.gdelt_event (slot timestamptz NOT NULL, id bigint NOT NULL, added text, lat real, lon real, iso2 text, place text, root text, code text, quad smallint,
  goldstein real, actor1 text, actor2 text, mentions int, sources int, url text, PRIMARY KEY (slot, id));
CREATE TABLE IF NOT EXISTS ti.gdelt_flow (slot timestamptz NOT NULL, fkey text NOT NULL, n int NOT NULL, m int NOT NULL, best int NOT NULL, roots jsonb NOT NULL, rep jsonb NOT NULL,
  urls int NOT NULL DEFAULT 1, PRIMARY KEY (slot, fkey));

-- IP geolocation cache (ip-api.com, GeoJS); failures cached a day, successes refreshed after 30 days.
CREATE TABLE IF NOT EXISTS ti.ip_geo (ip inet PRIMARY KEY, ok boolean NOT NULL, lat real, lon real, cc text, country text, region text, city text, asn text, as_name text, isp text,
  provider text NOT NULL, fetched_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS ip_geo_fetched ON ti.ip_geo (fetched_at);

-- Reported malicious infrastructure, one row per layer, IP and port; first_obs and last_obs are this collector's own observations.
CREATE TABLE IF NOT EXISTS ti.infra (layer text NOT NULL CHECK (layer IN ('c2','ioc','src','url')), ip inet NOT NULL, port int NOT NULL DEFAULT 0, family text, threat text, status text,
  confidence int, count int, tags text, ref text, cc_feed text, first_seen timestamptz, last_seen timestamptz, first_obs timestamptz NOT NULL DEFAULT now(),
  last_obs timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (layer, ip, port));
CREATE INDEX IF NOT EXISTS infra_last_obs ON ti.infra (last_obs);
CREATE TABLE IF NOT EXISTS ti.infra_daily (day date NOT NULL, layer text NOT NULL, cc text NOT NULL, family text NOT NULL, n int NOT NULL, PRIMARY KEY (day, layer, cc, family));
CREATE INDEX IF NOT EXISTS infra_daily_day ON ti.infra_daily (day);

-- Upstream reachability checks.
CREATE TABLE IF NOT EXISTS ti.feed_check (at timestamptz NOT NULL, feed text NOT NULL, ok boolean NOT NULL, status int, ms int, error text, PRIMARY KEY (at, feed));
CREATE INDEX IF NOT EXISTS feed_check_feed_at ON ti.feed_check (feed, at);

-- Internet disruption events (IODA).
CREATE TABLE IF NOT EXISTS ti.disruption (source text NOT NULL, entity text NOT NULL, start_at timestamptz NOT NULL, end_at timestamptz, cc text, name text, level text, score real,
  datasource text, detail jsonb, last_obs timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (source, entity, start_at));

-- Collector runs and per-job leases (the SQL-over-HTTP driver has no session, so locks are rows).
CREATE TABLE IF NOT EXISTS ti.run (id bigserial PRIMARY KEY, job text NOT NULL, started_at timestamptz NOT NULL, ms int, ok boolean, detail jsonb);
CREATE INDEX IF NOT EXISTS run_job_started ON ti.run (job, started_at);
CREATE TABLE IF NOT EXISTS ti.lease (job text PRIMARY KEY, holder text, until timestamptz NOT NULL DEFAULT 'epoch');
INSERT INTO ti.lease (job) VALUES ('gdelt'),('infra'),('health'),('snap'),('ioda'),('cables'),('retention') ON CONFLICT DO NOTHING;

-- Added 2026-10-22 (collector 2026-10-22.1). Small key-value state for jobs that cache upstream reads (Unit 42 notes, Gen Threat
-- Labs tree, OFAC action pages).
CREATE TABLE IF NOT EXISTS ti.kv (k text PRIMARY KEY, v jsonb, at timestamptz NOT NULL DEFAULT now());
-- NASA FIRMS detections rolled up per area of interest, 0.1-degree cell and UTC day (novelty baseline, 120 days kept).
CREATE TABLE IF NOT EXISTS ti.fire_cell (aoi text NOT NULL, cell text NOT NULL, day date NOT NULL, n int NOT NULL, frp real, cc text, PRIMARY KEY (aoi, cell, day));
CREATE INDEX IF NOT EXISTS fire_cell_day ON ti.fire_cell (day);
-- Corroboration lists naming each mapped host (lists = list ids; ipsum = lists counted by IPsum; tor = Tor exit relay).
CREATE TABLE IF NOT EXISTS ti.ip_list (ip inet PRIMARY KEY, lists text[] NOT NULL DEFAULT '{}', ipsum int, tor boolean NOT NULL DEFAULT false, checked_at timestamptz NOT NULL DEFAULT now());
-- Snapshot size per feed per run, for the volume baseline (spike and silence).
CREATE TABLE IF NOT EXISTS ti.feed_volume (at timestamptz NOT NULL, feed text NOT NULL, n int NOT NULL, PRIMARY KEY (feed, at));
-- CTI blogs: discovered feed per blog and recent items (titles and links only).
CREATE TABLE IF NOT EXISTS ti.blog (url text PRIMARY KEY, name text, type text, feed text, status text, note text, items int, newest timestamptz, checked_at timestamptz, fails int NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS ti.blog_item (link text PRIMARY KEY, blog_url text NOT NULL, title text, published timestamptz, seen_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS blog_item_published ON ti.blog_item (published);
-- Link health of the registry, toolkit and pivot patterns.
CREATE TABLE IF NOT EXISTS ti.link_check (url text PRIMARY KEY, label text, kind text, status text, why text, code int, checked_at timestamptz, ok_at timestamptz);
-- On-demand enrichment answers, cached a day.
CREATE TABLE IF NOT EXISTS ti.enrich (type text NOT NULL, q text NOT NULL, analyzer text NOT NULL, ok boolean, result jsonb, error text, at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (type, q, analyzer));
INSERT INTO ti.lease (job) VALUES ('lists'),('fires'),('maritime'),('leaksites'),('ransompay'),('unit42'),('genioc'),('lanesreg'),('blogs'),('links'),('sec8k') ON CONFLICT DO NOTHING;
-- ti_app's DML on these tables comes from the schema's default privileges (checked with has_table_privilege after creation).
-- Added 2026-11-03: submarine cables from OpenStreetMap (ODbL 1.0, "© OpenStreetMap contributors"), joined with Wikidata
-- (CC0) by exact name. Snapshot tables, replaced whole by the weekly cables job; no OSM user or edit metadata is kept.
-- Metadata (osm_base, counts, source URL, licence, attribution) lives in ti.kv under 'cables:meta'.
CREATE TABLE IF NOT EXISTS ti.cable (osm_id bigint PRIMARY KEY, name text, tags jsonb NOT NULL DEFAULT '{}', parts jsonb NOT NULL, points int NOT NULL,
  wikidata jsonb, seen_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS ti.cable_station (osm_id bigint PRIMARY KEY, name text, lat real NOT NULL, lon real NOT NULL, cc text, tags jsonb NOT NULL DEFAULT '{}',
  seen_at timestamptz NOT NULL DEFAULT now());
INSERT INTO ti.lease (job) VALUES ('cables') ON CONFLICT DO NOTHING;
