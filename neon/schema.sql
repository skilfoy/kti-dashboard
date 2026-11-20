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
-- 'cables' (reserved since G26) runs the weekly submarine cable job (neon/parts/37e-cables.mjs) on open data only;
-- TeleGeography's geocoded data is an annual paid licence and is not used. Keep the row.
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
-- Added 2026-11-14 (collector 2026-11-14.1): vendor and CERT advisories (titles, links, dates, CVE identifiers) and the
-- machine triage labels over blog and advisory titles (37f-triage.mjs). Budget, last run and evaluation live in ti.kv.
CREATE TABLE IF NOT EXISTS ti.advisory (link text PRIMARY KEY, feed text NOT NULL, title text, published timestamptz, cves jsonb NOT NULL DEFAULT '[]', seen_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS advisory_published ON ti.advisory (published);
CREATE TABLE IF NOT EXISTS ti.triage (link text PRIMARY KEY, kind text NOT NULL, source text, title text, published timestamptz, cves jsonb NOT NULL DEFAULT '[]',
  relevance int NOT NULL, vector text, theater text, actors jsonb NOT NULL DEFAULT '[]', why text, model text, prompt_v text, at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS triage_at ON ti.triage (at);
INSERT INTO ti.lease (job) VALUES ('psirt'),('triage'),('triageeval') ON CONFLICT DO NOTHING;
-- Added 2026-11-15 (collector 2026-11-15.3): the story a triage row belongs to (the representative's link; null when alone).
ALTER TABLE ti.triage ADD COLUMN IF NOT EXISTS cluster text;
-- Added 2026-11-15 (collector 2026-11-15.4): the verifier's result on relevance 3 stories, and the KEV watchlist's first
-- score and rank per CVE with the time KEV later listed it.
ALTER TABLE ti.triage ADD COLUMN IF NOT EXISTS verify text;
ALTER TABLE ti.triage ADD COLUMN IF NOT EXISTS verify_model text;
CREATE TABLE IF NOT EXISTS ti.kevrank (cve text PRIMARY KEY, first_seen timestamptz NOT NULL DEFAULT now(), first_score real NOT NULL, first_rank int NOT NULL, of_n int NOT NULL, in_kev_at timestamptz);
-- Added 2026-11-17 (collector 2026-11-17.1): titles from theater news feeds, read by the triage job (37g-news.mjs).
CREATE TABLE IF NOT EXISTS ti.news (link text PRIMARY KEY, feed text NOT NULL, source text, title text, published timestamptz NOT NULL, seen_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS news_published ON ti.news (published);
INSERT INTO ti.lease (job) VALUES ('news') ON CONFLICT DO NOTHING;

-- Source network and search (3.0): feed state, collected entries with a full-text index, agentic reports.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE TABLE IF NOT EXISTS ti.feed (id text PRIMARY KEY, url text NOT NULL, active boolean NOT NULL DEFAULT true, via text, alt text, url_used text, etag text, last_modified text,
  status text, fails int NOT NULL DEFAULT 0, entries int, checked_at timestamptz, ok_at timestamptz, primary_at timestamptz, next_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS feed_next ON ti.feed (next_at) WHERE active;
CREATE TABLE IF NOT EXISTS ti.item (link text PRIMARY KEY, fp text NOT NULL, feed text NOT NULL, source text, host text, title text NOT NULL, summary text,
  published timestamptz NOT NULL, category text, region text, lang text, seen_at timestamptz NOT NULL DEFAULT now(),
  tsv tsvector GENERATED ALWAYS AS (to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(summary, ''))) STORED);
CREATE UNIQUE INDEX IF NOT EXISTS item_fp ON ti.item (fp);
CREATE INDEX IF NOT EXISTS item_published ON ti.item (published);
CREATE INDEX IF NOT EXISTS item_feed ON ti.item (feed, published);
CREATE INDEX IF NOT EXISTS item_tsv ON ti.item USING gin (tsv);
CREATE INDEX IF NOT EXISTS item_title_trgm ON ti.item USING gin (title gin_trgm_ops);
CREATE TABLE IF NOT EXISTS ti.report (id text PRIMARY KEY, q text NOT NULL, type text NOT NULL, prompt text, status text NOT NULL, who text, steps jsonb NOT NULL DEFAULT '[]'::jsonb,
  body text, sources jsonb, model text, corpus jsonb, error text, created_at timestamptz NOT NULL DEFAULT now(), started_at timestamptz, done_at timestamptz);
CREATE INDEX IF NOT EXISTS report_created ON ti.report (created_at);
INSERT INTO ti.lease (job) VALUES ('sources'), ('reports') ON CONFLICT DO NOTHING;
-- Entity graph (3.4.0, 37k-entities.mjs): the gazetteer's entities and curated relationships, the entries that name an
-- entity (title and date, kept 400 days so the graph outlives the 45-day entry store) and one row per entity an entry names.
CREATE TABLE IF NOT EXISTS ti.entity (id text PRIMARY KEY, t text NOT NULL, n text NOT NULL, names text NOT NULL DEFAULT '', m jsonb NOT NULL DEFAULT '{}'::jsonb, at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS entity_names_trgm ON ti.entity USING gin (names gin_trgm_ops);
CREATE INDEX IF NOT EXISTS entity_n_trgm ON ti.entity USING gin (n gin_trgm_ops);
CREATE TABLE IF NOT EXISTS ti.erel (a text NOT NULL, b text NOT NULL, rel text NOT NULL, basis text NOT NULL, PRIMARY KEY (a, b, rel, basis));
CREATE INDEX IF NOT EXISTS erel_b ON ti.erel (b);
CREATE TABLE IF NOT EXISTS ti.mdoc (link text PRIMARY KEY, src text NOT NULL, feed text, host text, title text NOT NULL, published timestamptz NOT NULL, category text, at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS mdoc_published ON ti.mdoc (published);
CREATE TABLE IF NOT EXISTS ti.mention (eid text NOT NULL, link text NOT NULL, published timestamptz NOT NULL, host text, via text, PRIMARY KEY (eid, link));
CREATE INDEX IF NOT EXISTS mention_link ON ti.mention (link);
CREATE INDEX IF NOT EXISTS mention_published ON ti.mention (published);
CREATE INDEX IF NOT EXISTS mention_eid_published ON ti.mention (eid, published);
CREATE INDEX IF NOT EXISTS item_seen ON ti.item (seen_at, link);
CREATE INDEX IF NOT EXISTS advisory_seen ON ti.advisory (seen_at, link);
INSERT INTO ti.lease (job) VALUES ('entities') ON CONFLICT DO NOTHING;
-- Standing watches (3.5.0, 37l-watch.mjs): one change alert per watch and subject; kept 120 days after its last entry.
CREATE TABLE IF NOT EXISTS ti.alert (id text PRIMARY KEY, watch text NOT NULL, pir text, kind text NOT NULL, subject text NOT NULL, subject_name text, subject_type text, title text, headline text,
  n int NOT NULL DEFAULT 0, p int NOT NULL DEFAULT 0, first_at timestamptz, last_at timestamptz, links jsonb NOT NULL DEFAULT '[]'::jsonb, detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  opened_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS alert_watch_subject ON ti.alert (watch, subject, last_at);
CREATE INDEX IF NOT EXISTS alert_subject ON ti.alert (subject);
CREATE INDEX IF NOT EXISTS alert_opened ON ti.alert (opened_at);
INSERT INTO ti.lease (job) VALUES ('watch') ON CONFLICT DO NOTHING;
-- Track record (3.6.0, 37m-score.mjs): one value per metric and day, kept 800 days.
CREATE TABLE IF NOT EXISTS ti.score (day date NOT NULL, metric text NOT NULL, value real NOT NULL, n int, detail jsonb, at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (day, metric));
INSERT INTO ti.lease (job) VALUES ('score') ON CONFLICT DO NOTHING;
-- Cyber-physical coincidences (3.7.0, 37n-cyphys.mjs); the latest coincidences live in ti.kv ('cyphys:latest').
INSERT INTO ti.lease (job) VALUES ('cyphys') ON CONFLICT DO NOTHING;
-- Sigma detection drafts (3.8.0, 37o-sigma.mjs): one row per drafting attempt, its rules (accepted and rejected, with
-- the checker's reasons), the pages read and the model calls; kept 365 days.
CREATE TABLE IF NOT EXISTS ti.sigma (id bigserial PRIMARY KEY, subject text NOT NULL, name text NOT NULL, etype text, outcome text NOT NULL, reason text, model text,
  rules jsonb NOT NULL DEFAULT '[]'::jsonb, sources jsonb NOT NULL DEFAULT '[]'::jsonb, calls jsonb NOT NULL DEFAULT '[]'::jsonb, prompt_v int, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS sigma_subject ON ti.sigma (subject, created_at);
CREATE INDEX IF NOT EXISTS sigma_created ON ti.sigma (created_at);
INSERT INTO ti.lease (job) VALUES ('sigma') ON CONFLICT DO NOTHING;
-- Threatcasting futures (3.9.0, 37p-foresight.mjs): one row per drafting attempt for a theater; accepted sets are kept,
-- rejected and failed attempts 365 days.
CREATE TABLE IF NOT EXISTS ti.foresight (id bigserial PRIMARY KEY, theater_id text NOT NULL, name text, state_hash text, why text, outcome text NOT NULL, reason text, model text,
  futures jsonb, failures jsonb NOT NULL DEFAULT '[]'::jsonb, calls jsonb NOT NULL DEFAULT '[]'::jsonb, prompt_v int, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS foresight_theater ON ti.foresight (theater_id, created_at);
INSERT INTO ti.lease (job) VALUES ('foresight') ON CONFLICT DO NOTHING;
-- Non-English collection (3.10.0, 37q-translate.mjs): an English title for entries in other languages, the model that
-- wrote it and when, and failed attempts (a title is left after two). Translated titles are searched through their own
-- expression index and read by the entities job in tr_at order.
ALTER TABLE ti.item ADD COLUMN IF NOT EXISTS title_en text;
ALTER TABLE ti.item ADD COLUMN IF NOT EXISTS tr_model text;
ALTER TABLE ti.item ADD COLUMN IF NOT EXISTS tr_at timestamptz;
ALTER TABLE ti.item ADD COLUMN IF NOT EXISTS tr_fail smallint NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS item_tr ON ti.item (tr_at, link) WHERE tr_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS item_tr_pending ON ti.item (seen_at) WHERE lang <> 'en' AND title_en IS NULL;
CREATE INDEX IF NOT EXISTS item_tsv_en ON ti.item USING gin (to_tsvector('simple', coalesce(title_en, ''))) WHERE title_en IS NOT NULL;
INSERT INTO ti.lease (job) VALUES ('translate') ON CONFLICT DO NOTHING;
-- 2026-11-18: pg_stat_statements is enabled on the production database (CREATE EXTENSION pg_stat_statements, as the
-- owner) to rank the collector's reads by the Postgres transfer they cost (Free plan: 5 GB a month). It is left out of
-- this file because PGlite, which the tests load this schema into, does not ship it.
