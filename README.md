# Global threat intelligence

An open-source threat intelligence platform at https://intel.kilfoycyber.com, reassessed daily: seventeen geopolitical theaters with ThreatCon levels and warning indicators, threat vectors calibrated per critical-infrastructure sector, exploited vulnerabilities with weaponization timing, ransomware and extortion activity, residual risk with dark-web and breach exposure, threat actors, threat-informed defense priorities, and a live world map. Every judgment cites dated items from named public sources graded on the Admiralty scale, and a deterministic validator decides what ships.

Author: Sean Kilfoy.

## How it fits together

```
GitHub (skilfoy/kti-dashboard, private)
  data/authored/        analyst-authored datasets, revised by the daily reassessment
  pipeline/             builds the machine-collected datasets and the site data
  public/               the static site: page, runtime, styles, vendored d3
  api/ lib/             threat-feeds: the site's live-data service (Vercel functions)
  neon/                 the collector (a Neon Function every 15 minutes, with Postgres and a bucket)
  .github/workflows/    Site: build, test, deploy

GitHub Actions (Site workflow)
  02:23, 10:23, 18:23 UTC  rebuild every machine-collected dataset from its public sources (cached between runs)
  every push to main    validate the authored data, assemble public/data and site.json, run the offline
                        and browser tests, deploy to Vercel production, check the public site

Vercel (Hobby, project threat-feeds)
  https://intel.kilfoycyber.com    the site and /api on one origin, public
  https://*.vercel.app             the same deployment, behind Vercel Authentication (operator side)

Neon (project threat-intel)
  Function ti + Postgres + bucket ti-docs: collects the live feeds the map and the service read
```

The page in `public/` was written for a dashboard runtime; `public/runtime/dash.js` provides that interface here: datasets listed in `site.json` (built JSON files under `/data`, and live queries to `/api`), derived tables recomputed in dependency order, per-viewer filters, refresh. Built files carry a content hash in their URL and are cached for a year; `site.json` is revalidated on every load.

## Open by design

Every page, dataset and service route is public and readable from any origin: `/site.json` lists the datasets, `/data/<id>.json` serves each built one, and `/api/...` serves the live ones (the map's hosts with their addresses, on-demand enrichment through every analyzer, the exposure monitor). The one exception is `/api/admin`, the collector's control plane (run jobs, push code, read raw documents), which answers only on the project's `*.vercel.app` addresses behind Vercel Authentication (Standard Protection). Keep that protection on, and keep the Vercel project's name: the collector accepts this project's Vercel OIDC token by its owner, project and environment claims.

Secrets live only where they are used: the collector's keys in the Neon Function environment, the deploy token in the repository's Actions secrets. None is in this repository.

## Run it locally

```
npm ci
python3 -m pip install pyyaml==6.0.2
python3 -I pipeline/build_feeds.py work feeds          # about 10 minutes; GitHub-hosted sources only
python3 -I pipeline/site_build.py --authored data/authored --feeds feeds --out public
node test/dev_server.mjs                               # http://localhost:4173, live service offline
```

The live panels need the deployed service; locally they show as unavailable, and `node test/dev_server.mjs --live <dir>` can answer `/api` from saved responses (`<dataset id>.json` envelopes).

Tests: `npm i --no-save @electric-sql/pglite@0.5.8 playwright@1.64.0`, then `node test/run_all.mjs` (validator, collector jobs on PGlite, service routes on both hosts, page calculations, runtime) and `npx playwright install chromium && node test/e2e.mjs` (every page at 1400 and 390 pixels, light and dark: no script error, no sideways scroll). `node test/smoke.mjs https://intel.kilfoycyber.com` checks the deployed site.

## Deploy

Set up once: the `VERCEL_TOKEN` Actions secret (a Vercel token scoped to the skilfoys-projects team) and a CNAME for `intel` at Squarespace, kilfoycyber.com's DNS host, pointing to the target the workflow's "Attach the public domain" step reports. That step attaches the domain to the Vercel project if it is missing.

Every push to `main` deploys, and the schedule rebuilds the feeds and redeploys three times a day. Run "Site" by hand with "rebuild_feeds" ticked to rebuild out of schedule. Roll back from the Vercel dashboard (Instant Rollback) or by reverting the commit.

## Daily reassessment

A scheduled Claude session runs `pipeline/RUNBOOK.md` at 06:45 America/Chicago: it re-researches the theaters and the cyber picture against the closed source registry, has a separate judge check every change, runs the validator, appends a hash-chained ledger entry, and pushes `data/authored/` to `main`, which deploys. Work is tracked in the Notion "KTI work tracker"; items of type Feedback become FP-numbered follow-on requirements in the next run.

## Marking

The site is marked TLP:AMBER and PAP:AMBER by the owner's choice.

## Sources and terms

Each source's licence and terms are recorded in the source registry (Sources page) and in `site.json`; rule bodies from SigmaHQ, Elastic and Splunk stay in their repositories (titles and links only), and PoC-in-GitHub contributes dates, counts and repository names only. d3 is vendored under its ISC licence (`public/vendor/LICENSE-d3.txt`).
