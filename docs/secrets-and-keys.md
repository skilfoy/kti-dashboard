# Secrets and keys

Every name the system reads, where it lives, what it may do, who creates it, how to rotate it and how to check it works
without printing it. No value appears here, in the repository, in an issue or in a chat. The data sources registry
(`data/data_sources.json`) names the secret of each source the same way, by name and location only.

Principles: one place per secret (the system that uses it holds it, and nothing copies it); the smallest scope the
provider offers; checks that report a status, never the value.

## Neon function variables (function `ti`, project square-breeze-55687399, branch br-summer-scene-b8t048y2)

Set with an environment-only deploy (`deploy_function`, `environment` as a JSON map; Neon merges it into the existing
variables, so name only what changes). `get_function` lists the names, never the values.

| Name | Purpose | Least-privilege scope | Created by | Rotate | Check without printing |
| --- | --- | --- | --- | --- | --- |
| `DATABASE_URL` | Postgres connection for the collector (role `ti_app`) | Role `ti_app`: DML on schema `ti` only, no DDL | Sean (Neon Console, role and password) | `reset_postgres_role_password` for `ti_app`, then an environment-only deploy with the new URL, between trigger minutes | `/api/admin?op=status` answers with `db_bytes`; a job run is ok |
| `TI_BUCKET` | Bucket name (`ti-docs`) | Not a secret; a name | Sean | n/a | `op=status` |
| `TI_CODE_SHA256` | Pin: the only collector bundle the loader runs | Not a secret; a hash | The deploy (by hand or the auto-deploy workflow) | Changes with every deploy | `op=status` version; `x-ti-bundle` header |
| `TI_CODE_SHA256_PREV` | Pin of the previous bundle, for the loader's fallback | Not a secret; a hash | The deploy | Changes with every deploy | `code/by-sha/<hash>.mjs` exists |
| `FIRMS_MAP_KEY` | NASA FIRMS area API | A FIRMS MAP_KEY (free, per account) | Sean (firms.modaps.eosdis.nasa.gov, request a MAP_KEY) | Request a new MAP_KEY, deploy it, then let the old one lapse | `/api/admin?op=probe&target=firms_status` (the probe redacts the key) |
| `CLOQ_API_KEY` | cl0q data API (higher limits) | Read-only API key | Sean (cl0q account) | New key in cl0q, deploy it, revoke the old one | `/api/enrich?type=asn&q=13335` shows the cl0q analyzer ok |
| `SEC_USER_AGENT` | Contact string for SEC fair access; also identifies the cables job to Overpass and Wikidata | Not a credential; a name and an email address | Sean | Change when the contact changes | Health feed `sec_edgar` ok; the cables run detail shows requests answered |
| `ABUSECH_AUTH_KEY` | abuse.ch ThreatFox, URLhaus, MalwareBazaar, YARAify (not-for-profit use) | One Auth-Key from auth.abuse.ch | Sean (auth.abuse.ch) | New key in auth.abuse.ch, deploy it, revoke the old one | Health feeds `threatfox` and `urlhaus` ok (a refused key shows HTTP 401 or `unknown_auth_key`) |
| `GREYNOISE_API_KEY` (optional) | GreyNoise lookups that do not depend on the keyless lookup's tolerance of cloud egress (it refused with HTTP 429 from 3 to 9 November 2026 and has answered steadily since 10 November) | A GreyNoise community or paid key, read-only | Sean (GreyNoise account), tracked in the KTI work tracker | New key, deploy it, revoke the old one | Health feed `greynoise` ok and steady (24-hour uptime 95 percent or more) |
| `TAVILY_API_KEY`, `BRAVE_API_KEY`, `SEARXNG_URL`, `JINA_API_KEY` (optional) | Extra web search and page-reading providers for agentic reports; without them the agent searches Bing News, Google News and DuckDuckGo for free | Tavily (1,000 searches a month free), Brave Search API (2,000 a month free), a SearXNG instance's address, a Jina Reader key | Sean, if wanted | Set with `neon functions deploy ti --env NAME=value` (the variables merge) | A report's progress lists the provider among those tried |
| `TI_KEY` (optional, unset) | Operator override header `x-ti-key` | Full operator access to the collector | Only if Sean decides to set it | Replace the value; it is compared in constant time | `op=status` with the header |
| `AWS_ENDPOINT_URL_S3`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` | Branch object storage | Injected by Neon for the branch | Neon (managed) | Rotate the branch's storage credential in the Neon Console | Any job publishing a document |

Where the GreyNoise key lives: in the collector's Neon environment only. The collector's health probe sends it as the
`key` header when it is set and uses the keyless community lookup when it is not (`greynoiseHeaders` in
`neon/parts/40-ops.mjs`), so nothing breaks before the key exists. The exposure monitor (`api/exposure.js`) stays keyless
for now; moving its GreyNoise lookup behind the collector's `/enrich` is a follow-on, so the key never has to sit on
Vercel as well.

## GitHub (repository skilfoy/kti-dashboard)

| Name | Where | Purpose | Least-privilege scope | Created by | Rotate | Check without printing |
| --- | --- | --- | --- | --- | --- | --- |
| `VERCEL_TOKEN` | Repository secret | Site workflow deploys; the auto-deploy finds the commit's deployment | A Vercel access token scoped to team skilfoys-projects | Sean (Vercel, Account settings, Tokens) | New token, update the secret, delete the old token | The Site workflow's deploy step succeeds |
| `NEON_API_KEY` | Environment secret of `collector-production` (PR #7) | Read function `ti`, environment-only deploys, loader code deploy | A project-scoped key for square-breeze-55687399 (needs an organization admin; a personal key is the fallback) | Sean (Neon Console, API keys) | New key, update the secret, revoke the old key | A `dry_run` of Collector auto-deploy reaches the `old` step |
| `NEON_STORAGE_KEY_ID`, `NEON_STORAGE_SECRET` | Environment secrets of `collector-production` | Read the bundle and `code/by-sha/`, sign the upload URL, restore on rollback | A branch credential with `storage:read` and `storage:write` | Sean (Neon project Settings, Credentials) | Create a new credential, update both secrets, revoke the old credential | A `dry_run` shows OLD confirmed |
| `VERCEL_AUTOMATION_BYPASS_SECRET` | Environment secret of `collector-production` | Reach `/api/admin` on the deployment's `*.vercel.app` URL | Protection Bypass for Automation of project threat-feeds (Hobby supports it) | Sean (Vercel project Settings, Deployment Protection) | Regenerate in Vercel (the old value stops working), update the secret | A `dry_run` shows the `service` step with the code hash |
| `GITHUB_TOKEN` | Issued per workflow run | Issues and pull-request comments | Each workflow declares its own permissions (`issues: write` for the alert workflow) | GitHub | Automatic | n/a |

Restrict the `collector-production` environment's deployment branches to `main`, so no other branch can read its secrets.

## Vercel

None. The service reads the collector with its Vercel OIDC token, which the collector verifies against Vercel's
published keys; no shared secret exists on either side.

## Rotation and incident checklist

When a value may have leaked (pasted in a chat, an issue, a log, a commit, or a laptop lost):

1. **Revoke first.** Disable the exposed value at its provider before anything else: abuse.ch, FIRMS, cl0q, GreyNoise,
   Neon (API key, storage credential, role password), Vercel (token, bypass secret). A revoked value is harmless even
   if copies exist.
2. **Replace.** Create the new value with the same least-privilege scope and put it where it lives (Neon environment-only
   deploy, between trigger minutes; or the GitHub environment secret).
3. **Verify.** Use the check in the tables above; never print the value to confirm it.
4. **Clean up.** If the value reached a commit, rotate it anyway (history keeps it); remove it from the issue or log; note
   the incident in the KTI work tracker with the time, the name (not the value) and what was revoked.
5. **Review.** Check the provider's usage logs for the window between exposure and revocation where they exist (abuse.ch,
   Neon audit log, Vercel activity).

Routine rotation: yearly for API keys and tokens, and whenever someone with access leaves. Hashes, names and the contact
string are not secrets and need no rotation.
