# Collector auto-deploy: setup

The workflow `.github/workflows/collector-auto-deploy.yml` deploys the collector after the Site workflow deploys a main
commit that changes it. It does what the manual procedure in `pipeline/RUNBOOK.md` section 8 does, in the same order, and
skips with a notice until the secrets below exist. The deploy job runs in the GitHub environment `collector-production`,
so the four new values are **environment secrets** of that environment, not repository secrets: **Settings >
Environments > collector-production > Environment secrets > Add environment secret**. In the same place, set
**Deployment branches and tags** to **Selected branches** with `main` only, so no other branch's workflow can read them.
Never paste a value into an issue, a commit or a chat.

| Secret | Where to create it | Minimum permission | What the workflow does with it |
| --- | --- | --- | --- |
| `NEON_API_KEY` | Neon Console, **Organization settings > API keys > Create new API key**, project-scoped to `square-breeze-55687399`. Creating a project-scoped key needs an organization admin; if the account has no organization admin role, fall back to a personal API key (Account settings > API keys), which carries the account's full access | A project-scoped key (access to that one project only); a personal key only as the fallback | Reads function `ti` (deployment status and variable names, never values); environment-only deploys of `TI_CODE_SHA256` and `TI_CODE_SHA256_PREV`; a code deploy of `neon/loader.mjs` only when the loader changed, and its restore |
| `NEON_STORAGE_KEY_ID` and `NEON_STORAGE_SECRET` | Neon Console, project **Settings > Credentials > Create credential**, branch `br-summer-scene-b8t048y2` (main), scopes `storage:read` and `storage:write` | `storage:read` and `storage:write` on that branch (write is needed for the upload URL and the rollback) | Reads `ti-docs/code/collector.mjs` and the loader's kept copies `code/by-sha/<sha>.mjs.gz` (OLD and the probation check), signs the presigned upload URL the service uses for `op=push`, and puts the OLD bundle back on a rollback |
| `VERCEL_AUTOMATION_BYPASS_SECRET` | Vercel, project **threat-feeds > Settings > Deployment Protection > Protection Bypass for Automation > Generate** (available on the Hobby plan) | The bypass reaches protected deployments of this project only; Vercel Authentication stays on | Sent as `x-vercel-protection-bypass` to the deployment's own `*.vercel.app` URL for `/api/admin` (`op=sha`, `op=push`, `op=run&job=gdelt`, `op=status`). Treat it as the operator credential |
| `VERCEL_TOKEN` | Already a repository secret (the Site workflow uses it); a job in an environment still reads repository secrets, so it stays where it is | Unchanged | Read only here: finds the production deployment URL for the commit (`GET /v6/deployments?sha=`), so the push never goes through an alias that still points at the previous deployment |

`GITHUB_TOKEN` is the workflow's own token (`issues: write`, `pull-requests: write`, `contents: read`): it opens "Collector
deploy failed" and comments on the merged pull request.

## First run

1. Add the four new values above as environment secrets of `collector-production`, and limit its deployment branches to
   `main`.
2. Actions > **Collector auto-deploy** > Run workflow, `dry_run` ticked (the default). The log shows OLD, the service
   hash, the window and each write it would make; nothing changes.
3. From then on every merged collector change deploys itself. A failure restores OLD and opens an issue; the manual
   procedure stays the fallback.

## What it does, in order

1. Build `neon/collector.mjs` and run `node test/run_all.mjs`; a failure stops here.
2. OLD: the SHA-256 of `ti-docs/code/collector.mjs`, accepted only when the loader's copy `code/by-sha/OLD.mjs.gz`
   (gzipped since 3.2.0; `code/by-sha/OLD.mjs` for a copy kept earlier) holds that hash (the loader writes it after a good run of the pinned bundle; the Neon API does not return variable values).
3. The service deployment for the commit must report the built hash at `op=sha`.
4. Loader (only when `neon/loader.mjs` changed): code deploy, then the next scheduled run must be good.
5. Wait until 7 to 12 minutes after a trigger minute (:04, :19, :34, :49) with no lease held in `op=status` (scheduled
   runs arrive up to six minutes late, now and then twelve), then push the bundle and its gzipped copy
   `code/collector.mjs.gz` (which the loader reads first) through the service, read both back, and deploy the environment `{TI_CODE_SHA256: NEW, TI_CODE_SHA256_PREV: OLD}`; the other variables carry
   over. The upload waits for the window too, so the bucket and the pin disagree for seconds, not minutes.
6. `op=run&job=gdelt` and `op=status` must report the new version, and `code/by-sha/NEW.mjs.gz` must exist (probation
   passed without fallback). Otherwise both bucket copies and the pin go back to OLD (and the loader to its previous code), and
   an issue opens with the evidence.
