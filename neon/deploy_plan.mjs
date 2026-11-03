// Writes the production steps for one collector build as Markdown: the steps Sean approves and runs (runbook section 8).
// It reads nothing from production and writes nothing to it; the values come from the build in this checkout.
//   node neon/deploy_plan.mjs <repository root> [commit]      (after python3 pipeline/collector_build.py .)
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const sha256 = (b) => createHash('sha256').update(b).digest('hex');

export function deployPlan({ sha, bytes, version, loaderSha, commit = 'this commit' }) {
  if (!/^[0-9a-f]{64}$/.test(sha)) throw new Error('bundle sha256 must be 64 hex digits');
  return `# Collector deploy plan: ${version} (${sha.slice(0, 12)})

Build: \`neon/collector.mjs\`, ${bytes} bytes, SHA-256 \`${sha}\`, from ${commit}.
Loader: \`neon/loader.mjs\` SHA-256 \`${loaderSha}\` (deployed as the function's code only in the one-time step).

Nothing below has run. Each step writes to production and needs Sean's approval; run them in order, between trigger
minutes (the schedule fires at :04, :19, :34 and :49). No value below is secret; never paste a presigned URL, key or
connection string into an issue, commit or report.

## One time: the fallback loader
1. Neon \`get_function\` for \`ti\` (project square-breeze-55687399, branch br-summer-scene-b8t048y2): note the current
   \`TI_CODE_SHA256\` (call it OLD) and that the seven user-set variables are listed.
2. Neon \`deploy_function\` for \`ti\` with the code of \`neon/loader.mjs\` from this commit and no environment change. The
   running bundle stays OLD; after its next good scheduled run the loader keeps a copy at \`ti-docs/code/by-sha/OLD.mjs\`.
3. After the next trigger minute, Neon \`list_storage_objects\` on \`ti-docs\` with prefix \`code/by-sha/\`: OLD.mjs is there.

## Each collector deploy
1. Merge the pull request; the Site workflow deploys the service. \`/api/admin?op=sha\` on the operator side reports
   code sha256 \`${sha}\`.
2. Neon \`presign_storage_object\`: bucket \`ti-docs\`, key \`code/collector.mjs\`, operation upload, content type
   \`text/javascript\`.
3. \`/api/admin?op=push&asset=code&u=<that URL, URL-encoded>\` on the operator side: the answer names sha256 \`${sha}\`.
4. Straight after, Neon \`deploy_function\` for \`ti\`, environment only (no zip), \`environment\` set to
   \`{"TI_CODE_SHA256": "${sha}", "TI_CODE_SHA256_PREV": "<OLD from get_function>"}\` (Neon merges it into the existing
   variables).
5. Neon \`get_function\`: the seven variables plus \`TI_CODE_SHA256_PREV\` are listed.
6. \`/api/admin?op=run&job=infra\` (or the changed job), then \`/api/admin?op=status\`: version \`${version}\`. A status
   showing the previous version means the loader fell back (the new bundle failed its hash check or its first run);
   read the function logs for the "loader:" line.
7. To roll back by hand: \`deploy_function\` environment only with \`{"TI_CODE_SHA256": "<OLD>"}\`.
`;
}

export function planFor(root, commit) {
  const src = fs.readFileSync(path.join(root, 'neon', 'collector.mjs'));
  const version = (String(src).match(/export const VERSION = '([^']+)'/) || [])[1] || 'unknown';
  return deployPlan({ sha: sha256(src), bytes: src.length, version, loaderSha: sha256(fs.readFileSync(path.join(root, 'neon', 'loader.mjs'))), commit });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.stdout.write(planFor(path.resolve(process.argv[2] || '.'), process.argv[3]));
