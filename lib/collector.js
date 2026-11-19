// The Neon collector ships as ordered parts under neon/parts/, so a change to one job redeploys one small file. Joined
// in this order they form the single ES module the Neon loader imports (pinned by its SHA-256 in TI_CODE_SHA256),
// which /api/admin pushes to the bucket and /api/threatmap imports for its live fallback.
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { pathToFileURL } = require('url');

const PARTS = ['10-core.mjs', '20-gdelt.mjs', '30-infra.mjs', '35-cyber.mjs', '36-context.mjs', '37-intel.mjs', '37b-sea.mjs', '37c-reg.mjs', '37d-sec.mjs', '37e-cables.mjs', '37f-triage.mjs', '37g-news.mjs', '37h-sources.mjs', '37i-report.mjs', '37k-entities.mjs', '37l-watch.mjs', '37m-score.mjs', '38-lists.mjs', '39-enrich.mjs', '40-ops.mjs', '50-http.mjs'];
const DIR = path.join(__dirname, '..', 'neon', 'parts');
let SRC = null, MOD = null;

function source() {
  if (!SRC) SRC = Buffer.concat(PARTS.map((n) => fs.readFileSync(path.join(DIR, n))));
  return SRC;
}
const sha256 = () => crypto.createHash('sha256').update(source()).digest('hex');
async function load() {
  if (MOD) return MOD;
  const file = path.join(os.tmpdir(), `ti-collector-${sha256().slice(0, 16)}.mjs`);
  if (!fs.existsSync(file)) fs.writeFileSync(file, source());
  MOD = await import(pathToFileURL(file).href);
  return MOD;
}
module.exports = { PARTS, source, sha256, load };
