// Checks data/data_sources.json, the registry of every upstream the platform reads or has evaluated:
//   coverage   every collector health feed id, every site.json dataset (pipeline/datasets.py D and Q) and every lease
//              job in neon/schema.sql has a row;
//   gaps       the rows with status known_gap are exactly the collector's documented gaps (KNOWN_GAPS and the
//              KNOWN_GAP_VOLUME sources);
//   fields     ids unique, enums valid, a licence on every row, dates ISO, feeds naming real datasets and pages, a secret
//              given by name and location only;
//   secrets    no key-shaped string anywhere in the file.
// node pipeline/check_data_sources.mjs <repository root> [registry path]   (after python3 pipeline/collector_build.py .)
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const STATUSES = ['live', 'known_gap', 'held', 'candidate', 'declined', 'not_implemented'];
export const ACCESS = ['open', 'registration', 'key'];
export const SECRET_WHERE = ['neon_function_variable', 'github_secret', 'github_environment_secret', 'none'];
const FIELDS = ['id', 'name', 'owner', 'category', 'feeds', 'url', 'access', 'secret', 'licence', 'attribution', 'commercial_use', 'cadence', 'health_feed', 'jobs', 'status', 'gap_note',
  'source_ids', 'added', 'reviewed'];
// Strings shaped like credentials: provider prefixes, private keys, connection strings, bearer tokens, JWTs, long
// unbroken alphanumeric runs (32 or more) and presigned URL signatures.
export const KEY_SHAPES = [
  /AKIA[0-9A-Z]{16}/, /\bgh[pousr]_[A-Za-z0-9]{20,}/, /github_pat_[A-Za-z0-9_]{20,}/, /\bsk-[A-Za-z0-9]{16,}/, /\bxox[abpr]-[A-Za-z0-9-]{10,}/, /\bna[kp]_(live|test)_[A-Za-z0-9]{8,}/,
  /\bnsk_[A-Za-z0-9]{8,}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/, /postgres(ql)?:\/\/[^\s"]*:[^\s"]*@/, /\bBearer\s+[A-Za-z0-9._~+/-]{12,}/, /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\./,
  /X-Amz-Signature=/i, /(?<![A-Za-z0-9])[A-Za-z0-9]{32,}(?![A-Za-z0-9])/,
];
export function keyShaped(text) {
  const hits = [];
  for (const re of KEY_SHAPES) { const m = String(text).match(re); if (m) hits.push(re.source.slice(0, 40) + ' => ' + m[0].slice(0, 6) + '...'); }
  return hits;
}

export function context(root) {
  const C = { root };
  const py = spawnSync('python3', ['-I', '-c', 'import json,sys; sys.path.insert(0, sys.argv[1]); import datasets; print(json.dumps(sorted(list(datasets.D) + list(datasets.Q))))', path.join(root, 'pipeline')], { encoding: 'utf8' });
  if (py.status !== 0) throw new Error('could not read pipeline/datasets.py: ' + py.stderr);
  C.datasets = JSON.parse(py.stdout);
  const schema = fs.readFileSync(path.join(root, 'neon', 'schema.sql'), 'utf8');
  C.jobs = [...new Set([...schema.matchAll(/INSERT INTO ti\.lease \(job\) VALUES ([^;]+);/g)].flatMap((m) => [...m[1].matchAll(/\('([a-z0-9]+)'\)/g)].map((x) => x[1])))].sort();
  const html = fs.readFileSync(path.join(root, 'public', 'index.html'), 'utf8');
  C.pages = [...new Set([...html.matchAll(/data-page="([a-z]+)"/g)].map((m) => m[1]))].sort();
  return C;
}
export async function collectorFacts(root) {
  const M = await import(pathToFileURL(path.join(root, 'neon', 'collector.mjs')).href);
  return { health: M.HEALTH_FEED_IDS(), gaps: [...new Set([...Object.keys(M.KNOWN_GAPS), ...Object.values(M.KNOWN_GAP_VOLUME)])].sort() };
}

export function check(reg, text, C, F) {
  const errors = [];
  const err = (m) => errors.push(m);
  if (!reg || !Array.isArray(reg.rows)) return ['registry has no rows array'];
  for (const h of keyShaped(text)) err('key-shaped string in the registry: ' + h);
  const ids = new Set(), iso = /^\d{4}-\d{2}-\d{2}$/;
  const datasets = new Set(C.datasets), pages = new Set(C.pages);
  for (const r of reg.rows) {
    const at = `row ${r.id || '(no id)'}`;
    for (const f of FIELDS) if (!(f in r)) err(`${at}: missing field ${f}`);
    if (!/^[a-z0-9][a-z0-9-]*$/.test(r.id || '')) err(`${at}: id must be lowercase letters, digits and hyphens`);
    if (ids.has(r.id)) err(`${at}: duplicate id`); ids.add(r.id);
    if (!STATUSES.includes(r.status)) err(`${at}: status ${r.status} not one of ${STATUSES.join(', ')}`);
    if (!ACCESS.includes(r.access)) err(`${at}: access ${r.access} not one of ${ACCESS.join(', ')}`);
    if (!r.licence || !String(r.licence).trim()) err(`${at}: no licence`);
    if (!iso.test(r.added || '') || !iso.test(r.reviewed || '')) err(`${at}: added and reviewed must be YYYY-MM-DD`);
    if (!/^https?:\/\//.test(r.url || '')) err(`${at}: url must be http(s)`);
    if (r.secret != null) {
      if (typeof r.secret !== 'object' || !/^[A-Z][A-Z0-9_]{2,63}$/.test(r.secret.name || '') || !SECRET_WHERE.includes(r.secret.where) || Object.keys(r.secret).some((k) => !['name', 'where'].includes(k)))
        err(`${at}: secret must be {name: UPPER_CASE_NAME, where: ${SECRET_WHERE.join('|')}} and nothing else`);
      if (r.access === 'open' && r.secret.where !== 'none' && r.secret.name !== 'SEC_USER_AGENT' && r.secret.name !== 'GREYNOISE_API_KEY') err(`${at}: an open source with a stored secret`);
    }
    if (r.access === 'key' && !r.secret) err(`${at}: access "key" needs a secret name`);
    if (r.status === 'known_gap' && !r.gap_note) err(`${at}: a known gap needs a gap_note`);
    if (['held', 'candidate', 'declined', 'not_implemented'].includes(r.status) && !r.gap_note) err(`${at}: status ${r.status} needs a gap_note saying why`);
    for (const f of r.feeds || []) {
      if (f.startsWith('page:')) { if (!pages.has(f.slice(5))) err(`${at}: unknown page ${f}`); }
      else if (!f.startsWith('api:') && !f.startsWith('open-data:') && !datasets.has(f)) err(`${at}: unknown dataset ${f}`);
    }
    for (const j of r.jobs || []) if (!C.jobs.includes(j)) err(`${at}: unknown job ${j}`);
    if (r.health_feed && !F.health.includes(r.health_feed)) err(`${at}: unknown health feed ${r.health_feed}`);
  }
  const live = reg.rows.filter((r) => r.status !== 'candidate' && r.status !== 'not_implemented' && r.status !== 'declined');
  for (const h of F.health) if (!reg.rows.some((r) => r.health_feed === h)) err(`collector health feed ${h} has no row`);
  for (const d of C.datasets) if (!live.some((r) => (r.feeds || []).includes(d))) err(`dataset ${d} (site.json) has no row feeding it`);
  for (const j of C.jobs) if (!live.some((r) => (r.jobs || []).includes(j))) err(`lease job ${j} has no row`);
  const gapRows = reg.rows.filter((r) => r.status === 'known_gap').map((r) => r.gap_id || r.health_feed).sort();
  for (const g of F.gaps) if (!gapRows.includes(g)) err(`known gap ${g} (KNOWN_GAPS) has no known_gap row`);
  for (const g of gapRows) if (!F.gaps.includes(g)) err(`row with status known_gap names ${g}, which KNOWN_GAPS does not list`);
  return errors;
}

export async function run(root, file = path.join(root, 'data', 'data_sources.json')) {
  const text = fs.readFileSync(file, 'utf8');
  let reg = null;
  try { reg = JSON.parse(text); } catch (e) { return { errors: ['registry is not valid JSON: ' + e.message], rows: 0 }; }
  const errors = check(reg, text, context(root), await collectorFacts(root));
  return { errors, rows: reg.rows ? reg.rows.length : 0 };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const root = path.resolve(process.argv[2] || '.');
  const r = await run(root, process.argv[3]);
  for (const e of r.errors) console.log('  ' + e);
  console.log(r.errors.length ? `data sources registry: ${r.errors.length} problem(s) in ${r.rows} rows` : `data sources registry: ${r.rows} rows checked`);
  process.exit(r.errors.length ? 1 : 0);
}
