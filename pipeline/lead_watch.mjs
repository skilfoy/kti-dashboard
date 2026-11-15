// Intraday lead watch, without a model. Reads the machine triage document and keeps one GitHub issue, labelled
// lead-watch, open while a relevance 3 lead of the last 72 hours names a CVE that CISA KEV lists or an actor that a
// ranked key judgment names. The daily analyst run reads the issue first (runbook section 1). The watch moves no
// level and writes no authored data: it only makes sure the next analyst run looks.
// Usage: node pipeline/lead_watch.mjs <repo root>   (needs GITHUB_TOKEN with issues: write and GITHUB_REPOSITORY;
// DRY_RUN=1 prints the action only).
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

export const LABEL = 'lead-watch';
export const TITLE = 'Lead watch: leads that touch KEV or a ranked judgment';
export const TRIAGE_URL = 'https://intel.kilfoycyber.com/api/context?type=triage';
const esc = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Leads worth an analyst's first look: relevance 3 and a KEV CVE, or an actor named in a ranked judgment's text.
export function watchLeads(doc, judgments) {
  const ranked = (judgments || []).filter((j) => (j.exec_rank || 0) > 0 && j.status !== 'Retired');
  const text = (j) => [j.title, j.situation, j.assessment, j.attribution_judgment].join(' ');
  const hits = [];
  for (const r of (doc && doc.rows) || []) {
    if (r.relevance !== 3) continue;
    const why = [];
    if ((r.kev || []).length) why.push('names ' + r.kev.join(', ') + ', listed in CISA KEV');
    for (const a of r.actors || []) {
      if (String(a).length < 4) continue;
      const re = new RegExp('(^|[^a-z0-9])' + esc(a.toLowerCase()) + '([^a-z0-9]|$)');
      const js = ranked.filter((j) => re.test(text(j).toLowerCase())).map((j) => j.judgment_id);
      if (js.length) why.push(`names ${a}, which ${js.join(', ')} ${js.length > 1 ? 'name' : 'names'}`);
    }
    if (why.length) hits.push({ title: String(r.title).slice(0, 200), link: r.link, source: r.source || '', published: r.published || null, why });
  }
  return hits.sort((a, b) => String(b.published).localeCompare(String(a.published))).slice(0, 25);
}
export const fingerprint = (hits) => createHash('sha256').update(hits.map((h) => h.link).sort().join('\n')).digest('hex').slice(0, 12);
export function issueBody(hits, at) {
  return [`Machine triage leads of the last 72 hours that the next analyst run should open first. Updated ${at}.`, '',
    'These are leads from an unreviewed model tier. Open each page and confirm the claim before anything enters the evidence base.', '',
    ...hits.map((h) => `- [${h.title.replace(/[\[\]]/g, '')}](${h.link})${h.source ? ' (' + h.source + ')' : ''}: ${h.why.join('; ')}`), '',
    `<!-- fp:${fingerprint(hits)} -->`].join('\n');
}
// What to do with the open issue given this evaluation: create, update (the set of leads changed), close, or nothing.
export function plan(hits, open, at) {
  const fp = open && (String(open.body || '').match(/<!-- fp:([0-9a-f]{12}) -->/) || [])[1];
  if (!hits.length) return open ? { op: 'close', number: open.number, comment: `Cleared at ${at}: no relevance 3 lead of the last 72 hours touches KEV or a ranked judgment.` } : { op: 'none' };
  if (!open) return { op: 'create', title: TITLE, body: issueBody(hits, at) };
  return fp === fingerprint(hits) ? { op: 'none' } : { op: 'update', number: open.number, body: issueBody(hits, at) };
}
async function gh(method, p, body) {
  const r = await fetch('https://api.github.com/repos/' + process.env.GITHUB_REPOSITORY + p, { method, body: body ? JSON.stringify(body) : undefined,
    headers: { authorization: 'Bearer ' + process.env.GITHUB_TOKEN, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'content-type': 'application/json', 'user-agent': 'kti-lead-watch' } });
  if (!r.ok) throw new Error(`GitHub ${method} ${p}: HTTP ${r.status} ${(await r.text()).slice(0, 300)}`);
  return r.status === 204 ? null : r.json();
}
async function main() {
  const root = process.argv[2] || '.', at = new Date().toISOString().slice(0, 16) + 'Z';
  const judgments = JSON.parse(fs.readFileSync(path.join(root, 'data', 'authored', 'judgments.json'), 'utf8'));
  const r = await fetch(TRIAGE_URL, { headers: { accept: 'application/json', 'user-agent': 'kti-lead-watch' }, signal: AbortSignal.timeout(30000) });
  if (!r.ok) { console.log(`triage document not readable (HTTP ${r.status}); nothing changed`); return; }
  const doc = await r.json();
  const fresh = doc.generated && Date.now() - Date.parse(doc.generated) < 6 * 3600000;
  if (!fresh) { console.log('triage document is older than six hours; nothing changed'); return; }
  const hits = watchLeads(doc, judgments);
  const open = (await gh('GET', `/issues?state=open&labels=${LABEL}&per_page=20`)).filter((i) => !i.pull_request && i.title === TITLE)[0] || null;
  const a = plan(hits, open, at);
  console.log(JSON.stringify({ hits: hits.length, action: a.op }));
  if (process.env.DRY_RUN === '1' || a.op === 'none') return;
  if (a.op === 'create') await gh('POST', '/issues', { title: a.title, body: a.body, labels: [LABEL] });
  else if (a.op === 'update') await gh('PATCH', `/issues/${a.number}`, { body: a.body });
  else if (a.op === 'close') { await gh('POST', `/issues/${a.number}/comments`, { body: a.comment }); await gh('PATCH', `/issues/${a.number}`, { state: 'closed', state_reason: 'completed' }); }
}
if (import.meta.url === pathToFileURL(process.argv[1] || '').href) main().catch((e) => { console.error(e.message); process.exit(1); });
