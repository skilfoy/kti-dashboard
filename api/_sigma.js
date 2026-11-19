const { handle, sendJson, cors, q } = require('./_lib');
const store = require('../lib/store');

// Sigma detection drafts (3.8.0), from the collector's sigma document (neon/parts/37o-sigma.mjs).
//   /api/sigma                         the drafting attempts and their rules (accepted and rejected) of the last 180 days
//   /api/sigma?format=yaml[&subject=]  the accepted drafts as one multi-document YAML file, for a Sigma toolchain
//   /api/sigma?id=<rule id>&format=yaml  one accepted draft
// Drafts are written by a free hosted model from publishers' pages and accepted by deterministic checks; they are
// unreviewed leads for a detection engineer to test, never rules to deploy as they stand.
const SUBJECT = /^(actor|extortion|malware|tool|campaign|cve):[A-Za-z0-9:._\-]{1,120}$/;
const RID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

module.exports = handle(async (req, res) => {
  const s = await store.getDoc(req, 'sigma');
  if (!s.ok) return sendJson(res, 502, { error: 'not collected yet', store: s.reason || 'missing' }, 0);
  const subject = String(q(req, 'subject', '')), id = String(q(req, 'id', '')).toLowerCase();
  if (subject && !SUBJECT.test(subject)) return sendJson(res, 400, { error: 'subject must be an entity id such as malware:S1138' }, 0);
  if (id && !RID.test(id)) return sendJson(res, 400, { error: 'id must be a draft rule id (a UUID)' }, 0);
  let rows = s.doc.rows || [];
  if (subject) rows = rows.filter((r) => r.subject === subject);
  if (id) rows = rows.filter((r) => r.kind === 'rule' && r.id === id);
  if (q(req, 'format', '') === 'yaml') {
    const drafts = rows.filter((r) => r.kind === 'rule' && r.ok && r.yaml);
    if (id && !drafts.length) return sendJson(res, 404, { error: 'no accepted draft has that id' }, 0);
    cors(res);
    res.setHeader('Content-Type', 'application/yaml; charset=utf-8');
    res.setHeader('Content-Disposition', `inline; filename="${id ? 'kti-sigma-' + id : 'kti-sigma-drafts'}.yml"`);
    res.setHeader('Cache-Control', 'public, s-maxage=600, stale-while-revalidate=1800');
    const head = `# KTI Sigma drafts, generated ${s.doc.generated}. Written by a free hosted model from public reporting and accepted by\n# deterministic checks (taxonomy, condition, grounding in the cited pages, ATT&CK ids). Unreviewed: test before use.\n`;
    return res.status(200).send(head + drafts.map((r) => r.yaml).join('---\n'));
  }
  sendJson(res, 200, { ...s.doc, rows, age_min: Math.round(store.ageMin(s.doc.generated)) }, 120, 600);
});
