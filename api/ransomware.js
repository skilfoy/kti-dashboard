const path = require('path');
const { pathToFileURL } = require('url');
const { handle, sendJson, upstream, q } = require('./_lib');
const store = require('../lib/store');
// ransomware.live v2. ?type=recentvictims|groups|recentcyberattacks (default recentvictims).
const MAP = {
  recentvictims: 'https://api.ransomware.live/v2/recentvictims',
  groups: 'https://api.ransomware.live/v2/groups',
  recentcyberattacks: 'https://api.ransomware.live/v2/recentcyberattacks',
};
// The collector keeps a last-good copy of these every 30 minutes.
const SNAP = { recentvictims: 'snap-ransomware', recentcyberattacks: 'snap-cyberattacks' };
// Press-reported attacks are normalized by the collector's cyber part, which has no imports and loads on its own.
let CYBER = null;
const cyber = () => CYBER || (CYBER = import(pathToFileURL(path.join(__dirname, '..', 'neon', 'parts', '35-cyber.mjs')).href));

module.exports = handle(async (req, res) => {
  const type = MAP[q(req, 'type', 'recentvictims')] ? q(req, 'type', 'recentvictims') : 'recentvictims';
  const r = await upstream(MAP[type], { timeout: 25000 }).catch((e) => ({ ok: false, status: 0, error: String(e.message || e) }));
  const stale = async (why) => {
    const s = SNAP[type] ? await store.getDoc(req, SNAP[type]) : { ok: false };
    if (s.ok) return sendJson(res, 200, { ...s.doc, served_from: 'store-stale', stale: true, age_min: Math.round(store.ageMin(s.doc.generated)), upstream_status: r.status, ...(why ? { upstream_note: why } : {}) }, 60, 300);
    return sendJson(res, 502, { error: 'upstream', status: r.status, ...(why ? { note: why } : {}) }, 0);
  };
  if (!r.ok || !r.json) return stale();
  const arr = Array.isArray(r.json) ? r.json : (r.json.data || []);
  if (type === 'recentcyberattacks') {
    const doc = (await cyber()).cyberattackDoc(arr);
    if (!doc.count) return stale('upstream returned no rows');
    return sendJson(res, 200, doc, 600, 3600);
  }
  let rows = arr;
  if (type === 'recentvictims') {
    // Victim names are dropped here; the dashboard aggregates claims by group, sector and country.
    rows = arr.map((v) => ({
      group: String(v.group_name || v.group || '').toLowerCase(),
      country: v.country || '',
      sector: v.activity || v.sector || '',
      discovered: String(v.discovered || v.published || '').slice(0, 19),
      published: String(v.published || '').slice(0, 19),
    }));
  } else if (type === 'groups') {
    rows = arr.map((g) => ({ group: String(g.name || '').toLowerCase(), altname: g.altname || '', url_count: (g.locations || []).length }));
  }
  sendJson(res, 200, { source: 'ransomware.live', type, generated: new Date().toISOString(), count: rows.length, rows }, 60, 600);
});
