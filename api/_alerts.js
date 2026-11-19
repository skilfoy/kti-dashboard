const crypto = require('crypto');
const { handle, sendJson, cors, q } = require('./_lib');
const store = require('../lib/store');

// Standing watches and change alerts (3.5.0), answered from the collector (neon/parts/37l-watch.mjs).
//   /api/alerts[?pir=PIR-2][&format=atom]           the platform's change alerts of the last 30 days, as JSON or an Atom feed
//   /api/watch?ids=a,b[&since=ISO][&format=atom]    what changed for up to 25 entities: entries, first co-mentions, KEV
//                                                   additions for a watched vendor or product, and alerts on them
// Alerts are machine leads from entry titles, unreviewed. Nothing about a visitor's watchlist is stored: it travels in
// the request (or the feed reader's URL).
const SITE = 'https://intel.kilfoycyber.com';
const ID = /^(actor|extortion|malware|tool|campaign|vendor|product|cve|country):[A-Za-z0-9:._\-]{1,120}$/;
const xml = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c])).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '');
const uuid = (s) => { const h = crypto.createHash('sha1').update('kti-atom|' + s).digest('hex'); return `urn:uuid:${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`; };
const iso = (s) => { const t = Date.parse(s); return new Date(isFinite(t) ? t : Date.now()).toISOString(); };
function atom(res, { id, title, self, alt, updated, entries }) {
  cors(res);
  res.setHeader('Content-Type', 'application/atom+xml; charset=utf-8');
  res.setHeader('Cache-Control', 'public, s-maxage=600, stale-while-revalidate=1800');
  const body = ['<?xml version="1.0" encoding="utf-8"?>', '<feed xmlns="http://www.w3.org/2005/Atom">', `<id>${xml(id)}</id>`, `<title>${xml(title)}</title>`, `<updated>${iso(updated)}</updated>`,
    `<link rel="self" type="application/atom+xml" href="${xml(self)}"/>`, `<link rel="alternate" type="text/html" href="${xml(alt)}"/>`, '<author><name>Kilfoy Threat Intelligence</name></author>',
    ...entries.map((e) => ['<entry>', `<id>${xml(e.id)}</id>`, `<title>${xml(e.title)}</title>`, `<updated>${iso(e.updated)}</updated>`, `<link href="${xml(e.link || alt)}"/>`,
      e.category ? `<category term="${xml(e.category)}"/>` : '', `<summary type="text">${xml(e.summary || e.title)}</summary>`, '</entry>'].join('')), '</feed>'].join('\n');
  res.status(200).send(body);
}

async function alerts(req, res) {
  const s = await store.getDoc(req, 'alerts');
  if (!s.ok) return sendJson(res, 502, { error: 'not collected yet', store: s.reason || 'missing' }, 0);
  const pir = String(q(req, 'pir', '')).toUpperCase();
  const rows = (s.doc.rows || []).filter((r) => r.kind === 'alert' && (!pir || r.pir === pir));
  if (q(req, 'format', '') === 'atom') {
    return atom(res, { id: uuid('alerts|' + pir), title: `KTI change alerts${pir ? ' for ' + pir : ''}`, self: `${SITE}/api/alerts?format=atom${pir ? '&pir=' + pir : ''}`, alt: `${SITE}/#requirements`,
      updated: s.doc.generated, entries: rows.slice(0, 100).map((a) => ({ id: uuid(a.id), title: `[${a.pir}] ${a.headline}`, updated: a.updated_at || a.opened_at, category: a.watch,
        link: (a.links && a.links[0] && a.links[0].link) || `${SITE}/#graph?id=${encodeURIComponent(a.subject)}`,
        summary: `${a.title}. ${a.headline}. Latest: ${(a.links || []).slice(0, 5).map((l) => `${l.title} (${l.host})`).join('; ')}. Machine alert from entry titles, unreviewed.` })) });
  }
  return sendJson(res, 200, { ...s.doc, rows: pir ? (s.doc.rows || []).filter((r) => r.kind !== 'alert' || r.pir === pir) : s.doc.rows, age_min: Math.round(store.ageMin(s.doc.generated)) }, 120, 600);
}

async function watch(req, res) {
  const ids = String(q(req, 'ids', '')).split(',').map((x) => x.trim()).filter((x) => ID.test(x)).slice(0, 25);
  if (!ids.length) return sendJson(res, 400, { error: 'ids must list entity ids such as actor:G0007 (up to 25)' }, 0);
  const since = String(q(req, 'since', '')).slice(0, 40), days = Math.max(1, Math.min(90, +q(req, 'days', 30) || 30));
  const r = await store.call(req, `/watch?ids=${encodeURIComponent(ids.join(','))}&days=${days}${since ? '&since=' + encodeURIComponent(since) : ''}`, { timeout: 20000 });
  if (!r.ok) return sendJson(res, 502, { error: 'watch unavailable', reason: r.reason || 'HTTP ' + r.status }, 0);
  const body = JSON.parse(r.buf.toString('utf8'));
  if (q(req, 'format', '') === 'atom') {
    const names = (body.items || []).map((i) => i.n).join(', ');
    return atom(res, { id: uuid('watch|' + ids.join(',')), title: `KTI watchlist: ${names}`.slice(0, 200), self: `${SITE}/api/watch?ids=${encodeURIComponent(ids.join(','))}&format=atom`,
      alt: `${SITE}/#graph?id=${encodeURIComponent(ids[0])}`, updated: (body.events[0] && body.events[0].at) || new Date().toISOString(),
      entries: body.events.slice(0, 150).map((e) => ({ id: uuid([e.kind, e.entity, e.link || e.partner || e.alert || e.title].join('|')), title: e.kind === 'entry' ? `${e.entity_name}: ${e.title}` : e.title,
        updated: e.at, category: e.kind, link: e.link || `${SITE}/#graph?id=${encodeURIComponent(e.partner || e.entity)}`, summary: e.kind === 'entry' ? `${e.host}, named as "${e.via}"` : e.title })) });
  }
  sendJson(res, 200, { source: 'KTI entity graph watchlist', generated: new Date().toISOString(), ...body }, 120, 600);
}

module.exports = handle(async (req, res) => (q(req, 'route', '') === 'watch' ? watch(req, res) : alerts(req, res)));
