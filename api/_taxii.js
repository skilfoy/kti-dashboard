const crypto = require('crypto');
const { cors, q } = require('./_lib');
const store = require('../lib/store');

// TAXII 2.1 read-only server (3.0), public, TLP:GREEN content only. vercel.json rewrites /taxii2/<path> here.
//   GET /taxii2/                                         discovery
//   GET /taxii2/api/                                     API root
//   GET /taxii2/api/collections/                         collections
//   GET /taxii2/api/collections/{id}/                    one collection
//   GET /taxii2/api/collections/{id}/objects/            STIX 2.1 objects (?added_after, ?limit, ?next, ?match[type], ?match[id])
//   GET /taxii2/api/collections/{id}/objects/{obj-id}/   one object
//   GET /taxii2/api/collections/{id}/manifest/           the manifest
// Collections: the platform's key judgments (STIX report objects with their evidence as external references), the
// vendor and CERT advisories with their CVEs (vulnerability and report objects), and the agentic reports (report
// objects pointing to the report page and its cited sources). Object ids are deterministic, so a client's added_after
// polling sees an object once per version.
const MT = 'application/taxii+json;version=2.1', STIX = 'application/stix+json;version=2.1';
const TLP_GREEN = 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da';
const SITE = 'https://intel.kilfoycyber.com';
const uuid = (s) => {
  const h = crypto.createHash('sha1').update('kti-stix|' + s).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${((parseInt(h[16], 16) & 3) | 8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
};
const IDENT = `identity--${uuid('producer')}`;
const identity = (at) => ({ type: 'identity', spec_version: '2.1', id: IDENT, created: '2026-10-16T00:00:00.000Z', modified: '2026-10-16T00:00:00.000Z', name: 'Kilfoy Threat Intelligence', identity_class: 'organization', contact_information: SITE });
const iso = (s, d) => { const t = Date.parse(s); return isFinite(t) ? new Date(t).toISOString() : d; };
const COLS = {
  [uuid('col:judgments')]: { key: 'judgments', title: 'KTI key judgments', description: 'The platform\'s ranked analytic judgments on cyber and cyber-physical threats, with likelihood, probability, severity and the evidence items behind each.' },
  [uuid('col:advisories')]: { key: 'advisories', title: 'KTI vendor and CERT advisories', description: 'Advisories from 24 vendor PSIRT and CERT feeds of the last 14 days, as STIX vulnerability objects by CVE and one report per advisory; CVEs in CISA KEV are labelled.' },
  [uuid('col:graph')]: { key: 'graph', title: 'KTI entity graph', description: 'The actors, extortion groups, malware, tools, campaigns, CVEs, vendors, products and countries the platform\'s collection named most in the last 30 days, with curated relationships from ATT&CK, MISP and KEV and observed co-mention relationships (related-to, with entry and publisher counts and normalized PMI). Co-mention is association in reporting, not attribution.' },
  [uuid('col:alerts')]: { key: 'alerts', title: 'KTI change alerts', description: 'Alerts from the platform\'s standing watches, each tied to a priority intelligence requirement: STIX report objects naming the watched entity (as in the entity graph collection) with the latest entries as external references. Machine leads from entry titles, unreviewed.' },
  [uuid('col:reports')]: { key: 'reports', title: 'KTI agentic reports', description: 'Machine-written intelligence reports generated on the platform from its collected reporting and live web search, each citing its sources. Unreviewed.' },
};
const fetchJson = (u) => fetch(u, { headers: { accept: 'application/json' } }).then((r) => (r.ok ? r.json() : null)).catch(() => null);
const rows = (x) => (Array.isArray(x) ? x : (x && x.rows) || []);
async function objectsFor(key, req) {
  if (key === 'judgments') {
    const [js, ev, items, ledger] = await Promise.all(['judgments', 'evidence', 'items', 'ledger'].map((n) => fetchJson(`${SITE}/data/${n}.json`).then(rows)));
    const at = iso((ledger.slice(-1)[0] || {}).at, '2026-10-16T00:00:00.000Z');
    const byItem = new Map(items.map((i) => [i.item_id, i]));
    return js.filter((j) => j.status !== 'Retired' && (!j.tlp || /GREEN|CLEAR|WHITE/i.test(j.tlp))).map((j) => {
      const refs = ev.filter((e) => e.judgment_id === j.judgment_id).map((e) => byItem.get(e.item_id)).filter(Boolean);
      const mod = iso(j.last_reviewed, at);
      return { type: 'report', spec_version: '2.1', id: `report--${uuid(j.judgment_id)}`, created_by_ref: IDENT, created: iso(j.opened, mod), modified: mod, published: mod,
        name: `${j.judgment_id}: ${j.title}`, description: [j.situation, j.assessment, j.action].filter(Boolean).join('\n\n'), report_types: ['threat-report'],
        labels: [j.likelihood, j.probability && `probability:${j.probability}`, j.severity && `severity:${j.severity}`, j.vector && `vector:${j.vector}`, j.theater_id && `theater:${j.theater_id}`].filter(Boolean),
        object_refs: [IDENT], object_marking_refs: [TLP_GREEN],
        external_references: [{ source_name: 'KTI', url: `${SITE}/#theaters`, external_id: j.judgment_id }, ...refs.slice(0, 60).map((i) => ({ source_name: i.source_name || 'source', url: i.url, description: `${i.date} ${i.title}`.slice(0, 500) }))],
        x_kti_likelihood: j.likelihood || null, x_kti_horizon: j.horizon || null, x_kti_pirs: j.pirs || null };
    });
  }
  if (key === 'advisories') {
    const d = await store.getDoc(req, 'psirt', { timeout: 15000 });
    if (!d.ok) return [];
    const out = [], seen = new Map();
    for (const a of (d.doc.rows || []).filter((r) => r.kind === 'advisory')) {
      const when = iso(a.published || a.first_seen, iso(d.doc.generated, new Date().toISOString()));
      const kev = new Set(a.kev || []);
      const refs = (a.cves || []).map((c) => {
        if (!seen.has(c)) { const o = { type: 'vulnerability', spec_version: '2.1', id: `vulnerability--${uuid(c)}`, created_by_ref: IDENT, created: when, modified: when, name: c, object_marking_refs: [TLP_GREEN], external_references: [{ source_name: 'cve', external_id: c }] }; seen.set(c, o); out.push(o); }
        if (kev.has(c)) seen.get(c).labels = ['cisa-kev'];
        return seen.get(c).id;
      });
      if (!refs.length) continue;
      out.push({ type: 'report', spec_version: '2.1', id: `report--${uuid(a.link)}`, created_by_ref: IDENT, created: when, modified: when, published: when, name: a.title, report_types: ['vulnerability'],
        labels: ['vendor-advisory'].concat(kev.size ? ['names-kev-cve'] : []), object_refs: refs, object_marking_refs: [TLP_GREEN], external_references: [{ source_name: a.vendor || a.feed || 'advisory', url: a.link }] });
    }
    return out;
  }
  if (key === 'graph') {
    const d = await store.getDoc(req, 'entities', { timeout: 15000 });
    if (!d.ok) return [];
    const gen = iso(d.doc.generated, new Date().toISOString()), out = [], ref = new Map();
    const TYPE = { actor: 'intrusion-set', extortion: 'intrusion-set', malware: 'malware', tool: 'tool', campaign: 'campaign', cve: 'vulnerability', vendor: 'identity', product: 'software', country: 'location' };
    const sid = (id) => {
      const t = TYPE[id.split(':')[0]];
      if (!t) return null;
      return t === 'vulnerability' ? `vulnerability--${uuid(id.slice(4))}` : `${t}--${uuid('entity|' + id)}`;
    };
    for (const e of (d.doc.rows || []).filter((r) => r.kind === 'entity')) {
      const t = TYPE[e.t] || TYPE[e.id.split(':')[0]], id = sid(e.id);
      if (!t || !id) continue;
      const created = iso(e.first, gen), modified = iso(e.last, gen) > created ? iso(e.last, gen) : created;
      const att = /^(actor|extortion|malware|tool|campaign):([GSC]\d{4})$/.exec(e.id);
      const base = { type: t, spec_version: '2.1', id, object_marking_refs: [TLP_GREEN] };
      let o;
      if (t === 'software') o = { ...base, name: e.n };
      else if (t === 'location') o = { ...base, created_by_ref: IDENT, created, modified, name: e.n, country: e.id.slice(8) };
      else if (t === 'identity') o = { ...base, created_by_ref: IDENT, created, modified, name: e.n, identity_class: 'organization', sectors: ['technology'] };
      else if (t === 'vulnerability') o = { ...base, created_by_ref: IDENT, created, modified, name: e.n, external_references: [{ source_name: 'cve', external_id: e.n }] };
      else o = { ...base, created_by_ref: IDENT, created, modified, name: e.n, ...(t === 'malware' ? { is_family: true } : {}), ...(e.t === 'extortion' ? { labels: ['extortion'] } : {}),
        ...(att ? { external_references: [{ source_name: 'mitre-attack', external_id: att[2], url: `https://attack.mitre.org/${att[2][0] === 'G' ? 'groups' : att[2][0] === 'S' ? 'software' : 'campaigns'}/${att[2]}` }] } : {}) };
      o.x_kti_entity = e.id; o.x_kti_entries_7d = e.n7; o.x_kti_entries_30d = e.n30; o.x_kti_publishers_30d = e.p30;
      if (e.rising) o.x_kti_rising = true;
      ref.set(e.id, id);
      out.push(o);
    }
    // STIX relationship types: "uses" stands as is; "attributed-to" becomes "originates-from" for a country and stays
    // only for a campaign attributed to a group; every other curated link (KEV "affects" and "made-by") and every
    // co-mention is "related-to", with the source's own term kept in x_kti_relationship.
    const relType = (r, a, b) => {
      if (r.kind === 'edge') return 'related-to';
      if (r.rel === 'uses') return 'uses';
      if (r.rel === 'attributed-to' && b.startsWith('location--')) return 'originates-from';
      if (r.rel === 'attributed-to' && a.startsWith('campaign--') && b.startsWith('intrusion-set--')) return 'attributed-to';
      return 'related-to';
    };
    for (const r of (d.doc.rows || []).filter((x) => x.kind === 'rel' || x.kind === 'edge')) {
      const a = ref.get(r.a), b = ref.get(r.b);
      if (!a || !b) continue;
      const rel = relType(r, a, b);
      const o = { type: 'relationship', spec_version: '2.1', id: `relationship--${uuid(['graph', r.kind, r.a, r.b, r.rel || ''].join('|'))}`, created_by_ref: IDENT, created: gen, modified: gen,
        relationship_type: rel, source_ref: a, target_ref: b, object_marking_refs: [TLP_GREEN] };
      if (r.kind === 'edge') Object.assign(o, { description: `Named together in ${r.n} collected entries from ${r.p} publishers in the last 30 days (normalized PMI ${r.npmi}). Co-mention in reporting, not attribution.`, x_kti_basis: 'observed', x_kti_entries: r.n, x_kti_publishers: r.p, x_kti_npmi: r.npmi });
      else Object.assign(o, { x_kti_basis: r.basis, x_kti_relationship: r.rel });
      out.push(o);
    }
    return out;
  }
  if (key === 'alerts') {
    const d = await store.getDoc(req, 'alerts', { timeout: 15000 });
    if (!d.ok) return [];
    const TYPE = { actor: 'intrusion-set', extortion: 'intrusion-set', malware: 'malware', tool: 'tool', campaign: 'campaign', vendor: 'identity', product: 'software', country: 'location' };
    return (d.doc.rows || []).filter((r) => r.kind === 'alert').map((a) => {
      const pre = String(a.subject).split(':')[0], ref = pre === 'cve' ? `vulnerability--${uuid(String(a.subject).slice(4))}` : TYPE[pre] ? `${TYPE[pre]}--${uuid('entity|' + a.subject)}` : null;
      const created = iso(a.opened_at, iso(d.doc.generated, new Date().toISOString())), modified = iso(a.updated_at, created) > created ? iso(a.updated_at, created) : created;
      const links = Array.isArray(a.links) ? a.links : [];
      return { type: 'report', spec_version: '2.1', id: `report--${uuid('alert|' + a.id)}`, created_by_ref: IDENT, created, modified, published: modified, name: `[${a.pir}] ${a.headline}`,
        description: `${a.title}. ${a.n} entries from ${a.p} publishers between ${String(a.first_at || '').slice(0, 10)} and ${String(a.last_at || '').slice(0, 10)}. Machine alert from entry titles, unreviewed.`,
        report_types: ['threat-report'], labels: ['machine-generated', 'unreviewed', 'watch:' + a.watch, 'pir:' + a.pir], object_refs: [ref || IDENT], object_marking_refs: [TLP_GREEN],
        external_references: [{ source_name: 'KTI', external_id: a.id, url: `${SITE}/#requirements` }, ...links.slice(0, 8).map((l) => ({ source_name: l.host || 'source', url: l.link, description: String(l.title || '').slice(0, 300) }))] };
    });
  }
  if (key === 'reports') {
    const r = await store.call(req, '/reports?limit=100', { timeout: 15000 });
    if (!r.ok) return [];
    return (JSON.parse(r.buf.toString('utf8')).reports || []).map((x) => {
      const when = iso(x.done_at, iso(x.created_at, new Date().toISOString()));
      return { type: 'report', spec_version: '2.1', id: `report--${uuid(x.id)}`, created_by_ref: IDENT, created: iso(x.created_at, when), modified: when, published: when,
        name: `${x.q} (${x.type})`, description: String(x.lead || '').slice(0, 300), report_types: ['threat-report'], labels: ['machine-generated', 'unreviewed', 'type:' + x.type],
        object_refs: [IDENT], object_marking_refs: [TLP_GREEN], external_references: [{ source_name: 'KTI', external_id: x.id, url: `${SITE}/#search?report=${x.id}` }], x_kti_model: x.model || null };
    });
  }
  return [];
}
function send(res, status, body) {
  cors(res);
  res.setHeader('Content-Type', MT);
  res.setHeader('Cache-Control', status === 200 ? 'public, s-maxage=300, stale-while-revalidate=900' : 'no-store');
  res.status(status).send(JSON.stringify(body));
}
const err = (res, status, title, description) => send(res, status, { title, http_status: String(status), ...(description ? { description } : {}) });
module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') { cors(res); res.status(204).end(); return; }
  if (req.method !== 'GET' && req.method !== 'HEAD') return err(res, 405, 'Method not allowed', 'This TAXII server is read-only.');
  try {
    const parts = String(q(req, 'path', '')).split('/').filter(Boolean);
    const base = `https://${req.headers['x-forwarded-host'] || req.headers.host || 'intel.kilfoycyber.com'}/taxii2/`;
    if (!parts.length) return send(res, 200, { title: 'Kilfoy Threat Intelligence TAXII 2.1', description: 'Read-only TAXII 2.1 server for the KTI platform (TLP:GREEN).', contact: SITE, default: base + 'api/', api_roots: [base + 'api/'] });
    if (parts[0] !== 'api') return err(res, 404, 'Not found');
    if (parts.length === 1) return send(res, 200, { title: 'KTI', description: 'Key judgments, advisories, agentic reports, the entity graph and change alerts.', versions: [MT], max_content_length: 10485760 });
    if (parts[1] !== 'collections') return err(res, 404, 'Not found');
    const col = (id) => ({ id, title: COLS[id].title, description: COLS[id].description, can_read: true, can_write: false, media_types: [STIX] });
    if (parts.length === 2) return send(res, 200, { collections: Object.keys(COLS).map(col) });
    const id = parts[2];
    if (!COLS[id]) return err(res, 404, 'Collection not found');
    if (parts.length === 3) return send(res, 200, col(id));
    let objs = await objectsFor(COLS[id].key, req);
    if (!objs.length && COLS[id].key !== 'reports') return err(res, 503, 'Collection temporarily unavailable', 'The source of this collection did not answer.');
    objs = [identity(), ...objs];
    // date_added is the object's modified time (the platform publishes, it does not receive).
    objs = objs.map((o) => ({ o, added: o.modified || o.created })).sort((a, b) => a.added.localeCompare(b.added));
    const after = q(req, 'added_after', ''), types = String(q(req, 'match[type]', '')).split(',').filter(Boolean), ids = String(q(req, 'match[id]', '')).split(',').filter(Boolean);
    let list = objs.filter((x) => (!after || x.added > iso(after, '')) && (!types.length || types.includes(x.o.type)) && (!ids.length || ids.includes(x.o.id)));
    if (parts[3] === 'objects' && parts[4]) list = list.filter((x) => x.o.id === parts[4]);
    const limit = Math.max(1, Math.min(1000, +q(req, 'limit', 500) || 500)), start = Math.max(0, +q(req, 'next', 0) || 0), page = list.slice(start, start + limit);
    if (page.length) { res.setHeader('X-TAXII-Date-Added-First', page[0].added); res.setHeader('X-TAXII-Date-Added-Last', page[page.length - 1].added); }
    const more = start + limit < list.length;
    if (parts[3] === 'manifest') return send(res, 200, { more, ...(more ? { next: String(start + limit) } : {}), objects: page.map((x) => ({ id: x.o.id, date_added: x.added, version: x.o.modified || x.o.created, media_type: STIX })) });
    if (parts[3] === 'objects') {
      if (parts[4] && !page.length) return err(res, 404, 'Object not found');
      return send(res, 200, { more, ...(more ? { next: String(start + limit) } : {}), objects: page.map((x) => x.o) });
    }
    return err(res, 404, 'Not found');
  } catch (e) { return err(res, 500, 'Server error', String((e && e.message) || e).slice(0, 200)); }
};
module.exports.COLS = COLS;
