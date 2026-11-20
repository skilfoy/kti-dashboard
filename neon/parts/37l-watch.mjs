// ---------------------------------------------------------------- standing watches and change alerts (3.5.0)
// The machine half of the priority intelligence requirements. data/watches.json (published at /data/watches.json)
// ties each watch to a PIR and gives it a kind:
//   entity_terms     an entity of the selected types (and attributed country, for state actors) named in an entry
//                    whose title carries one of a term list's words (financial, critical infrastructure, identity
//                    abuse, takedowns), by enough publishers in the window
//   entity_category  the same, from a feed category (government and CERT publications) instead of terms
//   terms            a term list's word in titles by enough publishers, without an entity
//   kev_added        a CVE added to CISA KEV, with the date the collection first named it (lead time before KEV)
//   cve_surge        a CVE outside KEV reported by three or more publishers in 72 hours (a pre-KEV signal)
//   first_seen       an entity named for the first time (waits for the 14-day baseline)
//   surge            an entity named far above its own baseline (waits for the 14-day baseline)
// Every run re-evaluates each watch over its window and keeps one alert per watch and subject: new matching entries
// update the open alert; a subject quiet for QUIET_DAYS opens a new one next time. Alerts are leads, as the triage
// labels are: the reassessment opens the entries and cites the publishers. Watches name public threat entities and
// topics only.
export const WATCH = { QUIET_DAYS: 14, KEEP_DAYS: 120, LINKS: 8, URL: 'https://intel.kilfoycyber.com/data/watches.json', MAX_IDS: 25 };

let WSPEC = null;
async function loadWatches() {
  if (WSPEC && Date.now() - WSPEC.at < 3600e3) return WSPEC;
  let doc = null, via = 'site';
  const r = await get(ENV().TI_WATCHES_URL || WATCH.URL, { as: 'json', timeout: 20000 });
  if (r.ok && r.json && Array.isArray(r.json.watches) && r.json.watches.length) doc = r.json;
  if (doc) await s3Put('ref/watches.json.gz', gzipSync(Buffer.from(JSON.stringify(doc)), { level: 9 }), 'application/gzip').catch(() => null);
  else {
    const o = await refGet('ref/watches.json');
    if (!o) throw new Error('the watch list is unreachable: site ' + (r.status || r.error) + ', and ref/watches.json is missing from the bucket');
    doc = JSON.parse(o.buf.toString('utf8'));
    via = 'bucket';
  }
  WSPEC = { at: Date.now(), doc, via };
  return WSPEC;
}
export function resetWatches() { WSPEC = null; }

// A term list as a Postgres regular expression on word boundaries ("\m(bank|banks)\M"); list names refer to doc.terms.
export function termRegex(doc, name) {
  const raw = (doc.terms && doc.terms[name]) || name;
  const alts = String(raw).split('|').map((s) => s.trim()).filter(Boolean);
  if (!alts.length || alts.some((a) => !/^[a-z0-9 ?\-']+$/i.test(a))) throw new Error('bad term list ' + name);
  return '\\m(' + alts.join('|') + ')\\M';
}

// to_jsonb: a jsonb[] slice would reach the job as Postgres array text, not JSON.
const LINKS_SQL = `to_jsonb((array_agg(jsonb_build_object('link', d.link, 'title', d.title, 'host', d.host, 'published', d.published) ORDER BY d.published DESC))[1:${WATCH.LINKS}])`;
// The selected entities: by type, and by attributed country when the watch names one (MISP and ATT&CK attribution).
function selectSql(sel, at) {
  const where = [`e.t = ANY(ARRAY(SELECT jsonb_array_elements_text($${at}::jsonb)))`];
  const params = [sel.types || []];
  if (sel.nexus && sel.nexus.length) {
    where.push(`EXISTS (SELECT 1 FROM ti.erel r WHERE r.a = e.id AND r.rel = 'attributed-to' AND r.b = ANY(ARRAY(SELECT 'country:' || jsonb_array_elements_text($${at + 1}::jsonb))))`);
    params.push(sel.nexus);
  }
  return { where: where.join(' AND '), params };
}

// One watch's candidates: [{subject, name, type, n, p, first_at, last_at, links, detail}].
export async function evalWatch(w, doc, ctx) {
  const days = Math.max(1, Math.min(30, +w.window_days || 7)), minP = Math.max(1, +w.min_publishers || 1);
  if (w.kind === 'entity_terms' || w.kind === 'entity_category') {
    const s = selectSql(w.select || {}, 3);
    const filt = w.kind === 'entity_terms' ? `d.title ~* $2` : `d.category = ANY(ARRAY(SELECT jsonb_array_elements_text($2::jsonb)))`;
    return sql(`SELECT e.id AS subject, e.n AS name, e.t AS type, count(DISTINCT d.link)::int AS n, count(DISTINCT d.host)::int AS p, min(d.published) AS first_at, max(d.published) AS last_at, ${LINKS_SQL} AS links
      FROM ti.mention m JOIN ti.mdoc d ON d.link = m.link JOIN ti.entity e ON e.id = m.eid
      WHERE d.published > now() - make_interval(days => $1) AND d.published <= now() + interval '1 day' AND ${filt} AND ${s.where}
      GROUP BY 1, 2, 3 HAVING count(DISTINCT d.host) >= ${minP} ORDER BY p DESC, n DESC LIMIT 50`,
      [days, w.kind === 'entity_terms' ? termRegex(doc, w.terms) : (w.categories || []), ...s.params]);
  }
  if (w.kind === 'terms') {
    const rx = termRegex(doc, w.terms);
    return (await sql(`SELECT lower((regexp_match(d.title, $2, 'i'))[1]) AS subject, count(DISTINCT d.link)::int AS n, count(DISTINCT d.host)::int AS p, min(d.published) AS first_at, max(d.published) AS last_at, ${LINKS_SQL} AS links
      FROM ti.mdoc d WHERE d.published > now() - make_interval(days => $1) AND d.published <= now() + interval '1 day' AND d.title ~* $2
      GROUP BY 1 HAVING count(DISTINCT d.host) >= ${minP} ORDER BY p DESC LIMIT 30`, [days, rx]))
      .map((r) => ({ ...r, subject: 'term:' + r.subject.replace(/\s+/g, ' '), name: r.subject, type: 'term' }));
  }
  if (w.kind === 'kev_added') {
    return (await sql(`SELECT e.id AS subject, e.n AS name, 'cve' AS type, e.m, (SELECT count(DISTINCT x.link)::int FROM ti.mention x WHERE x.eid = e.id) AS n,
        (SELECT count(DISTINCT x.host)::int FROM ti.mention x WHERE x.eid = e.id) AS p, (SELECT min(x.published) FROM ti.mention x WHERE x.eid = e.id) AS named_first,
        (SELECT ${LINKS_SQL} FROM ti.mention x JOIN ti.mdoc d ON d.link = x.link WHERE x.eid = e.id) AS links
      FROM ti.entity e WHERE e.t = 'cve' AND e.m ? 'kev' AND (e.m->>'kev')::date > (now() - make_interval(days => $1))::date ORDER BY (e.m->>'kev') DESC LIMIT 60`, [days]))
      .map((r) => {
        const kev = r.m.kev, lead = r.named_first ? Math.round((Date.parse(kev + 'T00:00:00Z') - Date.parse(new Date(r.named_first).toISOString().slice(0, 10) + 'T00:00:00Z')) / 864e5) : null;
        return { subject: r.subject, name: r.name, type: 'cve', n: r.n, p: r.p, first_at: kev + 'T00:00:00Z', last_at: kev + 'T00:00:00Z', links: r.links || [],
          detail: { vendor: r.m.vendor || null, product: r.m.product || null, ransomware: !!r.m.ransomware, kev_added: kev, collection_first_named: r.named_first, lead_days: lead } };
      });
  }
  if (w.kind === 'cve_surge') {
    const hours = Math.max(6, Math.min(240, +w.window_hours || 72));
    return sql(`SELECT m.eid AS subject, m.eid AS name, 'cve' AS type, count(DISTINCT d.link)::int AS n, count(DISTINCT d.host)::int AS p, min(d.published) AS first_at, max(d.published) AS last_at, ${LINKS_SQL} AS links
      FROM ti.mention m JOIN ti.mdoc d ON d.link = m.link LEFT JOIN ti.entity e ON e.id = m.eid
      WHERE m.eid LIKE 'cve:%' AND d.published > now() - make_interval(hours => $1) AND d.published <= now() + interval '1 day' AND NOT coalesce(e.m ? 'kev', false)
      GROUP BY 1 HAVING count(DISTINCT d.host) >= ${minP} ORDER BY p DESC LIMIT 40`, [hours]).then((rs) => rs.map((r) => ({ ...r, name: r.subject.slice(4) })));
  }
  if (w.kind === 'coincidence') {
    const kv = (await sql(`SELECT v FROM ti.kv WHERE k = 'cyphys:latest'`))[0];
    const min = Math.max(2, +w.min_signals || 2);
    return ((kv && kv.v && kv.v.coincidences) || []).filter((c) => c.elevated >= min).map((c) => ({ subject: 'country:' + c.cc, name: c.name, type: 'country', n: c.elevated, p: c.cyber_p,
      first_at: c.outage_last || kv.v.at, last_at: kv.v.at, links: [], detail: { outage_hours: c.outage_hours, conflict_z: c.conflict_z, conflict_24h: c.conflict_24h, cyber_p: c.cyber_p,
        signals: ['outage', 'conflict', 'cyber'].filter((s) => c[s]), entities: (c.entities || []).slice(0, 6).map((e) => e.n) } }));
  }
  // Signposts (3.9.0, 37p-foresight.mjs): an indicator named as a signpost by a threatcasting future whose authored
  // state moved since the last run. Nothing is read before a future exists; the first run after that records the
  // states and opens nothing.
  if (w.kind === 'signpost') {
    const idx = (await kvGet('foresight:signposts')) || {};
    if (!Object.keys(idx).length) return [];
    const inds = await siteRef('theater_indicators', (a) => a.length >= 10 && a.every((i) => i.ind_id && i.theater_id));
    const prev = await kvGet('signpost:states');
    const now = Object.fromEntries(inds.map((i) => [i.ind_id, i.state]));
    await kvPut('signpost:states', now);
    if (!prev) return [];
    const items = await siteRef('items', (a) => a.length >= 100 && a.every((i) => i.item_id)).catch(() => []);
    const url = new Map(items.map((i) => [i.item_id, i.url]));
    const at = new Date().toISOString();
    return inds.filter((i) => idx[i.ind_id] && prev[i.ind_id] && prev[i.ind_id] !== i.state).map((i) => {
      const futures = idx[i.ind_id].map((f) => ({ ...f, meets: f.expect === 'present' ? ['Observed', 'Confirmed'].includes(i.state) : i.state === 'Not observed' }));
      return { subject: `indicator:${i.ind_id}:${i.state}`, name: i.ind_id, type: 'indicator', n: 1, p: 1, first_at: i.last_seen || at, last_at: at,
        links: url.get(i.item_id) ? [{ link: url.get(i.item_id), title: i.note || i.indicator, host: (String(url.get(i.item_id)).match(/^https?:\/\/([^/]+)/) || [])[1] || null, published: i.last_seen || null }] : [],
        detail: { theater_id: i.theater_id, theater: i.theater_name || i.theater_id, indicator: i.indicator, from: prev[i.ind_id], to: i.state, item_id: i.item_id || null, futures } };
    });
  }
  if (w.kind === 'first_seen' || w.kind === 'surge') {
    if (!ctx.baselineReady) return [];
    const s = selectSql(w.select || {}, 1);
    const rows = await sql(`SELECT e.id AS subject, e.n AS name, e.t AS type, count(*) FILTER (WHERE m.published > now() - interval '7 days')::int AS n,
        count(DISTINCT m.host) FILTER (WHERE m.published > now() - interval '7 days')::int AS p, count(*) FILTER (WHERE m.published > now() - interval '30 days')::int AS n30,
        min(m.published) AS first_ever, min(m.published) FILTER (WHERE m.published > now() - interval '7 days') AS first_at, max(m.published) AS last_at
      FROM ti.mention m JOIN ti.entity e ON e.id = m.eid WHERE ${s.where} GROUP BY 1, 2, 3 HAVING count(*) FILTER (WHERE m.published > now() - interval '7 days') > 0`, s.params);
    const out = [];
    for (const r of rows) {
      if (r.p < minP) continue;
      if (w.kind === 'first_seen' && Date.parse(r.first_ever) > Date.now() - 7 * 864e5) out.push({ ...r, detail: { first_named: r.first_ever } });
      if (w.kind === 'surge') { const z = riseScore(r.n, r.n30, ctx.priorDays); if (z >= (+w.z || 3)) out.push({ ...r, detail: { z, n30: r.n30 } }); }
    }
    for (const r of out) {
      const l = await sql(`SELECT ${LINKS_SQL} AS links FROM ti.mention x JOIN ti.mdoc d ON d.link = x.link WHERE x.eid = $1 AND d.published > now() - interval '7 days'`, [r.subject]);
      r.links = (l[0] && l[0].links) || [];
    }
    return out;
  }
  throw new Error('unknown watch kind ' + w.kind);
}

export function headline(w, c, doc) {
  const pubs = `${c.n} ${c.n === 1 ? 'entry' : 'entries'} from ${c.p} ${c.p === 1 ? 'publisher' : 'publishers'}`;
  switch (w.kind) {
    case 'kev_added': return `${c.name} added to CISA KEV${c.detail && c.detail.vendor ? ` (${c.detail.vendor}${c.detail.product ? ' ' + c.detail.product : ''})` : ''}${c.detail && c.detail.lead_days > 0 ? `; the collection named it ${c.detail.lead_days} days earlier` : ''}`;
    case 'cve_surge': return `${c.name} reported by ${c.p} publishers outside KEV (${pubs})`;
    case 'terms': return `"${c.name}" in ${pubs}`;
    case 'first_seen': return `${c.name} named for the first time (${pubs})`;
    case 'surge': return `${c.name} named well above its baseline (${pubs} in 7 days, z ${c.detail && c.detail.z})`;
    case 'coincidence': return `${c.name}: ${c.detail.signals.join(', ')} elevated together${c.detail.outage_hours ? `; ${c.detail.outage_hours} h of outage` : ''}${c.detail.conflict_z != null && c.detail.signals.includes('conflict') ? `; conflict z ${c.detail.conflict_z}` : ''}${c.detail.signals.includes('cyber') ? `; ${c.detail.cyber_p} publishers on threat actors` : ''}`;
    case 'entity_category': return `${c.name} named in government or CERT publications (${pubs})`;
    case 'signpost': {
      const met = c.detail.futures.filter((f) => f.meets).map((f) => `"${f.name}"`);
      return `${c.name} (${c.detail.theater}) moved ${c.detail.from} to ${c.detail.to}: ${c.detail.indicator}${met.length ? `; now meets the signpost of ${met.join(' and ')}` : '; a signpost of this theater\'s futures'}`;
    }
    default: return `${c.name} named with ${(doc && doc.term_labels && doc.term_labels[w.terms]) || w.terms + ' terms'} (${pubs})`;
  }
}

export async function jobWatch() {
  const t0 = Date.now();
  const { doc, via } = await loadWatches();
  const since = (await sql(`SELECT (v->>'since')::timestamptz AS since FROM ti.kv WHERE k = 'entities:since'`))[0];
  const ageDays = since && since.since ? (Date.now() - Date.parse(since.since)) / 864e5 : 0;
  const ctx = { baselineReady: ageDays >= ENTITY.BASELINE_DAYS, priorDays: Math.min(23, ageDays - 7) };
  const open = await sql(`SELECT id, watch, subject, last_at, opened_at, n, p FROM ti.alert WHERE last_at > now() - make_interval(days => $1)`, [WATCH.QUIET_DAYS]);
  const openBy = new Map(open.map((a) => [a.watch + '|' + a.subject, a]));
  const rows = [], per = {};
  for (const w of doc.watches) {
    let cands;
    try { cands = await evalWatch(w, doc, ctx); } catch (e) { per[w.id] = { error: String(e.message || e) }; continue; }
    per[w.id] = { candidates: cands.length };
    for (const c of cands) {
      const prior = openBy.get(w.id + '|' + c.subject);
      const id = prior ? prior.id : 'A-' + createHash('sha256').update([w.id, c.subject, String(c.first_at).slice(0, 10)].join('|')).digest('hex').slice(0, 12);
      rows.push({ id, watch: w.id, pir: w.pir, kind: w.kind, subject: c.subject, subject_name: String(c.name || '').slice(0, 200), subject_type: c.type || null, title: w.title,
        headline: headline(w, c, doc).slice(0, 400), n: c.n || 0, p: c.p || 0, first_at: c.first_at || null, last_at: c.last_at || c.first_at || null, links: c.links || [], detail: c.detail || {} });
    }
  }
  const st = [];
  // New entries extend an open alert (counts, latest entries, last date); its id and opening time stay.
  if (rows.length) st.push([`INSERT INTO ti.alert (id, watch, pir, kind, subject, subject_name, subject_type, title, headline, n, p, first_at, last_at, links, detail)
    SELECT id, watch, pir, kind, subject, subject_name, subject_type, title, headline, n, p, first_at, last_at, links, detail FROM jsonb_to_recordset($1::jsonb)
      AS x(id text, watch text, pir text, kind text, subject text, subject_name text, subject_type text, title text, headline text, n int, p int, first_at timestamptz, last_at timestamptz, links jsonb, detail jsonb)
    ON CONFLICT (id) DO UPDATE SET headline = EXCLUDED.headline, n = GREATEST(ti.alert.n, EXCLUDED.n), p = GREATEST(ti.alert.p, EXCLUDED.p), last_at = GREATEST(ti.alert.last_at, EXCLUDED.last_at),
      first_at = LEAST(ti.alert.first_at, EXCLUDED.first_at), links = EXCLUDED.links, detail = EXCLUDED.detail,
      updated_at = CASE WHEN (ti.alert.n, ti.alert.p) IS DISTINCT FROM (GREATEST(ti.alert.n, EXCLUDED.n), GREATEST(ti.alert.p, EXCLUDED.p)) THEN now() ELSE ti.alert.updated_at END`, [rows]]);
  st.push([`DELETE FROM ti.alert WHERE last_at < now() - make_interval(days => $1)`, [WATCH.KEEP_DAYS]]);
  await sqlTx(st);
  const fresh = rows.filter((r) => !openBy.has(r.watch + '|' + r.subject)).length;
  const out = await alertsDoc(doc, ctx);
  const published = await putDoc('alerts', out);
  return { watches: doc.watches.length, via, candidates: rows.length, opened: fresh, baseline_ready: ctx.baselineReady, per_watch: per, published, ms: Date.now() - t0 };
}

async function alertsDoc(doc, ctx) {
  const alerts = await sql(`SELECT id, watch, pir, kind, subject, subject_name, subject_type, title, headline, n, p, first_at, last_at, opened_at, updated_at, links, detail
    FROM ti.alert WHERE last_at > now() - interval '30 days' ORDER BY opened_at DESC, p DESC LIMIT 400`);
  const counts = new Map();
  for (const a of alerts) counts.set(a.watch, (counts.get(a.watch) || 0) + 1);
  return {
    source: 'KTI standing watches over the entity graph and CISA KEV', generated: new Date().toISOString(), served_from: 'store', baseline_ready: ctx.baselineReady,
    method: 'Each watch in data/watches.json belongs to a priority intelligence requirement and is evaluated every 15 minutes over its window: entities named with a term list in entry titles, entities named by government and CERT publications, term clusters, KEV additions with the collection\'s lead time, CVEs outside KEV reported by three or more publishers, and (after a 14-day baseline) first appearances and surges. One alert is kept per watch and subject; new entries update it, and a subject quiet for 14 days opens a new alert. Alerts are machine leads from titles, unreviewed.',
    marking: 'Machine alerts, unreviewed', count: alerts.length,
    rows: doc.watches.map((w) => ({ kind: 'watch', watch: w.id, pir: w.pir, watch_kind: w.kind, title: w.title, alerts_30d: counts.get(w.id) || 0, waits_for_baseline: !!w.baseline && !ctx.baselineReady }))
      .concat(alerts.map((a) => ({ ...a, kind: 'alert', watch_kind: a.kind }))),
  };
}

// ---------------------------------------------------------------- a visitor's watchlist (GET /watch on the HTTP surface)
// What changed for up to 25 entities since a time: entries that name each, entities co-mentioned with it for the first
// time, CVEs added to KEV for a watched vendor or product, and platform alerts on it. Nothing is stored: the list lives
// in the visitor's browser or in their feed reader's URL.
export async function watchChanges(ids, since, days = 30) {
  ids = [...new Set(String(ids || '').split(',').map((s) => s.trim()).filter((s) => EID.test(s)))].slice(0, WATCH.MAX_IDS);
  if (!ids.length) return { error: 'ids required', status: 400 };
  days = Math.max(1, Math.min(90, +days || 30));
  const floor = Date.now() - days * 864e5, t = Math.max(floor, Date.parse(since) || floor), sinceIso = new Date(t).toISOString();
  const J = JSON.stringify(ids);
  const [ents, entries, partners, kev, alerts] = await sqlTx([
    [`SELECT id, t, n FROM ti.entity WHERE id = ANY(ARRAY(SELECT jsonb_array_elements_text($1::jsonb)))`, [J]],
    [`SELECT m.eid, d.link, d.title, d.host, d.published, m.via FROM ti.mention m JOIN ti.mdoc d ON d.link = m.link
      WHERE m.eid = ANY(ARRAY(SELECT jsonb_array_elements_text($1::jsonb))) AND d.published > $2::timestamptz ORDER BY d.published DESC LIMIT 400`, [J, sinceIso]],
    [`WITH co AS (SELECT a.eid AS w, b.eid AS o, min(a.published) AS first, count(*)::int AS n, count(DISTINCT a.host)::int AS p FROM ti.mention a JOIN ti.mention b ON b.link = a.link AND b.eid <> a.eid
        WHERE a.eid = ANY(ARRAY(SELECT jsonb_array_elements_text($1::jsonb))) AND b.eid NOT LIKE 'country:%' GROUP BY 1, 2)
      SELECT co.w, co.o, e.n AS name, e.t, co.first, co.n AS cnt, co.p FROM co JOIN ti.entity e ON e.id = co.o WHERE co.first > $2::timestamptz ORDER BY co.first DESC LIMIT 100`, [J, sinceIso]],
    [`SELECT r.b AS w, c.id, c.m FROM ti.erel r JOIN ti.entity c ON c.id = r.a WHERE r.rel = 'affects' AND r.b = ANY(ARRAY(SELECT jsonb_array_elements_text($1::jsonb)))
        AND (c.m->>'kev')::date >= ($2::timestamptz)::date ORDER BY c.m->>'kev' DESC LIMIT 100`, [J, sinceIso]],
    [`SELECT id, watch, pir, headline, subject, opened_at, last_at, n, p FROM ti.alert WHERE subject = ANY(ARRAY(SELECT jsonb_array_elements_text($1::jsonb))) AND (opened_at > $2::timestamptz OR updated_at > $2::timestamptz) ORDER BY opened_at DESC LIMIT 100`, [J, sinceIso]],
  ]);
  const name = new Map(ents.map((e) => [e.id, e]));
  const items = ids.map((id) => {
    const e = name.get(id) || { id, t: id.split(':')[0], n: id.split(':').slice(1).join(':') };
    const es = entries.filter((x) => x.eid === id);
    return { id, t: e.t, n: e.n, known: name.has(id), entries: es.length, publishers: new Set(es.map((x) => x.host)).size, latest: es.slice(0, 5).map(({ eid, ...x }) => x),
      new_partners: partners.filter((x) => x.w === id).slice(0, 12).map((x) => ({ id: x.o, n: x.name, t: x.t, first: x.first, entries: x.cnt, publishers: x.p })),
      kev: kev.filter((x) => x.w === id).map((x) => ({ cve: x.id.slice(4), added: x.m.kev, product: x.m.product || null, ransomware: !!x.m.ransomware })),
      alerts: alerts.filter((x) => x.subject === id) };
  });
  // One chronological list for the feed: an event per entry, new partner, KEV addition and alert.
  const events = [];
  for (const it of items) {
    for (const x of entries.filter((y) => y.eid === it.id)) events.push({ at: x.published, entity: it.id, entity_name: it.n, kind: 'entry', title: x.title, link: x.link, host: x.host, via: x.via });
    for (const x of partners.filter((y) => y.w === it.id)) events.push({ at: x.first, entity: it.id, entity_name: it.n, kind: 'new_partner', title: `${it.n} named with ${x.name} for the first time`, partner: x.o });
    for (const x of it.kev) events.push({ at: x.added + 'T00:00:00Z', entity: it.id, entity_name: it.n, kind: 'kev', title: `${x.cve} (${it.n}${x.product && !it.n.includes(x.product) ? ' ' + x.product : ''}) added to CISA KEV` });
    for (const x of it.alerts) events.push({ at: x.opened_at, entity: it.id, entity_name: it.n, kind: 'alert', title: x.headline, alert: x.id, pir: x.pir });
  }
  events.sort((a, b) => String(b.at).localeCompare(String(a.at)));
  return { since: sinceIso, ids, items, events: events.slice(0, 300), count: events.length };
}
