// ---------------------------------------------------------------- GDELT
const GDELT = 'http://data.gdeltproject.org/gdeltv2/';
const ARMED = new Set(['MIL', 'REB', 'INS', 'SEP', 'UAF', 'SPY']);
const TYPES = [12, 13, 14, 22, 23, 24];
const C = { id: 0, a1: 6, a2: 16, root: 25, code: 26, rootCode: 28, quad: 29, gold: 30, mentions: 31, sources: 32,
  a1geoType: 35, a1place: 36, a1lat: 40, a1lon: 41, geoType: 51, place: 52, lat: 56, lon: 57, added: 59, url: 60 };
const W_HOURS = 24, W_BASE = 48, KEEP_DETAIL_H = 96, EVENTS_PER_SLOT = 60;
const stamp = (d) => d.toISOString().replace(/[-:T]/g, '').slice(0, 14);
const fromStamp = (s) => new Date(Date.UTC(+s.slice(0, 4), +s.slice(4, 6) - 1, +s.slice(6, 8), +s.slice(8, 10), +s.slice(10, 12)));

export function firstEntry(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error('zip: no end of central directory');
  const cd = buf.readUInt32LE(eocd + 16);
  if (buf.readUInt32LE(cd) !== 0x02014b50) throw new Error('zip: bad central directory');
  const method = buf.readUInt16LE(cd + 10), size = buf.readUInt32LE(cd + 20), lo = buf.readUInt32LE(cd + 42);
  if (buf.readUInt32LE(lo) !== 0x04034b50) throw new Error('zip: bad local header');
  const start = lo + 30 + buf.readUInt16LE(lo + 26) + buf.readUInt16LE(lo + 28);
  const data = buf.subarray(start, start + size);
  if (method === 0) return data;
  if (method === 8) return inflateRawSync(data);
  throw new Error('zip: unsupported method ' + method);
}

// One 15-minute export reduced to the rows the window document needs.
export function aggregateSlot(text, G) {
  const countries = new Map(), cells = new Map(), events = [], flows = new Map();
  let scanned = 0, kept = 0;
  for (const line of text.split('\n')) {
    if (!line) continue;
    scanned++;
    const f = line.split('\t');
    if (f.length < 61 || f[C.root] !== '1' || f[C.quad] !== '4') continue;
    if (!TYPES.some((i) => ARMED.has(f[i]))) continue;
    const lat = parseFloat(f[C.lat]), lon = parseFloat(f[C.lon]);
    if (!isFinite(lat) || !isFinite(lon)) continue;
    kept++;
    const mentions = parseInt(f[C.mentions], 10) || 0;
    const iso = isoAt(G, lon, lat);
    if (iso) { const c = countries.get(iso) || { iso2: iso, n: 0, m: 0 }; c.n++; c.m += mentions; countries.set(iso, c); }
    if (f[C.geoType] !== '1') {
      const la = Math.floor(lat) + 0.5, lo = Math.floor(lon) + 0.5, k = la + '|' + lo;
      const c = cells.get(k) || { lat: la, lon: lo, n: 0, m: 0 }; c.n++; c.m += mentions; cells.set(k, c);
    }
    events.push({ id: f[C.id], added: f[C.added], lat: r2(lat), lon: r2(lon), iso2: iso, place: f[C.place], root: f[C.rootCode], code: f[C.code],
      quad: 4, goldstein: parseFloat(f[C.gold]) || 0, actor1: f[C.a1], actor2: f[C.a2], mentions, sources: parseInt(f[C.sources], 10) || 0, url: f[C.url] });
    const a1lat = parseFloat(f[C.a1lat]), a1lon = parseFloat(f[C.a1lon]);
    if (!isFinite(a1lat) || !isFinite(a1lon) || (a1lat === 0 && a1lon === 0) || gcKm(a1lat, a1lon, lat, lon) < 100) continue;
    const fk = Math.round(a1lat) + '|' + Math.round(a1lon) + '>' + Math.round(lat) + '|' + Math.round(lon);
    let fl = flows.get(fk);
    if (!fl) { fl = { fkey: fk, n: 0, m: 0, best: -1, roots: {}, rep: null, urls: new Set() }; flows.set(fk, fl); }
    fl.n++; fl.m += mentions; fl.urls.add(f[C.url]);
    fl.roots[f[C.rootCode]] = (fl.roots[f[C.rootCode]] || 0) + Math.max(1, mentions);
    if (mentions > fl.best) {
      fl.best = mentions;
      fl.rep = { src_lat: r2(a1lat), src_lon: r2(a1lon), src_type: +f[C.a1geoType] || 0, src_place: f[C.a1place], src_iso2: isoAt(G, a1lon, a1lat),
        dst_lat: r2(lat), dst_lon: r2(lon), dst_type: +f[C.geoType] || 0, dst_place: f[C.place], dst_iso2: iso,
        actor1: f[C.a1], actor2: f[C.a2], code: f[C.code], url: f[C.url], id: f[C.id] };
    }
  }
  events.sort((a, b) => b.mentions - a.mentions || b.sources - a.sources);
  const seen = new Set(), top = [];
  for (const e of events) { if (seen.has(e.url)) continue; seen.add(e.url); top.push(e); if (top.length >= EVENTS_PER_SLOT) break; }
  return { scanned, kept, countries: [...countries.values()], cells: [...cells.values()], events: top,
    flows: [...flows.values()].map(({ urls, ...fl }) => ({ ...fl, urls: urls.size })) };
}

// Latest published export. Without lastupdate.txt the clock gives the last quarter hour minus 15 minutes, and a 404
// for a slot that recent may only be publication lag, so it is retried rather than recorded as missing.
async function gdeltLatest() {
  const r = await get(GDELT + 'lastupdate.txt', { timeout: 10000 });
  const m = r.ok && r.text.match(/(\d{14})\.export\.CSV\.zip/);
  if (m) return { latest: fromStamp(m[1]), fromFile: true };
  const n = new Date(); n.setUTCSeconds(0, 0); n.setUTCMinutes(n.getUTCMinutes() - (n.getUTCMinutes() % 15) - 15);
  return { latest: n, fromFile: false };
}

// A 404 is "not yet published" until the slot has settled: GDELT can name a later export in lastupdate.txt before an
// earlier one is served, and on 2 November 2026 every slot of the previous 48 hours answered 200 although the store had
// recorded about one in seven as missing. So a 404 stays a retryable failure (pending) until the slot is SETTLE_H hours
// old and has been asked MISSING_AFTER times; only then is it recorded missing. Failed slots are retried with a doubling
// back-off (15 minutes up to 6 hours) for up to MAX_ATTEMPTS asks. A recheck pass re-asks a few slots recorded missing
// in the trailing RECHECK_DAYS days (the earlier rule marked a slot missing on its first 404), oldest check first.
export const GDELT_RETRY = { SETTLE_H: 6, MISSING_AFTER: 3, MAX_ATTEMPTS: 8, RECHECK_DAYS: 30, RECHECK_PER_RUN: 4, BACKFILL_RECHECK: 48, CONCURRENCY: 4 };
export const gdeltBackoffMs = (attempts) => Math.min(900000 * 2 ** Math.max(0, (attempts || 1) - 1), 6 * 3600000);
// Status for one fetch result: ok, pending (a 404 not yet settled, stored as failed), missing, or failed.
export function gdeltStatus({ status, ok }, slot, priorAttempts, now = Date.now()) {
  if (ok) return 'ok';
  if (status !== 404) return 'failed';
  const settled = now - slot.getTime() >= GDELT_RETRY.SETTLE_H * 3600000 && (priorAttempts || 0) + 1 >= GDELT_RETRY.MISSING_AFTER;
  return settled ? 'missing' : 'pending';
}
// historyDays (up to 35) fills country counts for slots older than the 72-hour window, for the 30-day baseline;
// cells, events and flows are not kept that far back. reprocess re-reads the 72-hour window and overwrites its rows.
export async function jobGdelt({ backfill = false, budgetMs = 40000, rebuild = false, historyDays = 0, reprocess = false } = {}) {
  const t0 = Date.now();
  const G = await geo();
  const { latest } = await gdeltLatest();
  const span = W_HOURS + W_BASE;
  const hist = Math.max(0, Math.min(35, +historyDays || 0));
  const want = [];
  for (let i = hist ? span * 4 : 0; i < (hist ? hist * 96 : span * 4); i++) want.push(new Date(latest.getTime() - i * 900000));
  const lookback = hist ? hist * 24 : span;
  const known = new Map((await sql(`SELECT slot, status, attempts, processed_at FROM ti.gdelt_file WHERE slot > $1::timestamptz - make_interval(hours => $2)`,
    [latest, lookback])).map((r) => [r.slot, r]));
  const now = Date.now(), R = GDELT_RETRY;
  let waiting = 0, gaveUp = 0;
  const isDone = (k) => {
    if (!k) return false;
    if (k.status === 'ok' || k.status === 'missing') return true;
    if (k.attempts >= R.MAX_ATTEMPTS) { gaveUp++; return true; }
    if (now - Date.parse(k.processed_at) < gdeltBackoffMs(k.attempts)) { waiting++; return true; }
    return false;
  };
  const done = new Set(reprocess && !hist ? [] : want.map((d) => d.toISOString()).filter((s2) => isDone(known.get(s2))));
  const cap = backfill || reprocess ? (hist ? 400 : 96) : 16;
  const todo = want.filter((d) => !done.has(d.toISOString())).slice(0, cap).map((d) => ({ slot: d, prior: (known.get(d.toISOString()) || {}).attempts || 0 }));
  // Recheck: slots recorded missing in the trailing window, asked again on the same back-off, a few per run.
  const recheck = reprocess ? [] : (await sql(`SELECT slot, attempts FROM ti.gdelt_file WHERE status = 'missing' AND slot > now() - make_interval(days => $1) AND attempts < $2
      AND processed_at < now() - make_interval(secs => least(900 * power(2, greatest(attempts, 1) - 1), 21600)) ORDER BY processed_at, slot LIMIT $3`,
    [R.RECHECK_DAYS, R.MAX_ATTEMPTS, backfill ? R.BACKFILL_RECHECK : R.RECHECK_PER_RUN]))
    .map((r) => ({ slot: new Date(r.slot), prior: r.attempts, recheck: true })).filter((r) => !todo.some((x) => x.slot.getTime() === r.slot.getTime()));
  const liveFrom = latest.getTime() - span * 3600000;
  const results = [];
  await pool(todo.concat(recheck), backfill || reprocess ? 8 : R.CONCURRENCY, async ({ slot, prior, recheck: re }) => {
    if (Date.now() - t0 > budgetMs) return;
    const s0 = Date.now();
    const r = await get(GDELT + stamp(slot) + '.export.CSV.zip', { as: 'buf', timeout: 20000 });
    const historyOnly = !!hist || slot.getTime() <= liveFrom;
    const st = gdeltStatus(r, slot, prior);
    if (st !== 'ok') {
      // A recheck that is still not served keeps the slot missing (its attempts and check time advance); a pending 404
      // is stored as failed so the regular pass asks again after its back-off.
      const status = re ? 'missing' : st;
      results.push({ slot, status: status === 'pending' ? 'failed' : status, pending: status === 'pending', recheck: !!re, http: r.status, ms: Date.now() - s0 });
      return;
    }
    try {
      const agg = aggregateSlot(firstEntry(r.buf).toString('utf8'), G);
      results.push({ slot, status: 'ok', recovered: !!re, recheck: !!re, ms: Date.now() - s0, ...agg, historyOnly });
    } catch (e) { results.push({ slot, status: 'failed', recheck: !!re, ms: Date.now() - s0, error: String(e.message || e) }); }
  });
  // Write in batches of 8 slots, one transaction each, so a large backfill stays under the request size limit.
  for (let i = 0; i < results.length; i += 8) {
    const part = results.slice(i, i + 8);
    const files = [], countries = [], cells = [], events = [], flows = [];
    for (const r of part) {
      const s = r.slot.toISOString();
      files.push({ slot: s, status: r.status, scanned: r.scanned || 0, kept: r.kept || 0, ms: r.ms });
      if (r.status !== 'ok') continue;
      for (const c of r.countries) countries.push({ slot: s, ...c });
      if (r.historyOnly) continue;
      for (const c of r.cells) cells.push({ slot: s, ...c });
      for (const e of r.events) events.push({ slot: s, ...e });
      if (!r.historyOnly) for (const f of r.flows) flows.push({ slot: s, fkey: f.fkey, n: f.n, m: f.m, best: f.best, urls: f.urls, roots: f.roots, rep: f.rep });
    }
    await sqlTx([
      [`INSERT INTO ti.gdelt_country (slot, iso2, n, m) SELECT slot, iso2, n, m FROM jsonb_to_recordset($1::jsonb) AS x(slot timestamptz, iso2 text, n int, m int)
        ON CONFLICT (slot, iso2) DO UPDATE SET n = EXCLUDED.n, m = EXCLUDED.m`, [countries]],
      [`INSERT INTO ti.gdelt_cell (slot, lat, lon, n, m) SELECT slot, lat, lon, n, m FROM jsonb_to_recordset($1::jsonb) AS x(slot timestamptz, lat real, lon real, n int, m int)
        ON CONFLICT (slot, lat, lon) DO UPDATE SET n = EXCLUDED.n, m = EXCLUDED.m`, [cells]],
      [`INSERT INTO ti.gdelt_event (slot, id, added, lat, lon, iso2, place, root, code, quad, goldstein, actor1, actor2, mentions, sources, url)
        SELECT slot, id, added, lat, lon, iso2, place, root, code, quad, goldstein, actor1, actor2, mentions, sources, url
        FROM jsonb_to_recordset($1::jsonb) AS x(slot timestamptz, id bigint, added text, lat real, lon real, iso2 text, place text, root text, code text, quad smallint,
          goldstein real, actor1 text, actor2 text, mentions int, sources int, url text)
        ON CONFLICT (slot, id) DO UPDATE SET mentions = EXCLUDED.mentions, sources = EXCLUDED.sources`, [events]],
      [`INSERT INTO ti.gdelt_flow (slot, fkey, n, m, best, urls, roots, rep) SELECT slot, fkey, n, m, best, urls, roots, rep
        FROM jsonb_to_recordset($1::jsonb) AS x(slot timestamptz, fkey text, n int, m int, best int, urls int, roots jsonb, rep jsonb)
        ON CONFLICT (slot, fkey) DO UPDATE SET n = EXCLUDED.n, m = EXCLUDED.m, best = EXCLUDED.best, urls = EXCLUDED.urls, roots = EXCLUDED.roots, rep = EXCLUDED.rep`, [flows]],
      [`INSERT INTO ti.gdelt_file (slot, status, scanned, kept, ms, attempts) SELECT slot, status, scanned, kept, ms, 1
        FROM jsonb_to_recordset($1::jsonb) AS x(slot timestamptz, status text, scanned int, kept int, ms int)
        ON CONFLICT (slot) DO UPDATE SET status = EXCLUDED.status, scanned = EXCLUDED.scanned, kept = EXCLUDED.kept, ms = EXCLUDED.ms,
          attempts = ti.gdelt_file.attempts + 1, processed_at = now()`, [files]],
    ]);
  }
  const counts = { ok: 0, missing: 0, failed: 0 };
  const main = results.filter((r) => !r.recheck);
  for (const r of main) counts[r.status]++;
  const pend = main.filter((r) => r.pending), hard = main.filter((r) => r.status === 'failed' && !r.pending);
  const remaining = want.length - done.size - counts.ok - counts.missing;
  const iso = (rs) => rs.slice(0, 6).map((r) => r.slot.toISOString());
  const re = results.filter((r) => r.recheck);
  const files = { files_ok: counts.ok, files_missing: counts.missing, files_pending: pend.length, files_failed: hard.length,
    // Retry and recheck detail for the run record: pending = a 404 not yet settled (asked again later), waiting = failed
    // slots inside their back-off, gave_up = slots asked MAX_ATTEMPTS times, recovered = recorded missing, now served.
    retry: { pending: pend.length, waiting, gave_up: gaveUp, rechecked: re.length, recovered: re.filter((r) => r.recovered).length, still_missing: re.filter((r) => r.status === 'missing').length,
      pending_slots: iso(pend), missing_slots: iso(main.filter((r) => r.status === 'missing')), failed: hard.slice(0, 4).map((r) => ({ slot: r.slot.toISOString(), http: r.http, error: r.error })) } };
  let published = null;
  if (counts.ok || counts.missing || re.some((r) => r.recovered) || rebuild || !(await s3Get('docs/gdelt-w24b48.json.gz'))) {
    published = [await putDoc('gdelt-w24b48', await gdeltWindow(latest, W_HOURS, W_BASE)), await putDoc('gdelt-series30', await gdeltSeries())];
  }
  return { latest: latest.toISOString(), history_days: hist || undefined, reprocess: reprocess || undefined, processed: results.length, ...files,
    remaining: reprocess && !hist ? Math.max(0, want.length - results.length) : Math.max(0, remaining), published, ms: Date.now() - t0 };
}

// The 24h window with a 48h baseline, rows shaped exactly like threat-feeds /api/gdelt-events, plus kind "base30".
export async function gdeltWindow(latest, hours, baseline, { top = 80, maxFlows = 140 } = {}) {
  const L = latest.toISOString(), H = `floor(extract(epoch FROM ($1::timestamptz - slot)) / 3600)::int`;
  const live = `slot > $1::timestamptz - make_interval(hours => $2) AND slot <= $1::timestamptz`;
  const [files, cells, countries, base, base30, events, flows] = await sqlTx([
    [`SELECT count(*) FILTER (WHERE status = 'ok')::int AS ok, count(*) FILTER (WHERE status = 'missing')::int AS missing,
        count(*) FILTER (WHERE status = 'failed')::int AS failed, coalesce(sum(scanned), 0)::int AS scanned, coalesce(sum(kept), 0)::int AS kept,
        count(*) FILTER (WHERE status IN ('ok','missing') AND slot > $1::timestamptz - make_interval(hours => $2))::int AS live_done
      FROM ti.gdelt_file WHERE slot > $1::timestamptz - make_interval(hours => $3) AND slot <= $1::timestamptz`, [L, hours, hours + baseline]],
    [`SELECT lat, lon, ${H} AS h, sum(n)::int AS n, sum(m)::int AS m FROM ti.gdelt_cell WHERE ${live} GROUP BY 1, 2, 3`, [L, hours]],
    [`SELECT iso2, ${H} AS h, sum(n)::int AS n, sum(m)::int AS m FROM ti.gdelt_country WHERE ${live} GROUP BY 1, 2`, [L, hours]],
    [`SELECT iso2, sum(n)::int AS n, sum(m)::int AS m FROM ti.gdelt_country
      WHERE slot > $1::timestamptz - make_interval(hours => $3) AND slot <= $1::timestamptz - make_interval(hours => $2) GROUP BY 1`, [L, hours, hours + baseline]],
    [`WITH blocks AS (SELECT k, $1::timestamptz - make_interval(hours => $2) - make_interval(days => k) AS hi FROM generate_series(0, 29) AS k),
       cov AS (SELECT b.k FROM blocks b JOIN ti.gdelt_file f ON f.slot > b.hi - interval '1 day' AND f.slot <= b.hi AND f.status IN ('ok','missing')
               GROUP BY b.k HAVING count(*) >= 90),
       per AS (SELECT b.k, c.iso2, sum(c.n)::int AS n FROM cov JOIN blocks b USING (k) JOIN ti.gdelt_country c ON c.slot > b.hi - interval '1 day' AND c.slot <= b.hi GROUP BY 1, 2),
       isos AS (SELECT DISTINCT iso2 FROM per)
      SELECT i.iso2, count(*)::int AS days, round(avg(coalesce(p.n, 0)), 2)::float8 AS mean, coalesce(round(stddev_samp(coalesce(p.n, 0)), 2), 0)::float8 AS sd
      FROM cov CROSS JOIN isos i LEFT JOIN per p ON p.k = cov.k AND p.iso2 = i.iso2 GROUP BY i.iso2`, [L, hours]],
    [`SELECT * FROM (SELECT DISTINCT ON (url) id::text AS id, ${H} AS h, added, lat, lon, iso2, place, root, code, quad, goldstein, actor1, actor2, mentions, sources, url
        FROM ti.gdelt_event WHERE ${live} ORDER BY url, mentions DESC, sources DESC) t ORDER BY mentions DESC, sources DESC LIMIT $3`, [L, hours, top]],
    [`WITH w AS (SELECT *, ${H} AS h FROM ti.gdelt_flow WHERE ${live}),
       agg AS (SELECT fkey, sum(n)::int AS n, sum(m)::int AS m, sum(urls)::int AS articles, min(h)::int AS h, count(DISTINCT h)::int AS hours_seen,
                 (array_agg(rep ORDER BY best DESC))[1] AS rep
               FROM w GROUP BY fkey ORDER BY sum(m) DESC, sum(n) DESC LIMIT $3),
       rt AS (SELECT w.fkey, r.key AS root, sum(r.value::int) AS c FROM w JOIN agg USING (fkey) CROSS JOIN LATERAL jsonb_each_text(w.roots) r GROUP BY 1, 2),
       topr AS (SELECT DISTINCT ON (fkey) fkey, root FROM rt ORDER BY fkey, c DESC, root)
      SELECT agg.n, agg.m, agg.articles, agg.h, agg.hours_seen, agg.rep, topr.root FROM agg JOIN topr USING (fkey) ORDER BY agg.m DESC, agg.n DESC`, [L, hours, maxFlows]],
  ]);
  const f = files[0] || { ok: 0, missing: 0, failed: 0, scanned: 0, kept: 0, live_done: 0 };
  const rows = [
    ...cells.map((c) => ({ kind: 'cell', lat: c.lat, lon: c.lon, h: c.h, n: c.n, m: c.m })),
    ...countries.map((c) => ({ kind: 'country', iso2: c.iso2, h: c.h, n: c.n, m: c.m })),
    ...base.map((b) => ({ kind: 'base', iso2: b.iso2, hours: baseline, n: b.n, m: b.m })),
    ...events.map((e) => ({ kind: 'event', ...e })),
    ...flows.map((x) => ({ kind: 'flow', ...x.rep, root: x.root, n: x.n, m: x.m, articles: x.articles, h: x.h, hours_seen: x.hours_seen })),
    ...base30.map((b) => ({ kind: 'base30', iso2: b.iso2, days: b.days, mean: b.mean, sd: b.sd })),
  ];
  const expected = (hours + baseline) * 4;
  return {
    source: 'GDELT 2.0 Event exports (15-minute files), collected incrementally', generated: new Date().toISOString(), served_from: 'store',
    latest: L, hours, baseline, actors: 'armed', quads: '4', files_requested: expected, files_ok: f.ok, files_missing: f.missing, files_failed: f.failed,
    events_scanned: f.scanned, events_kept: f.kept, flows: flows.length, coverage: r2((f.ok + f.missing) / expected), coverage_live: r2(f.live_done / (hours * 4)),
    base30_days: base30.length ? Math.max(...base30.map((b) => b.days)) : 0, count: rows.length, rows,
  };
}

export async function gdeltSeries() {
  const [rows, days] = await sqlTx([
    [`SELECT iso2, to_char(date_trunc('day', slot AT TIME ZONE 'UTC'), 'YYYY-MM-DD') AS d, sum(n)::int AS n FROM ti.gdelt_country
      WHERE slot > now() - interval '31 days' GROUP BY 1, 2`],
    [`SELECT to_char(date_trunc('day', slot AT TIME ZONE 'UTC'), 'YYYY-MM-DD') AS d, count(*) FILTER (WHERE status IN ('ok','missing'))::int AS files
      FROM ti.gdelt_file WHERE slot > now() - interval '31 days' GROUP BY 1 ORDER BY 1`],
  ]);
  const tot = new Map();
  for (const r of rows) tot.set(r.iso2, (tot.get(r.iso2) || 0) + r.n);
  const keep = new Set([...tot.entries()].sort((a, b) => b[1] - a[1]).slice(0, 80).map((x) => x[0]));
  const out = rows.filter((r) => keep.has(r.iso2)).map((r) => ({ kind: 'series', iso2: r.iso2, d: r.d, n: r.n }));
  for (const d of days) out.push({ kind: 'day', d: d.d, files: d.files, complete: d.files >= 90 });
  return { source: 'GDELT 2.0 Event exports, armed-actor material conflict, daily totals by country', generated: new Date().toISOString(), count: out.length, rows: out };
}

