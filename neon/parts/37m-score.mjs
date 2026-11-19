// ---------------------------------------------------------------- track record (3.6.0)
// The platform's own accuracy, measured where a measurement exists and kept as a daily series (ti.score), so the record
// shows its trend and cannot be restated after the fact. The collector measures what its store holds:
//   kev_foresight      CVEs CISA added to KEV since the collection began: how many the collection named first, and
//                      the median days between its first entry and the listing
//   cve_surge_hits     W-2B alerts (a CVE outside KEV reported by three or more publishers) whose CVE KEV listed after
//                      the alert opened, among those at least 30 days old
//   kev_watchlist      the advisory tier's pre-KEV ranking (ti.kevrank): CVEs tracked and the share KEV listed later
//   triage_eval        the triage tier's agreement with the analyst's own labels on the gold set (vector and theater
//                      accuracy, vector false-positive rate)
//   sources            the source network's feeds answering on their last read
//   collector          the share of scheduled job runs that succeeded in seven days
// The page adds what the authored record holds: forecast outcomes and Brier scores, lead dispositions and citation
// verification. Small samples are reported as counts, never as rates alone.
export const TRACK = { KEEP_DAYS: 800, SURGE_MATURE_DAYS: 30 };

export function median(xs) {
  const a = xs.filter((x) => Number.isFinite(x)).sort((p, q) => p - q);
  if (!a.length) return null;
  const m = a.length >> 1;
  return a.length % 2 ? a[m] : (a[m - 1] + a[m]) / 2;
}

export async function measure() {
  const [kev, surge, kr, ev, feeds, runs, since] = await sqlTx([
    // KEV additions since the collection began, with the collection's first entry naming each CVE.
    [`SELECT e.id, (e.m->>'kev')::date AS kev, (SELECT min(m.published) FROM ti.mention m WHERE m.eid = e.id) AS first_named
      FROM ti.entity e WHERE e.t = 'cve' AND e.m ? 'kev' AND (e.m->>'kev')::date >= coalesce((SELECT (v->>'since')::timestamptz FROM ti.kv WHERE k = 'entities:since'), now())::date`],
    [`SELECT a.subject, a.opened_at, (e.m->>'kev')::date AS kev FROM ti.alert a LEFT JOIN ti.entity e ON e.id = a.subject WHERE a.watch = 'W-2B'`],
    [`SELECT count(*)::int AS tracked, count(*) FILTER (WHERE in_kev_at IS NOT NULL)::int AS listed, count(*) FILTER (WHERE first_seen < now() - interval '30 days')::int AS mature,
        count(*) FILTER (WHERE first_seen < now() - interval '30 days' AND in_kev_at IS NOT NULL)::int AS mature_listed, min(first_seen) AS since FROM ti.kevrank`],
    [`SELECT v FROM ti.kv WHERE k = 'triage:eval'`],
    [`SELECT count(*)::int AS active, count(*) FILTER (WHERE status IN ('ok', 'unchanged'))::int AS answering, count(*) FILTER (WHERE fails >= 6)::int AS failing FROM ti.feed WHERE active`],
    [`SELECT count(*)::int AS runs, count(*) FILTER (WHERE ok)::int AS ok FROM ti.run WHERE started_at > now() - interval '7 days'`],
    [`SELECT (v->>'since')::timestamptz AS since FROM ti.kv WHERE k = 'entities:since'`],
  ]);
  // Named first: an entry on an earlier day than the listing. Same-day entries are mostly reports of the listing itself.
  const named = kev.filter((r) => r.first_named && Date.parse(r.first_named) < Date.parse(String(r.kev).slice(0, 10) + 'T00:00:00Z'));
  const after = kev.filter((r) => r.first_named && !named.includes(r)).length;
  const leads = named.map((r) => Math.round((Date.parse(String(r.kev).slice(0, 10) + 'T00:00:00Z') - Date.parse(new Date(r.first_named).toISOString().slice(0, 10) + 'T00:00:00Z')) / 864e5));
  const mature = surge.filter((s) => Date.parse(s.opened_at) < Date.now() - TRACK.SURGE_MATURE_DAYS * 864e5);
  const hit = (s) => s.kev && Date.parse(String(s.kev).slice(0, 10) + 'T23:59:59Z') >= Date.parse(s.opened_at);
  const e = (ev[0] && ev[0].v) || null, k = kr[0] || {}, f = feeds[0] || {}, r = runs[0] || {};
  const pct = (a, b) => (b ? Math.round((1000 * a) / b) / 10 : null);
  return {
    collecting_since: since[0] && since[0].since,
    kev_foresight: { kev_added: kev.length, named_first: named.length, share: pct(named.length, kev.length), median_lead_days: median(leads), max_lead_days: leads.length ? Math.max(...leads) : null,
      named_on_or_after: after, not_named: kev.length - named.length - after },
    cve_surge_hits: { alerts: surge.length, mature: mature.length, listed_after: mature.filter(hit).length, share: pct(mature.filter(hit).length, mature.length),
      listed_after_any_age: surge.filter(hit).length, mature_after_days: TRACK.SURGE_MATURE_DAYS },
    kev_watchlist: { tracked: k.tracked || 0, listed: k.listed || 0, mature: k.mature || 0, mature_listed: k.mature_listed || 0, share_mature: pct(k.mature_listed || 0, k.mature || 0), since: k.since || null },
    triage_eval: e ? { items: e.gold_items || e.items, complete: !!e.complete, vector_accuracy: e.vector_accuracy, theater_accuracy: e.theater_accuracy, theater_macro_f1: e.theater_macro_f1,
      vector_false_positive_rate: e.vector_false_positive_rate, prompt_version: e.prompt_version, promoted: !!e.promoted, thresholds: e.thresholds || null } : null,
    sources: { active: f.active || 0, answering: f.answering || 0, share: pct(f.answering || 0, f.active || 0), failing: f.failing || 0 },
    collector: { runs_7d: r.runs || 0, ok_7d: r.ok || 0, share: pct(r.ok || 0, r.runs || 0) },
  };
}

// The values kept per day: one row per metric, so the series survives a change in what the document shows.
export function scoreRows(day, m) {
  const out = [];
  const add = (metric, value, n, detail = null) => { if (value != null && Number.isFinite(+value)) out.push({ day, metric, value: +value, n: n == null ? null : +n, detail }); };
  add('kev_foresight_share', m.kev_foresight.share, m.kev_foresight.kev_added);
  add('kev_foresight_median_lead_days', m.kev_foresight.median_lead_days, m.kev_foresight.named_first);
  add('cve_surge_hit_share', m.cve_surge_hits.share, m.cve_surge_hits.mature);
  add('kev_watchlist_share', m.kev_watchlist.share_mature, m.kev_watchlist.mature);
  if (m.triage_eval) { add('triage_vector_accuracy', m.triage_eval.vector_accuracy, m.triage_eval.items); add('triage_theater_accuracy', m.triage_eval.theater_accuracy, m.triage_eval.items); }
  add('sources_answering_share', m.sources.share, m.sources.active);
  add('collector_ok_share', m.collector.share, m.collector.runs_7d);
  return out;
}

export async function jobScore() {
  const t0 = Date.now(), m = await measure(), day = new Date().toISOString().slice(0, 10), rows = scoreRows(day, m);
  // The day's value is the last measurement of the day.
  await sqlTx([
    [`INSERT INTO ti.score (day, metric, value, n, detail) SELECT day, metric, value, n, detail FROM jsonb_to_recordset($1::jsonb) AS x(day date, metric text, value real, n int, detail jsonb)
      ON CONFLICT (day, metric) DO UPDATE SET value = EXCLUDED.value, n = EXCLUDED.n, detail = EXCLUDED.detail, at = now()`, [rows]],
    [`DELETE FROM ti.score WHERE day < (now() AT TIME ZONE 'UTC')::date - $1::int`, [TRACK.KEEP_DAYS]],
  ]);
  const series = await sql(`SELECT to_char(day, 'YYYY-MM-DD') AS day, metric, value, n FROM ti.score WHERE day > (now() AT TIME ZONE 'UTC')::date - 180 ORDER BY day`);
  const doc = {
    source: 'KTI track record: measured by the collector from its own store', generated: new Date().toISOString(), served_from: 'store', ...m,
    method: 'Each figure is measured from the store, never entered by hand, and kept as a daily series (ti.score). KEV foresight counts CVEs CISA added to KEV since the collection began and whether an entry named the CVE first; lead days run from the first entry\'s date to the KEV date. Surge hits count W-2B alerts at least 30 days old whose CVE KEV listed after the alert opened. The KEV watchlist is the advisory tier\'s forward test of its pre-KEV ranking. Triage figures are the tier\'s agreement with the analyst\'s labels on the gold set. Small samples are shown with their counts.',
    count: series.length, rows: series.map((s) => ({ kind: 'series', ...s })),
  };
  return { published: await putDoc('scorecard', doc), metrics: rows.length, ms: Date.now() - t0 };
}
