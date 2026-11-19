// ---------------------------------------------------------------- cyber-physical coincidences (3.7.0)
// Three signals per country over the last 72 hours, each against its own baseline, from data the collector already
// holds:
//   outage    IODA internet-outage events at warning or critical level (BGP, active probing, telescope): the longest
//             event's hours in the window and the number of distinct signals that saw one
//   conflict  GDELT material-conflict events in the last 24 hours against the country's daily mean and spread over
//             the 30 days before (z score)
//   cyber     collected entries naming the country beside a threat entity (actor, extortion group, malware, tool) in
//             72 hours, by distinct publishers, against the country's daily average since the graph began
// A country where two or more signals are elevated at once is a coincidence: the three are shown side by side for an
// analyst to read, never added into a cause. A state-attributed actor named in the window is listed with the
// attributed country (the attacker side), apart from the country it was named beside (the target side).
export const CYPHYS = { HOURS: 72, OUTAGE_MIN_H: 1, CONFLICT_Z: 2, CONFLICT_MIN: 10, CYBER_MIN_P: 3, CYBER_RATIO: 2 };

export function conflictZ(last24, mu, sd) {
  if (last24 == null || mu == null) return null;
  const s = Math.max(Number(sd) || 0, Math.sqrt(Math.max(Number(mu), 1)));
  return Math.round(((Number(last24) - Number(mu)) / s) * 10) / 10;
}
export function flagsOf(r) {
  const outage = r.outage_hours >= CYPHYS.OUTAGE_MIN_H;
  const conflict = r.conflict_z != null && r.conflict_z >= CYPHYS.CONFLICT_Z && r.conflict_24h >= CYPHYS.CONFLICT_MIN;
  const cyber = r.cyber_p >= CYPHYS.CYBER_MIN_P && (r.cyber_base == null || r.cyber_per_day >= CYPHYS.CYBER_RATIO * Math.max(r.cyber_base, 0.34));
  return { outage, conflict, cyber, elevated: [outage, conflict, cyber].filter(Boolean).length };
}

export async function jobCyphys() {
  const t0 = Date.now(), H = CYPHYS.HOURS;
  const [out, conf, cyb, base, att] = await sqlTx([
    [`SELECT cc, max(name) AS name, count(*)::int AS events, count(DISTINCT split_part(entity, '/', 3))::int AS signals, round(max(EXTRACT(epoch FROM (least(coalesce(end_at, now()), now()) - greatest(start_at, now() - make_interval(hours => $1)))) / 3600)::numeric, 1)::real AS hours,
        max(level) FILTER (WHERE level = 'critical') AS critical, max(start_at) AS last_start
      FROM ti.disruption WHERE source = 'ioda' AND level IN ('warning', 'critical') AND coalesce(end_at, now()) > now() - make_interval(hours => $1) AND cc IS NOT NULL GROUP BY 1`, [H]],
    [`WITH d AS (SELECT iso2, date_trunc('day', slot) AS dd, sum(m)::real AS m FROM ti.gdelt_country WHERE slot > now() - interval '31 days' AND slot <= now() - interval '24 hours' GROUP BY 1, 2)
      SELECT d.iso2 AS cc, avg(d.m)::real AS mu, stddev_samp(d.m)::real AS sd, count(*)::int AS days, (SELECT sum(g.m)::real FROM ti.gdelt_country g WHERE g.iso2 = d.iso2 AND g.slot > now() - interval '24 hours') AS last24
      FROM d GROUP BY 1`],
    [`SELECT substr(c.eid, 9) AS cc, count(DISTINCT c.link)::int AS n, count(DISTINCT c.host)::int AS p,
        to_jsonb((array_agg(DISTINCT e.id || '|' || e.n || '|' || e.t))[1:12]) AS ents
      FROM ti.mention c JOIN ti.mention t ON t.link = c.link AND t.eid NOT LIKE 'country:%' AND t.eid NOT LIKE 'cve:%' JOIN ti.entity e ON e.id = t.eid AND e.t IN ('actor', 'extortion', 'malware', 'tool')
      WHERE c.eid LIKE 'country:%' AND c.published > now() - make_interval(hours => $1) GROUP BY 1`, [H]],
    [`SELECT substr(c.eid, 9) AS cc, count(DISTINCT c.link)::real / greatest(1, EXTRACT(epoch FROM (now() - make_interval(hours => $1) - min(c.published))) / 86400)::real AS per_day
      FROM ti.mention c JOIN ti.mention t ON t.link = c.link JOIN ti.entity e ON e.id = t.eid AND e.t IN ('actor', 'extortion', 'malware', 'tool')
      WHERE c.eid LIKE 'country:%' AND c.published <= now() - make_interval(hours => $1) AND c.published > now() - interval '45 days' GROUP BY 1`, [H]],
    // State-attributed actors named in the window, by the country ATT&CK or MISP attributes them to.
    [`SELECT substr(r.b, 9) AS cc, count(DISTINCT m.link)::int AS n, to_jsonb((array_agg(DISTINCT e.id || '|' || e.n))[1:10]) AS actors
      FROM ti.mention m JOIN ti.erel r ON r.a = m.eid AND r.rel = 'attributed-to' AND r.b LIKE 'country:%' JOIN ti.entity e ON e.id = m.eid
      WHERE m.published > now() - make_interval(hours => $1) GROUP BY 1`, [H]],
  ]);
  const by = new Map();
  const row = (cc) => by.get(cc) || by.set(cc, { cc, name: null, outage_hours: 0, outage_events: 0, outage_signals: 0, outage_critical: false, conflict_24h: null, conflict_mu: null, conflict_z: null,
    cyber_n: 0, cyber_p: 0, cyber_per_day: 0, cyber_base: null, entities: [], attributed_actors: [], attributed_n: 0 }).get(cc);
  for (const o of out) { const r = row(o.cc); Object.assign(r, { name: o.name, outage_hours: Number(o.hours) || 0, outage_events: o.events, outage_signals: o.signals, outage_critical: !!o.critical, outage_last: o.last_start }); }
  for (const c of conf) { if (!by.has(c.cc) && !(c.last24 > 0)) continue; const r = row(c.cc); Object.assign(r, { conflict_24h: c.last24 || 0, conflict_mu: c.mu, conflict_z: c.days >= 7 ? conflictZ(c.last24 || 0, c.mu, c.sd) : null }); }
  for (const c of cyb) { const r = row(c.cc); Object.assign(r, { cyber_n: c.n, cyber_p: c.p, cyber_per_day: Math.round((c.n / (H / 24)) * 100) / 100, entities: (c.ents || []).map((s) => { const [id, n, t] = String(s).split('|'); return { id, n, t }; }) }); }
  for (const b of base) if (by.has(b.cc)) by.get(b.cc).cyber_base = Math.round(b.per_day * 100) / 100;
  for (const a of att) { const r = row(a.cc); r.attributed_n = a.n; r.attributed_actors = (a.actors || []).map((s) => { const [id, n] = String(s).split('|'); return { id, n }; }); }
  const names = new Map(); for (const [cc, ns] of CA_NAMES) names.set(cc, ns[0]);
  const rows = [...by.values()].map((r) => ({ ...r, name: names.get(r.cc) || r.name || r.cc, ...flagsOf(r) }))
    .filter((r) => r.elevated > 0 || r.attributed_n > 0)
    .sort((a, b) => b.elevated - a.elevated || (b.conflict_z || 0) - (a.conflict_z || 0) || b.cyber_p - a.cyber_p);
  const coincidences = rows.filter((r) => r.elevated >= 2);
  await sql(`INSERT INTO ti.kv (k, v, at) VALUES ('cyphys:latest', $1::jsonb, now()) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, at = now()`, [{ at: new Date().toISOString(), coincidences }]);
  const doc = {
    source: 'KTI cyber-physical coincidences: IODA outages, GDELT material conflict and the entity graph', generated: new Date().toISOString(), served_from: 'store', hours: H,
    thresholds: { ...CYPHYS },
    method: `Per country over ${H} hours: IODA outage events at warning or critical level (hours, distinct signals); GDELT material-conflict events in the last 24 hours against the country's 30-day daily mean and spread (z of ${CYPHYS.CONFLICT_Z} or more with at least ${CYPHYS.CONFLICT_MIN} events); and collected entries naming the country beside a threat entity, from ${CYPHYS.CYBER_MIN_P} or more publishers at ${CYPHYS.CYBER_RATIO} times the country's daily average or more. Two elevated signals at once make a coincidence. The signals sit side by side; none is evidence that another caused it. State-attributed actors named in the window are listed under the country they are attributed to.`,
    countries: rows.length, coincidences: coincidences.length, count: rows.length, rows: rows.map((r) => ({ kind: 'country', ...r })),
  };
  return { countries: rows.length, coincidences: coincidences.length, published: await putDoc('cyphys', doc), ms: Date.now() - t0 };
}
