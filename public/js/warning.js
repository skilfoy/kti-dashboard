/* Measured indications and warning on the Theaters page: each theater's tempo from independent live collection, and
   the warning indicators that a live measurement can show moving, evaluated against analyst-set rules, with proposed
   state changes for the analyst to apply or reject (Suryavanshi ch4: consistency and momentum; Arici 3.5.2: only
   independent collection corroborates). A proposal changes nothing on its own. */
(() => {
  const { h, v } = TI;
  const r3 = (x) => Math.round(x * 1000) / 1000;
  const DAY = 864e5;
  const LANES_RULES = { 'israel-palestine': ['T-LEV'], 'usa-iran': ['T-HRM'] };  // as context.js attaches pairs

  // ---- Per-feed measurements (one calculation per feed, so one feed down leaves the others measured) ----
  dash.calc('warn_lanes', {
    title: 'Lanes temperature change by theater',
    description: 'For each theater, the Lanes pairs attached to it (both countries in the theater, or Israel-Palestine to the Levant and USA-Iran to Hormuz): the highest 7-day mean temperature, and the largest week-on-week rise among pairs at or above the 0.3 amber line.',
    inputs: ['theaters', 'live_lanes'],
    fn: (theaters, lanes) => theaters.map((t) => {
      const ccs = String(t.countries || '').split(',').filter(Boolean);
      const ps = lanes.filter((r) => (r.a2 && r.b2 && ccs.includes(r.a2) && ccs.includes(r.b2)) || (LANES_RULES[r.conflict] || []).includes(t.theater_id));
      const hot = ps.filter((r) => +r.t7 >= 0.3 && r.delta7 != null);
      const top = hot.slice().sort((a, b) => b.delta7 - a.delta7)[0];
      return { theater_id: t.theater_id, pairs: ps.map((r) => r.conflict).join(', '), t7_max: ps.length ? r3(Math.max(...ps.map((r) => +r.t7 || 0))) : null,
        delta7_max: top ? r3(top.delta7) : null, delta7_pair: top ? top.conflict : null, as_of: ps.length ? ps.map((r) => r.date).sort().pop() : null };
    }),
  });

  dash.calc('warn_outages', {
    title: 'IODA outages by country, 72 hours',
    description: 'For each country in the IODA outage list: outage events starting in the 72 hours to the newest event, those IODA rates warning or critical, those it rates critical, and events in the 7 days held. IODA rates an event against its own baseline for that country\'s signals, so its level is the momentum measure.',
    inputs: ['live_outages'],
    fn: (rows) => {
      const ev = rows.filter((r) => r.kind === 'outage' && r.start_at);
      const ref = Math.max(...ev.map((r) => Date.parse(r.start_at)).filter(isFinite), 0);
      const by = new Map();
      for (const r of ev) {
        const t = Date.parse(r.start_at);
        const a = by.get(r.cc) || { cc: r.cc, name: r.name, e72: 0, a72: 0, c72: 0, e7d: 0, ongoing: 0 };
        if (ref - t <= 7 * DAY) a.e7d += 1;
        if (ref - t <= 3 * DAY) { a.e72 += 1; if (r.level && r.level !== 'normal') a.a72 += 1; if (r.level === 'critical') a.c72 += 1; }
        if (r.ongoing === true || r.ongoing === 'true') a.ongoing += 1;
        by.set(r.cc, a);
      }
      return [...by.values()].map((a) => ({ cc: a.cc, name: a.name, events_72h: a.e72, alerts_72h: a.a72, critical_72h: a.c72, events_7d: a.e7d, ongoing: a.ongoing,
        as_of: ref ? new Date(ref).toISOString().slice(0, 16) + 'Z' : null }));
    },
  });

  dash.calc('warn_ofac', {
    title: 'OFAC actions by theater, 14 days',
    description: 'For each theater, the OFAC Recent Actions tagged to it in the 14 days to the newest listed action: actions, actions adding SDN entries, actions removing entries, actions issuing general licenses, and actions in the 14 days before that; span_days is how far back the listing reaches, and the prior window counts only when it reaches 28 days.',
    inputs: ['theaters', 'live_ofac'],
    fn: (theaters, rows) => {
      const days = rows.map((r) => Date.parse(String(r.date).slice(0, 10) + 'T00:00:00Z')).filter(isFinite);
      const ref = Math.max(...days, 0);
      const span = days.length ? Math.round((ref - Math.min(...days)) / DAY) : 0;
      return theaters.map((t) => {
        const tagged = rows.filter((r) => String(r.theaters || '').split(',').map((s) => s.trim()).includes(t.theater_id));
        const age = (r) => (ref - Date.parse(String(r.date).slice(0, 10) + 'T00:00:00Z')) / DAY;
        const cur = tagged.filter((r) => age(r) <= 14), prev = tagged.filter((r) => age(r) > 14 && age(r) <= 28);
        return { theater_id: t.theater_id, actions_14d: cur.length, designations_14d: cur.filter((r) => +r.added > 0 || /Designation/.test(r.actions || '')).length,
          removals_14d: cur.filter((r) => +r.removed > 0 || /Removal|Delisting/.test(r.actions || '')).length, gl_14d: cur.filter((r) => /General license/i.test(r.actions || '')).length,
          actions_prior_14d: prev.length, as_of: ref ? new Date(ref).toISOString().slice(0, 10) : null, span_days: span };
      });
    },
  });

  // ---- Evaluation: page code over whichever feeds answered ----
  const FAM = ['Press events (GDELT)', 'Satellite thermal (FIRMS)', 'Internet measurement (IODA)', 'Maritime notices (NGA, MARAD, UKMTO)', 'Sanctions actions (OFAC)'];
  const kind = (id, k) => (TI.rows(id) || []).filter((r) => r.kind === k);
  function metrics() {
    const m = { gdelt: null, lanes: null, fires: null, outages: null, maritime: null, ofac: null };
    if (TI.ready('live_gdelt_theaters')) m.gdelt = TI.index(TI.rows('live_gdelt_theaters'), 'theater_id');
    if (TI.ready('warn_lanes')) m.lanes = TI.index(TI.rows('warn_lanes'), 'theater_id');
    if (TI.ready('live_fires')) m.fires = TI.index(kind('live_fires', 'aoi'), 'id');
    if (TI.ready('warn_outages')) m.outages = TI.index(TI.rows('warn_outages'), 'cc');
    if (TI.ready('live_maritime')) {
      // Press reports (PRESS) do not stand in for the official notices these measures count.
      const ok = kind('live_maritime', 'source').some((s) => s.id !== 'PRESS' && (s.ok === true || s.ok === 'true'));
      m.maritime = ok ? TI.index(kind('live_maritime', 'theater'), 'theater_id') : null;
      m.maritimeDown = !ok;
    }
    if (TI.ready('warn_ofac')) m.ofac = TI.index(TI.rows('warn_ofac'), 'theater_id');
    return m;
  }
  const theaterCcs = () => new Map((TI.rows('theaters') || []).map((t) => [t.theater_id, String(t.countries || '').split(',').filter(Boolean)]));

  // One measurement: { value, ok, text, momentum, source }
  function measure(m, metric, theaterId, scope, ccsOf) {
    const none = (why) => ({ value: null, ok: false, text: why });
    const ccs = scope ? String(scope).split(',').map((s) => s.trim()) : ccsOf.get(theaterId) || [];
    switch (metric) {
      case 'gdelt_ratio': {
        if (!m.gdelt) return none('GDELT feed unavailable');
        const g = m.gdelt.get(theaterId);
        if (!g || g.ratio == null) return none('No GDELT baseline yet');
        const val = g.events >= 5 ? g.ratio : 0;
        return { value: val, ok: true, momentum: g.ratio, source: 'live_gdelt_theaters', text: `${TI.f.int(g.events)} conflict events in 24 hours, ${TI.f.dec2(g.ratio)} times the 48-hour rate${g.events < 5 ? ' (under 5 events, not counted)' : ''}` };
      }
      case 'lanes_delta7': {
        if (!m.lanes) return none('Lanes feed unavailable');
        const l = m.lanes.get(theaterId);
        if (!l || !l.pairs) return none('No Lanes pair for this theater');
        if (l.delta7_max == null) return { value: 0, ok: true, momentum: null, source: 'warn_lanes', text: `Lanes pairs ${l.pairs} below the 0.3 amber line (7-day mean ${TI.f.dec2(l.t7_max)})` };
        return { value: l.delta7_max, ok: true, momentum: l.delta7_max, source: 'warn_lanes', text: `Lanes ${l.delta7_pair} 7-day mean moved ${l.delta7_max >= 0 ? '+' : ''}${TI.f.dec2(l.delta7_max)} week on week (data to ${l.as_of})` };
      }
      case 'fires_ratio': case 'fires_novel': {
        if (!m.fires) return none('FIRMS feed unavailable');
        const a = m.fires.get(theaterId);
        if (!a) return none('No FIRMS area for this theater');
        if (a.ok === false || a.ok === 'false') return none('FIRMS area not read at the last run');
        if (metric === 'fires_ratio') return a.ratio == null ? none(`No FIRMS baseline yet (${TI.f.int(a.baseline_days || 0)} days held)`) : { value: +a.ratio, ok: true, momentum: +a.ratio, source: 'live_fires', text: `${TI.f.int(a.yesterday)} detections yesterday, ${TI.f.dec2(a.ratio)} times the daily median` };
        return a.novelty_judged === true || a.novelty_judged === 'true' ? { value: +a.novel_cells || 0, ok: true, momentum: null, source: 'live_fires', text: `${TI.f.int(a.novel_cells)} new thermal-anomaly cells in 48 hours` } : none('FIRMS novelty not judged until 7 days are held');
      }
      case 'outages_72h': case 'outages_alert': {
        if (!m.outages) return none('IODA feed unavailable');
        let e = 0, al = 0, cr = 0;
        for (const c of ccs) { const o = m.outages.get(c); if (o) { e += o.events_72h; al += o.alerts_72h; cr += +o.critical_72h || 0; } }
        // IODA rates each event against its own baseline, so its critical level is the momentum test.
        return { value: metric === 'outages_72h' ? al : cr, ok: true, momentum: null, source: 'warn_outages',
          text: `${TI.f.int(e)} IODA outage events in 72 hours in ${ccs.join(', ')}: ${TI.f.int(al)} rated warning or critical, ${TI.f.int(cr)} critical` };
      }
      case 'maritime_incidents_30d': case 'maritime_hostile': case 'maritime_mines': case 'maritime_military': {
        if (!m.maritime) return none(m.maritimeDown ? 'No maritime source answered at the last run' : 'Maritime feed unavailable');
        const t = m.maritime.get(theaterId) || {};
        const f = { maritime_incidents_30d: 'incidents_30d', maritime_hostile: 'warn_hostile', maritime_mines: 'warn_mines', maritime_military: 'warn_military' }[metric];
        const label = { maritime_incidents_30d: 'ASAM incidents in 30 days', maritime_hostile: 'navigational warnings naming hostile activity', maritime_mines: 'navigational warnings naming mines', maritime_military: 'navigational warnings for military activity' }[metric];
        return { value: +t[f] || 0, ok: true, momentum: null, source: 'live_maritime', text: `${TI.f.int(+t[f] || 0)} ${label}` };
      }
      case 'ofac_designations_14d': case 'ofac_removals_14d': case 'ofac_gl_14d': {
        if (!m.ofac) return none('OFAC feed unavailable');
        const o = m.ofac.get(theaterId) || {};
        const f = metric.replace('ofac_', '');
        const label = { designations_14d: 'actions adding SDN entries', removals_14d: 'actions removing SDN entries', gl_14d: 'actions issuing general licenses' }[f];
        return { value: +o[f] || 0, ok: true, momentum: o.actions_prior_14d ? (+o.actions_14d || 0) / o.actions_prior_14d : null, source: 'warn_ofac', text: `${TI.f.int(+o[f] || 0)} OFAC ${label} in 14 days to ${o.as_of || '—'}` };
      }
      default: return none('Unknown metric');
    }
  }

  // Analyst-set rules over the measurements, rolled up per indicator with a proposed state.
  function evaluate() {
    if (!TI.ready('indicator_rules', 'theater_indicators', 'theaters')) return null;
    const m = metrics(), ccsOf = theaterCcs();
    const rules = TI.rows('indicator_rules').map((r) => {
      const x = measure(m, r.metric, r.theater_id, r.scope, ccsOf);
      const fired = x.ok && x.value != null && +x.value >= +r.threshold;
      return { ...r, value: x.value, measured: x.ok ? 'Yes' : 'No', result: !x.ok ? 'No data' : fired ? 'Above threshold' : 'Below threshold', reading: x.text, source: x.source || null,
        strength: x.ok && +r.threshold ? r3((+x.value || 0) / +r.threshold) : null, momentum: x.momentum == null ? null : r3(x.momentum) };
    });
    const now = Date.now();
    const byInd = new Map();
    for (const r of rules) { if (!byInd.has(r.ind_id)) byInd.set(r.ind_id, []); byInd.get(r.ind_id).push(r); }
    const tname = new Map((TI.rows('theaters') || []).map((t) => [t.theater_id, t.name]));
    const inds = TI.rows('theater_indicators').filter((i) => byInd.has(i.ind_id)).map((i) => {
      const rs = byInd.get(i.ind_id);
      const meas = rs.filter((r) => r.measured === 'Yes'), fired = rs.filter((r) => r.result === 'Above threshold');
      const fams = [...new Set(fired.map((r) => r.family))];
      const direct = fired.some((r) => r.kind === 'Direct');
      const days = i.last_seen ? Math.floor((now - Date.parse(String(i.last_seen).slice(0, 10) + 'T00:00:00Z')) / DAY) : null;
      const st = i.state;
      let proposal = 'No change', why = '';
      const observedBar = fams.length >= 2 || direct;
      if (!meas.length) { proposal = 'Cannot measure now'; why = 'No rule for this indicator has a live reading.'; }
      else if (st === 'Not observed' && fired.length) { proposal = observedBar ? 'Observed' : 'Emerging'; why = observedBar ? (direct ? 'A direct measurement is above its threshold.' : `${fams.length} independent collection families agree.`) : 'One collection family is above its threshold; a second independent family, or reporting, would make it Observed.'; }
      else if (st === 'Emerging' && observedBar) { proposal = 'Observed'; why = direct ? 'A direct measurement is above its threshold.' : `${fams.length} independent collection families agree.`; }
      else if (fired.length) { proposal = 'No change'; why = 'Measurements support the current state.'; }
      else if (st !== 'Not observed' && days != null && days > (st === 'Confirmed' ? 30 : st === 'Observed' ? 21 : 14)) { proposal = 'Review'; why = `No measured signal and last seen ${days} days ago; the analyst decides whether the state still holds.`; }
      else { why = 'No measured signal; the current state rests on reporting.'; }
      return { ind_id: i.ind_id, theater_id: i.theater_id, theater: tname.get(i.theater_id) || i.theater_id, indicator: i.indicator, direction: i.direction, state: st, last_seen: i.last_seen || null,
        rules: rs.length, measured: meas.length, fired: fired.length, families: fams.length, family_list: fams.join('; '),
        strength: fired.length ? Math.max(...fired.map((r) => r.strength || 0)) : null, proposal, why,
        basis: fired.map((r) => `${r.reading} (${r.kind.toLowerCase()}, threshold ${r.threshold})`).join('; ') };
    });
    // Theater tempo: one headline per collection family, at the default thresholds the rules use.
    const tempo = (TI.rows('theaters') || []).map((t) => {
      const fam = [
        ['press', 'Press events (GDELT)', [measure(m, 'gdelt_ratio', t.theater_id, null, ccsOf), 1.5], [measure(m, 'lanes_delta7', t.theater_id, null, ccsOf), 0.05]],
        ['sat', 'Satellite thermal (FIRMS)', [measure(m, 'fires_ratio', t.theater_id, null, ccsOf), 1.5], [measure(m, 'fires_novel', t.theater_id, null, ccsOf), 3]],
        ['net', 'Internet measurement (IODA)', [measure(m, 'outages_alert', t.theater_id, null, ccsOf), 1]],
        ['sea', 'Maritime notices (NGA, MARAD, UKMTO)', [measure(m, 'maritime_hostile', t.theater_id, null, ccsOf), 1], [measure(m, 'maritime_mines', t.theater_id, null, ccsOf), 1], [measure(m, 'maritime_military', t.theater_id, null, ccsOf), 1]],
        ['sanc', 'Sanctions actions (OFAC)', [measure(m, 'ofac_designations_14d', t.theater_id, null, ccsOf), 1]],
      ];
      // OFAC sanctions a theater's programs most weeks, so its family rises only when actions outrun the prior 14 days.
      const o = m.ofac ? m.ofac.get(t.theater_id) : null;
      if (o) fam[4].push(+o.span_days >= 28
        ? [{ ok: true, value: (+o.actions_14d >= 2 && +o.actions_14d > +o.actions_prior_14d) ? 1 : 0, text: `${TI.f.int(o.actions_14d)} OFAC actions in 14 days against ${TI.f.int(o.actions_prior_14d)} in the 14 before` }, 1]
        : [{ ok: false, value: null, text: `OFAC listing reaches back ${TI.f.int(o.span_days)} days; momentum needs 28` }, 1]);
      const row = { theater_id: t.theater_id, name: t.name, threatcon: t.threatcon };
      let rising = 0, measured = 0;
      for (const [k, , ...ms] of fam) {
        let use = ms;
        if (k === 'sanc') use = ms.slice(1);  // the momentum test above replaces the designation count
        const ok = use.filter(([x]) => x.ok);
        const up = ok.filter(([x, thr]) => x.value != null && +x.value >= thr);
        if (ok.length) measured += 1;
        if (up.length) rising += 1;
        // Maritime notices are counts with no baseline, so they show as active.
        row[k] = !ok.length ? 'No data' : up.length ? (k === 'sea' ? 'Active' : 'Rising') : 'Quiet';
        row[k + '_text'] = (up.length ? up : ok.length ? ok : use).map(([x]) => x.text).join('; ');
      }
      row.rising = rising; row.measured = measured; row.consistency = `${rising} of ${measured}`;
      return row;
    });
    return { rules, inds, tempo };
  }
  TI.warnEval = evaluate;

  const STATE_CLS = { Rising: 'ti-yes', Active: 'ti-yes', Quiet: 'ti-muted', 'No data': 'ti-muted' };
  TI.warn = {
    draw(sec) {
      const box = sec.querySelector('#warn-card');
      if (!box) return;
      const tt = sec.querySelector('#tbl-warn-tempo'), tp = sec.querySelector('#tbl-warn-prop'), tr = sec.querySelector('#tbl-warn-rules');
      if (!TI.tableState(tt, ['theaters', 'indicator_rules', 'theater_indicators'])) return;
      const e = evaluate();
      if (!e) return;
      const cell = (k) => ({ field: k, label: { press: 'Press', sat: 'Satellite', net: 'Internet', sea: 'Maritime', sanc: 'Sanctions' }[k], attr: { class: (r) => STATE_CLS[r[k]] || '', title: (r) => r[k + '_text'] || '' } });
      TI.table(tt, e.tempo.slice().sort((a, b) => b.rising - a.rising || b.threatcon - a.threatcon || a.name.localeCompare(b.name)), [
        { field: 'name', label: 'Theater', cls: 'ti-wrap' },
        { field: 'threatcon', label: 'ThreatCon', num: true, fmt: 'int' },
        { field: 'consistency', label: 'Families signaling', get: (r) => r.consistency },
        cell('press'), cell('sat'), cell('net'), cell('sea'), cell('sanc'),
      ]);
      const sort = (r) => ({ Observed: 3, Emerging: 2, Review: 1 }[r.proposal] || 0);
      const pf = sec.querySelector('#warn-filter').value;
      TI.table(tp, e.inds.map((r) => ({ ...r, order: sort(r) })).sort((a, b) => b.order - a.order || b.families - a.families || a.ind_id.localeCompare(b.ind_id)), [
        { field: 'ind_id', label: 'ID', cls: 'ti-mono ti-nowrap' },
        { field: 'theater', label: 'Theater', hideSm: true },
        { field: 'indicator', label: 'Indicator', cls: 'ti-wrap' },
        { field: 'direction', label: 'Direction', hideSm: true },
        { field: 'state', label: 'Current state' },
        { field: 'proposal', label: 'Proposed', attr: { class: (r) => (r.proposal === 'Observed' || r.proposal === 'Emerging' ? 'ti-yes' : r.proposal === 'Review' ? '' : 'ti-muted') } },
        { field: 'measured', label: 'Rules read', num: true, fmt: 'int', get: (r) => r.measured, hideSm: true },
        { field: 'families', label: 'Families above', num: true, fmt: 'int' },
        { field: 'why', label: 'Why', cls: 'ti-wrap' },
        { field: 'basis', label: 'Measured basis', cls: 'ti-wrap', hideSm: true },
      ], { countEl: sec.querySelector('#warn-count'),
        filter: (r) => !pf || (pf === 'change' ? ['Observed', 'Emerging', 'Review'].includes(r.proposal) : r.proposal === pf) });
      const n = e.inds.filter((r) => r.proposal === 'Observed' || r.proposal === 'Emerging').length, rv = e.inds.filter((r) => r.proposal === 'Review').length;
      const read = e.rules.filter((r) => r.measured === 'Yes').length;
      const nt = sec.querySelector('#warn-note');
      TI.clear(nt).append(`${read} of ${e.rules.length} rules have a live reading now, covering ${new Set(e.rules.map((r) => r.ind_id)).size} of ${TI.rows('theater_indicators').length} indicators. `,
        h('strong', { text: `${n} proposed state change${n === 1 ? '' : 's'}` }), ` and ${rv} review${rv === 1 ? '' : 's'} wait for the analyst; the daily reassessment applies or rejects each in theater_indicators and cites the reading.`);
      TI.table(tr, e.rules, [
        { field: 'rule_id', label: 'Rule', cls: 'ti-mono ti-nowrap' },
        { field: 'metric', label: 'Metric', cls: 'ti-mono', hideSm: true },
        { field: 'reading', label: 'Live reading', cls: 'ti-wrap' },
        { field: 'threshold', label: 'Threshold', num: true },
        { field: 'result', label: 'Result', attr: { class: (r) => (r.result === 'Above threshold' ? 'ti-yes' : 'ti-muted') } },
        { field: 'family', label: 'Collection family', hideSm: true },
        { field: 'kind', label: 'Direct or proxy', hideSm: true },
        { field: 'rationale', label: 'Why this measures it', cls: 'ti-wrap', hideSm: true },
      ], { sort: 'result', dir: 'asc' });
    },
  };
  TI.root.addEventListener('input', (ev) => { if (ev.target.id === 'warn-filter') TI.draw('theaters'); });
})();
