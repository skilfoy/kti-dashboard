/* Track record (3.6.0): the platform's measured accuracy in one card at the top of Method. Machine measurements come
   from the collector's scorecard document (live_scorecard: KEV foresight, pre-KEV surge hits, the KEV watchlist's
   forward test, triage agreement, source and collector health, each kept as a daily series); the analyst record comes
   from the authored datasets through the page's own calculations (forecast_record, lead_use, verification_summary). */
(() => {
  const { h } = TI;
  const pct = (x) => (x == null || x === '' ? '—' : `${Math.round(+x * 10) / 10}%`);
  const share = (x) => (x == null || x === '' ? '—' : `${Math.round(+x * 1000) / 10}%`);
  const tile = (label, value, sub) => h('div', { class: 'ti-tile' }, h('div', { class: 'ti-tile-label', text: label }), h('div', { class: 'ti-big', text: value }), h('div', { class: 'ti-tile-sub', text: sub }));
  const LABEL = { kev_foresight_share: 'KEV additions named first (%)', kev_foresight_median_lead_days: 'Median days named before KEV', cve_surge_hit_share: 'Surge alerts later in KEV (%)',
    kev_watchlist_share: 'Watchlist CVEs later in KEV (%)', triage_vector_accuracy: 'Triage vector accuracy', triage_theater_accuracy: 'Triage theater accuracy',
    sources_answering_share: 'Feeds answering (%)', collector_ok_share: 'Collector runs succeeding (%)' };
  function method(sec) {
    const box = sec.querySelector('#track-tiles'), tb = sec.querySelector('#tbl-track');
    if (!box || !tb) return;
    if (!TI.tableState(tb, ['live_scorecard'])) return;
    const rows = TI.rows('live_scorecard') || [], m = rows.find((r) => r.kind === 'meta') || {};
    const kf = TI.obj(m.kev_foresight), sh = TI.obj(m.cve_surge_hits), kw = TI.obj(m.kev_watchlist), te = TI.obj(m.triage_eval), so = TI.obj(m.sources), co = TI.obj(m.collector);
    const fr = TI.ready('forecast_record') ? (TI.rows('forecast_record')[0] || {}) : {}, lu = TI.ready('lead_use') ? (TI.rows('lead_use')[0] || {}) : {};
    const vs = TI.ready('verification_summary') ? (TI.rows('verification_summary')[0] || {}) : {};
    TI.clear(box);
    box.append(
      tile('KEV foresight', kf.kev_added ? `${kf.named_first} of ${kf.kev_added}` : 'none yet', kf.kev_added ? `KEV additions the collection named on an earlier day; median ${kf.median_lead_days ?? '—'} days ahead` : `no KEV addition since ${String(m.collecting_since || '').slice(0, 10)}`),
      tile('Pre-KEV surge alerts', sh.mature ? `${sh.listed_after} of ${sh.mature}` : `${sh.alerts || 0} open`, sh.mature ? 'alerts 30 days or older whose CVE KEV then listed' : `scored once 30 days old; ${sh.listed_after_any_age || 0} already listed`),
      tile('KEV watchlist', kw.mature ? `${kw.mature_listed} of ${kw.mature}` : `${kw.tracked || 0} tracked`, kw.mature ? 'ranked CVEs 30 days or older that KEV then listed' : `forward test since ${String(kw.since || '').slice(0, 10)}; ${kw.listed || 0} listed so far`),
      tile('Triage agreement', te.vector_accuracy != null ? `${share(te.vector_accuracy)} / ${share(te.theater_accuracy)}` : '—', te.items ? `vector / theater accuracy on ${te.items} analyst-labelled titles; ${share(te.vector_false_positive_rate)} vector false positives` : 'evaluation pending'),
      tile('Forecasts scored', fr.scored != null ? String(fr.scored) : '—', fr.brier_mean != null ? `mean Brier ${fr.brier_mean} (a standing 50% scores 0.25)` : 'no horizon has passed yet'),
      tile('Lead precision', lu.opened ? share(lu.precision) : '—', lu.opened ? `${lu.used + lu.duplicate} of ${lu.opened} opened leads used or already held` : 'no lead opened yet'),
      tile('Citations verified', vs.supported_share != null ? share(vs.supported_share) : '—', vs.judged != null ? `${vs.supported} of ${vs.judged} judged pages carry the claim` : 'not fetched yet'),
      tile('Collection health', `${pct(so.share)} feeds`, `${so.answering || 0} of ${so.active || 0} feeds answering; ${pct(co.share)} of ${co.runs_7d || 0} collector runs ok in 7 days`),
    );
    // The series: latest value, and the values 7 and 30 days earlier, per metric.
    const series = rows.filter((r) => r.kind === 'series');
    const by = new Map();
    for (const r of series) { if (!by.has(r.metric)) by.set(r.metric, []); by.get(r.metric).push(r); }
    const at = (list, daysAgo) => { const d = new Date(Date.now() - daysAgo * 864e5).toISOString().slice(0, 10); const x = list.filter((r) => r.day <= d).pop(); return x ? x.value : null; };
    const out = [...by.entries()].map(([metric, list]) => {
      const last = list[list.length - 1];
      return { metric, label: LABEL[metric] || metric, value: last.value, n: last.n, d7: at(list, 7), d30: at(list, 30), since: list[0].day, days: list.length };
    });
    TI.table(tb, out, [
      { field: 'label', label: 'Measure', cls: 'ti-wrap' },
      { field: 'value', label: 'Now', num: true },
      { field: 'n', label: 'n', num: true },
      { field: 'd7', label: '7 days ago', num: true },
      { field: 'd30', label: '30 days ago', num: true },
      { field: 'since', label: 'Kept since', fmt: 'date', hideSm: true },
    ], { sort: 'label', dir: 'asc', empty: 'The first measurement is taken in the next hour.' });
  }
  TI.track = { method };
})();
