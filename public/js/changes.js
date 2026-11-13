/* The change log and the forecast record: what the latest run changed (Brief), when a theater's level and trend took
   effect (Theaters), and the scored horizons, open horizons and full log (Method). Reads the history and outcomes
   datasets through the run_changes, run_summary, theater_history and forecast_record calculations. */
(() => {
  const { h, v } = TI;
  const COLS = [
    { field: 'date', label: 'Date', fmt: 'date', cls: 'ti-nowrap' },
    { field: 'run_id', label: 'Run', cls: 'ti-nowrap ti-mono', hideSm: true },
    { field: 'kind', label: 'Kind', hideSm: true },
    { field: 'name', label: 'Subject', cls: 'ti-wrap' },
    { field: 'what', label: 'Changed' },
    { field: 'from', label: 'From', cls: 'ti-wrap' },
    { field: 'to', label: 'To', cls: 'ti-wrap' },
  ];

  function brief(sec) {
    const box = sec.querySelector('#since-list');
    if (!box) return;
    const ids = ['run_changes', 'run_summary'];
    if (TI.failed(...ids)) { TI.failLine(box); return; }
    if (!TI.ready(...ids)) return;
    const sum = TI.rows('run_summary')[0] || {};
    const lvl = sec.querySelector('#since-level');
    if (lvl) {
      TI.clear(lvl);
      lvl.append(sum.last_level_change
        ? h('span', {}, 'Last ThreatCon level change: ', v('span', 'run_summary', 'last_level_change', null, sum.last_level_change), '.')
        : h('span', {}, 'No ThreatCon level has changed since the record began on ', v('span', 'run_summary', 'record_from', null, sum.record_from || '—'), '.'));
      for (const m of lvl.querySelectorAll('[data-source]')) m.setAttribute('data-row', '0');
    }
    const rows = TI.rows('run_changes');
    const latest = rows.filter((r) => r.latest === 'Yes');
    const cut = sum.at ? new Date(Date.parse(sum.at) - 14 * 864e5).toISOString().slice(0, 10) : '';
    const recent = rows.filter((r) => r.latest !== 'Yes' && r.date >= cut);
    TI.clear(box);
    const list = (title, set) => {
      box.append(h('h3', { class: 'ti-h3', text: title }));
      const ul = h('ul', { class: 'ti-changes' });
      for (const r of set) {
        const w = { event_id: r.event_id };
        ul.append(h('li', {},
          v('span', 'run_changes', 'date', w, r.date, 'ti-cap ti-muted ti-nowrap'), ' ',
          v('span', 'run_changes', 'kind', w, r.kind, 'ti-badge'), ' ',
          v('strong', 'run_changes', 'name', w, r.name), ': ', v('span', 'run_changes', 'what', w, r.what), ' ',
          v('span', 'run_changes', 'from', w, r.from, 'ti-muted'), ' to ', v('span', 'run_changes', 'to', w, r.to)));
      }
      box.append(ul);
    };
    if (latest.length) list('In this run', latest);
    else box.append(h('p', { class: 'ti-card-note', text: 'No level, trend, judgment or warning indicator moved in this run.' }));
    if (recent.length) list('Earlier in the last 14 days', recent.slice(0, 12));
  }

  function theaterRow(t) {
    if (!TI.ready('theater_history')) return null;
    const r = TI.rows('theater_history').find((x) => x.theater_id === t.theater_id);
    if (!r) return null;
    return [h('dt', { text: 'Level history' }), v('dd', 'theater_history', 'summary', { theater_id: t.theater_id }, r.summary)];
  }

  function method(sec) {
    const line = sec.querySelector('#forecast-line');
    if (line && TI.ready('forecast_record')) {
      const f = TI.rows('forecast_record')[0] || {};
      const m = (field, text) => { const e = v('span', 'forecast_record', field, null, text); e.setAttribute('data-row', '0'); return e; };
      TI.clear(line);
      line.append(m('resolved', TI.f.int(f.resolved)), ' horizons scored: ', m('held', TI.f.int(f.held)), ' held, ', m('not_held', TI.f.int(f.not_held)), ' did not hold, ',
        m('indeterminate', TI.f.int(f.indeterminate)), ' indeterminate. Mean Brier score ', m('brier_mean', f.brier_mean == null ? '—' : d3.format('.3f')(f.brier_mean)),
        ' over ', m('scored', TI.f.int(f.scored)), ' scored outcomes. ', m('open', TI.f.int(f.open)), ' judgments carry an open horizon, the next on ', m('next_horizon', f.next_horizon || '—'), '.');
    }
    const to = sec.querySelector('#tbl-outcomes');
    if (to && TI.tableState(to, ['outcomes'])) {
      TI.table(to, TI.rows('outcomes'), [
        { field: 'outcome_id', label: 'Record', cls: 'ti-nowrap ti-mono' },
        { field: 'judgment_id', label: 'Judgment', cls: 'ti-nowrap' },
        { field: 'statement', label: 'Judged statement', cls: 'ti-wrap' },
        { field: 'likelihood', label: 'Likelihood' },
        { field: 'probability', label: 'Range', hideSm: true },
        { field: 'horizon', label: 'Horizon', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'outcome', label: 'Outcome' },
        { field: 'brier', label: 'Brier', num: true, get: (r) => (r.brier == null ? '' : d3.format('.3f')(r.brier)) },
        { field: 'basis', label: 'Basis', cls: 'ti-wrap', hideSm: true },
        { field: 'item_ids', label: 'Items', cls: 'ti-mono', hideSm: true },
      ], { sort: 'horizon', dir: 'desc', empty: 'No horizon has passed yet.' });
    }
    const th = sec.querySelector('#tbl-horizons');
    if (th && TI.tableState(th, ['judgments'])) {
      TI.table(th, TI.rows('judgments'), [
        { field: 'judgment_id', label: 'Judgment', cls: 'ti-nowrap' },
        { field: 'title', label: 'Title', cls: 'ti-wrap' },
        { field: 'likelihood', label: 'Likelihood' },
        { field: 'probability', label: 'Range', hideSm: true },
        { field: 'opened', label: 'Opened', fmt: 'date', cls: 'ti-nowrap', hideSm: true },
        { field: 'horizon', label: 'Scored by', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'status', label: 'Status', hideSm: true },
      ], { filter: (r) => r.status !== 'Retired' && r.horizon, sort: 'horizon', dir: 'asc' });
    }
    const tl = sec.querySelector('#tbl-history');
    if (tl && TI.tableState(tl, ['run_changes'])) {
      TI.table(tl, TI.rows('run_changes'), COLS, { sort: 'date', dir: 'desc', empty: 'No tracked value has changed since the record began.' });
    }
    TI.fillMarks(sec);
  }

  TI.changes = { brief, theaterRow, method };
})();
