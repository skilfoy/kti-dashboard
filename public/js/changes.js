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

  function week(sec) {
    const line = sec.querySelector('#week-line');
    if (!line || !TI.ready('week_review')) return;
    const w = TI.rows('week_review')[0] || {};
    const m = (field, text) => { const e = v('span', 'week_review', field, null, text); e.setAttribute('data-row', '0'); return e; };
    const int = TI.f.int, rng = sec.querySelector('#week-range');
    if (rng) rng.textContent = w.from ? `${w.from} to ${w.to}` : '';
    TI.clear(line);
    line.append(m('level_moves', int(w.level_moves)), ' ThreatCon level moves and ', m('trend_moves', int(w.trend_moves)), ' trend moves; ', m('judgment_changes', int(w.judgment_changes)), ' changes to a judgment, ',
      m('indicator_changes', int(w.indicator_changes)), ' to a warning indicator and ', m('vector_changes', int(w.vector_changes)), ' to a vector. ', m('items_added', int(w.items_added)), ' evidence items added',
      w.theaters ? ', most in ' : '', w.theaters ? m('theaters', w.theaters) : '', '. ', m('outcomes', int(w.outcomes)), ' forecast outcomes recorded. ',
      w.leads_opened ? h('span', {}, 'The analyst run opened ', m('leads_opened', int(w.leads_opened)), ' machine leads and used ', m('leads_used', int(w.leads_used)), ' as evidence (', m('lead_precision', d3.format('.0%')(w.lead_precision)), ' used or already held).') : 'No machine leads were recorded in the period.');
  }
  function brief(sec) {
    week(sec);
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
    const ct = sec.querySelector('#tbl-corroboration');
    if (ct && TI.tableState(ct, ['judgment_corroboration'])) {
      TI.table(ct, TI.rows('judgment_corroboration'), [
        { field: 'judgment_id', label: 'Judgment', cls: 'ti-nowrap' },
        { field: 'title', label: 'Title', cls: 'ti-wrap', hideSm: true },
        { field: 'supporting', label: 'Supporting items', num: true, fmt: 'int' },
        { field: 'publishers', label: 'Publishers', num: true, fmt: 'int' },
        { field: 'categories', label: 'Categories', num: true, fmt: 'int', hideSm: true },
        { field: 'top_publisher', label: 'Most cited', get: (r) => (r.top_publisher ? `${r.top_publisher} (${d3.format('.0%')(r.top_share)})` : '') },
        { field: 'flag', label: 'Flag', attr: { 'data-status': (r) => (r.flag ? 'review' : 'ok') }, get: (r) => r.flag || 'independent' },
      ], { limit: 20, empty: 'No ranked judgments.' });
    }
    const al = sec.querySelector('#ach-line'), at = sec.querySelector('#tbl-ach');
    if (at && TI.tableState(at, ['ach_matrix'])) {
      const rows = TI.rows('ach_matrix'), alt = rows.filter((r) => r.hypothesis !== 'H1');
      const total = alt.reduce((s, r) => s + r.evidence, 0), rated = alt.reduce((s, r) => s + r.evidence - r.unrated, 0);
      if (al) al.textContent = `${TI.f.int(rated)} of ${TI.f.int(total)} evidence ratings against the stated alternatives are in. ` + (rated < total ? 'The daily run rates the evidence of the judgments it reviews; a hypothesis stands or falls only once its ratings are complete.' : 'Every alternative is fully rated.');
      TI.table(at, rows, [
        { field: 'judgment_id', label: 'Judgment', cls: 'ti-nowrap' },
        { field: 'hypothesis', label: 'H' },
        { field: 'text', label: 'Hypothesis', cls: 'ti-wrap' },
        { field: 'consistent', label: 'Consistent', num: true, fmt: 'int' },
        { field: 'inconsistent', label: 'Inconsistent', num: true, fmt: 'int' },
        { field: 'neutral', label: 'Not diagnostic', num: true, fmt: 'int', hideSm: true },
        { field: 'unrated', label: 'Unrated', num: true, fmt: 'int', hideSm: true },
        { field: 'standing', label: 'Standing', attr: { 'data-status': (r) => (r.standing === 'least inconsistent' ? 'ok' : r.standing === 'more inconsistent' ? 'review' : '') } },
      ], { limit: 60, empty: 'No ranked judgments.' });
    }
    const ll = sec.querySelector('#leads-line');
    if (ll && TI.ready('lead_use')) {
      const s = TI.rows('lead_use')[0] || {};
      const m = (field, text) => { const e = v('span', 'lead_use', field, null, text); e.setAttribute('data-row', '0'); return e; };
      const pct = (x) => (x == null ? '—' : d3.format('.0%')(x));
      TI.clear(ll);
      if (!s.opened) ll.append('No leads recorded yet. The record starts with the first analyst run after 15 November 2026.');
      else ll.append(m('opened', TI.f.int(s.opened)), ' leads opened since ', m('first', s.first), ': ', m('used', TI.f.int(s.used)), ' used, ', m('duplicate', TI.f.int(s.duplicate)), ' already held, ',
        m('rejected', TI.f.int(s.rejected)), ' rejected, ', m('wrong', TI.f.int(s.wrong)), ' wrong. Precision ', m('precision', pct(s.precision)), '; for relevance 3 leads ', m('top_precision', pct(s.top_precision)),
        ' over ', m('top_opened', TI.f.int(s.top_opened)), '.');
    }
    const lt = sec.querySelector('#tbl-leads');
    if (lt && TI.tableState(lt, ['leads'])) {
      TI.table(lt, TI.rows('leads'), [
        { field: 'date', label: 'Date', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'source', label: 'Tier' },
        { field: 'relevance', label: 'Rel.', num: true, get: (r) => (r.relevance == null ? '' : r.relevance) },
        { field: 'disposition', label: 'Result', attr: { 'data-status': (r) => (r.disposition === 'wrong' ? 'review' : r.disposition === 'used' ? 'ok' : '') } },
        { field: 'title', label: 'Lead', link: 'link', cls: 'ti-wrap', get: (r) => r.title || r.link },
        { field: 'item_ids', label: 'Items', hideSm: true },
        { field: 'reason', label: 'Reason', cls: 'ti-wrap', hideSm: true },
      ], { sort: 'date', dir: 'desc', limit: 200, empty: 'No leads recorded yet.' });
    }
    const vl = sec.querySelector('#verify-line');
    if (vl && TI.ready('verification_summary')) {
      const s = TI.rows('verification_summary')[0] || {};
      const m = (field, text) => v('span', 'verification_summary', field, { state: s.state }, text);
      TI.clear(vl);
      vl.append(m('supported', TI.f.int(s.supported)), ' of the ', m('judged', TI.f.int(s.judged)), ' items whose page could be judged carry the claim (',
        m('supported_share', s.supported_share == null ? '—' : d3.format('.0%')(s.supported_share)), '); ', m('judged_share', d3.format('.0%')(s.judged_share || 0)),
        ' of the evidence base could be judged. Last fetch ', m('newest_check', s.newest_check ? s.newest_check.replace('T', ' ').replace('Z', ' UTC') : 'not yet run'), '.');
    }
    const vs = sec.querySelector('#tbl-verify-states');
    if (vs && TI.tableState(vs, ['verification_summary'])) {
      TI.table(vs, TI.rows('verification_summary'), [
        { field: 'label', label: 'What the fetch found', cls: 'ti-wrap' },
        { field: 'items', label: 'Items', num: true, fmt: 'int' },
        { field: 'share', label: 'Share', num: true, get: (r) => d3.format('.1%')(r.share) },
      ], { filter: (r) => r.items > 0 });
    }
    const vt = sec.querySelector('#tbl-verify');
    if (vt && TI.tableState(vt, ['verification'])) {
      TI.table(vt, TI.rows('verification'), [
        { field: 'item_id', label: 'Item', cls: 'ti-nowrap ti-mono' },
        { field: 'date', label: 'Event date', fmt: 'date', cls: 'ti-nowrap', hideSm: true },
        { field: 'source_name', label: 'Source', cls: 'ti-wrap' },
        { field: 'host', label: 'Host', cls: 'ti-mono', hideSm: true },
        { field: 'state', label: 'State' },
        { field: 'http_status', label: 'HTTP', num: true },
        { field: 'tokens_found', label: 'Tokens', get: (r) => (r.tokens_total == null ? '' : `${r.tokens_found} of ${r.tokens_total}`) },
        { field: 'moved_to', label: 'Redirected to', cls: 'ti-mono', hideSm: true },
        { field: 'checked_at', label: 'Checked', fmt: 'date', cls: 'ti-nowrap', hideSm: true },
      ], { filter: (r) => ['gone', 'mismatch', 'weak_match'].includes(r.state), sort: 'item_id', dir: 'desc', empty: 'No fetched page is missing or fails to carry its item.' });
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
