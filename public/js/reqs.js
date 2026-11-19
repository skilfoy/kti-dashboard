/* Requirements: PIR register with QIR, PIR detail, collection matrix, follow-on requirements. */
(() => {
  const { h, v } = TI;
  let selected = 'PIR-2';

  function detail(sec, p, q) {
    const el = sec.querySelector('#req-detail');
    TI.clear(el);
    const w = { pir_id: p.pir_id };
    el.append(h('div', { class: 'ti-kj-top' }, h('h3', { class: 'ti-kj-title' }, v('span', 'pirs', 'pir_id', w, p.pir_id), ' · ', v('span', 'pirs', 'question', w, p.question)),
      h('div', { class: 'ti-kj-meta' }, v('span', 'pirs', 'status', w, p.status, 'ti-badge'), h('span', { class: 'ti-badge' }, 'QIR ', v('span', 'qir', 'qir', w, q ? String(q.qir) : '—'), ' / 512'))));
    const row = (label, field) => [h('dt', { text: label }), v('dd', 'pirs', field, w, p[field] == null || p[field] === '' ? '—' : String(p[field]))];
    el.append(h('dl', { class: 'ti-dl' },
      row('Decision supported', 'decision'), row('Stakeholder', 'stakeholder'), row('Horizon', 'horizon'), row('Last time of value', 'ltiov'),
      row('Answered by', 'answered_by'), row('SIRs', 'sirs'), row('EEIs', 'eeis'), row('Gaps', 'gaps'), row('Panels', 'panels'), row('Review', 'review'), row('Last reviewed', 'last_reviewed')));
  }

  TI.page('requirements', (sec) => {
    const tp = sec.querySelector('#tbl-pirs');
    if (TI.tableState(tp, ['pirs', 'qir'])) {
      const qmap = TI.index(TI.rows('qir'), 'pir_id');
      const pirs = TI.rows('pirs');
      TI.table(tp, pirs, [
        { field: 'pir_id', label: 'PIR', cls: 'ti-nowrap' },
        { field: 'question', label: 'Question', cls: 'ti-wrap' },
        { field: 'S', label: 'S', num: true }, { field: 'D', label: 'D', num: true }, { field: 'F', label: 'F', num: true },
        { field: 'R', label: 'R', num: true }, { field: 'T', label: 'T', num: true },
        { field: 'qir', label: 'QIR', num: true, source: 'qir', get: (r) => (qmap.get(r.pir_id) || {}).qir },
        { field: 'status', label: 'Status' },
        { field: 'horizon', label: 'Horizon', hideSm: true },
        { field: 'answered_by', label: 'Answered by', hideSm: true },
      ], { sort: 'pir_id', dir: 'asc', selected, onClick: (r) => { selected = r.pir_id; TI.draw('requirements'); } });
      const p = pirs.find((x) => x.pir_id === selected) || pirs[0];
      detail(sec, p, qmap.get(p.pir_id));
      const sel = sec.querySelector('#cm-pir');
      if (sel.options.length === 1) for (const x of pirs) sel.append(h('option', { value: x.pir_id, text: x.pir_id }));
    }
    const ta = sec.querySelector('#tbl-alerts');
    if (TI.tableState(ta, ['live_alerts'])) {
      const all = TI.rows('live_alerts') || [], f = sec.querySelector('#al-pir').value;
      const rows = all.filter((r) => r.kind === 'alert').map((r) => {
        const l = TI.list(r.links)[0] || {};
        return { ...r, first_link: TI.obj(l).link || null, graph: /^(term:)/.test(r.subject) ? null : '#graph?id=' + encodeURIComponent(r.subject) };
      });
      const asel = sec.querySelector('#al-pir');
      if (asel.options.length === 1) for (const x of [...new Set(rows.map((r) => r.pir))].sort()) asel.append(h('option', { value: x, text: x }));
      TI.table(ta, rows, [
        { field: 'opened_at', label: 'Opened', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'pir', label: 'PIR', cls: 'ti-nowrap' },
        { field: 'headline', label: 'Alert', cls: 'ti-wrap', link: 'first_link' },
        { field: 'subject_name', label: 'Entity', link: 'graph', hideSm: true },
        { field: 'p', label: 'Publishers', num: true },
        { field: 'last_at', label: 'Latest', fmt: 'date', hideSm: true },
      ], { sort: 'opened_at', dir: 'desc', countEl: sec.querySelector('#al-count'), filter: (r) => !f || r.pir === f, empty: 'No alert in the last 30 days.' });
      const ws = all.filter((r) => r.kind === 'watch');
      sec.querySelector('#al-watches').textContent = ws.length ? 'Watches: ' + ws.map((w) => `${w.watch} (${w.pir}) ${w.title}${String(w.waits_for_baseline) === 'true' ? ', starts once the collection has a 14-day baseline' : ''}: ${w.alerts_30d}`).join('; ') + '.' : '';
      sec.querySelector('#req-alerts-atom').href = '/api/alerts?format=atom' + (f ? '&pir=' + encodeURIComponent(f) : '');
    }
    const tm = sec.querySelector('#tbl-matrix');
    if (TI.tableState(tm, ['collection_matrix'])) {
      const f = sec.querySelector('#cm-pir').value;
      TI.table(tm, TI.rows('collection_matrix'), [
        { field: 'pir_id', label: 'PIR', cls: 'ti-nowrap' },
        { field: 'source_name', label: 'Source' },
        { field: 'role', label: 'Role' },
        { field: 'eei', label: 'Element of information', cls: 'ti-wrap' },
        { field: 'last_satisfied', label: 'Last satisfied', fmt: 'date' },
      ], { sort: 'pir_id', dir: 'asc', countEl: sec.querySelector('#cm-count'), filter: (r) => !f || r.pir_id === f });
    }
    const tf = sec.querySelector('#tbl-fp');
    if (TI.tableState(tf, ['followons'])) {
      TI.table(tf, TI.rows('followons'), [
        { field: 'fp_id', label: 'ID', cls: 'ti-nowrap' },
        { field: 'requirement', label: 'Requirement', cls: 'ti-wrap' },
        { field: 'level', label: 'Level' },
        { field: 'type', label: 'Type' },
        { field: 'priority', label: 'Priority' },
        { field: 'status', label: 'Status' },
        { field: 'rationale', label: 'Rationale', cls: 'ti-wrap', hideSm: true },
        { field: 'raised', label: 'Raised', fmt: 'date', hideSm: true },
      ], { sort: 'fp_id', dir: 'asc' });
    }
  });
  dash.onData(() => TI.draw('requirements'));
  TI.root.addEventListener('input', (ev) => { if (ev.target.id === 'cm-pir' || ev.target.id === 'al-pir') TI.draw('requirements'); });
})();
