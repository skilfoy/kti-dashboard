/* Header takeaway and the Brief page: tiles, executive judgments with argument maps, recent items and the disruption lane. */
(() => {
  const { h, v } = TI;
  const header = document.getElementById('header');
  const open = new Set();

  const ITEM_COLS = [
    { field: 'date', label: 'Date', fmt: 'date', cls: 'ti-nowrap' },
    { field: 'theater_name', label: 'Theater', hideSm: true },
    { field: 'title', label: 'Item', link: 'url', cls: 'ti-wrap' },
    { field: 'source_name', label: 'Source', hideSm: true },
    { field: 'grade', label: 'Grade' },
    { field: 'veracity', label: 'Veracity' },
  ];

  function judgmentCard(j, conf, evidence) {
    const id = j.judgment_id;
    const w = { judgment_id: id };
    const card = h('article', { class: 'ti-card ti-kj ti-fade' });
    const meta = h('div', { class: 'ti-kj-meta' },
      v('span', 'judgments', 'likelihood', w, j.likelihood, 'ti-badge'),
      v('span', 'judgments', 'probability', w, j.probability, 'ti-cap ti-muted'),
      h('span', { class: 'ti-badge ti-conf-' + (conf ? conf.confidence : 'LOW') },
        'Confidence ', v('span', 'confidence', 'confidence', w, conf ? conf.confidence : '—')),
      h('span', { class: 'ti-badge ti-sev-' + j.severity }, 'Severity ', v('span', 'judgments', 'severity', w, j.severity)),
      j.horizon ? h('span', { class: 'ti-cap ti-muted', title: 'The date by which this judgment is scored in the forecast record' }, 'Scored by ', v('span', 'judgments', 'horizon', w, j.horizon)) : null);
    card.append(h('div', { class: 'ti-kj-top' }, v('h3', 'judgments', 'title', w, j.title, 'ti-kj-title'), meta));
    card.append(h('p', {}, h('span', { class: 'ti-kj-label', text: 'Situation' }), v('span', 'judgments', 'situation', w, j.situation)));
    card.append(h('p', {}, h('span', { class: 'ti-kj-label', text: 'Assessment' }), v('span', 'judgments', 'assessment', w, j.assessment)));
    card.append(h('p', { class: 'ti-cta' }, h('span', { class: 'ti-kj-label', text: 'Action' }), v('span', 'judgments', 'cta', w, j.cta)));
    card.append(h('div', { class: 'ti-kj-meta ti-cap ti-muted' },
      'NIST CSF 2.0 ', v('span', 'judgments', 'csf', w, j.csf), ' · ', v('span', 'judgments', 'pirs', w, j.pirs),
      ' · Evidence: ', v('span', 'confidence', 'supporting', w, conf ? String(conf.supporting) : '—'), ' items from ',
      v('span', 'confidence', 'origins', w, conf ? String(conf.origins) : '—'), ' origins, mean score ',
      v('span', 'confidence', 'mean_score', w, conf ? TI.f.dec2(conf.mean_score) : '—')));
    const btn = h('button', { class: 'ti-more', type: 'button', 'aria-expanded': String(open.has(id)) }, open.has(id) ? 'Hide argument map' : 'Argument map');
    const map = h('div', { class: 'ti-amap', hidden: !open.has(id) });
    btn.addEventListener('click', () => {
      if (open.has(id)) open.delete(id); else open.add(id);
      map.hidden = !open.has(id);
      btn.textContent = open.has(id) ? 'Hide argument map' : 'Argument map';
      btn.setAttribute('aria-expanded', String(open.has(id)));
    });
    card.append(btn);
    const evs = evidence.filter((e) => e.judgment_id === id);
    const args = [...new Set(evs.map((e) => e.argument))];
    for (const a of args) {
      const group = evs.filter((e) => e.argument === a);
      const box = h('div', { class: 'ti-arg' }, v('div', 'evidence', 'argument_text', { evid_id: group[0].evid_id }, group[0].argument_text, 'ti-h3'));
      const ul = h('ul');
      for (const e of group) {
        const ew = { evid_id: e.evid_id };
        ul.append(h('li', {},
          v('span', 'evidence', 'role', ew, e.role, 'ti-role'), ' ',
          h('a', { href: e.url, target: '_blank', rel: 'noopener noreferrer' }, v('span', 'evidence', 'item_title', ew, e.item_title)),
          h('span', { class: 'ti-cap ti-muted' }, ' (', v('span', 'evidence', 'source_name', ew, e.source_name), ', ', v('span', 'evidence', 'grade', ew, e.grade), ', ', v('span', 'evidence', 'date', ew, e.date), ')'),
          h('div', { class: 'ti-cap ti-muted' }, v('span', 'evidence', 'bridge', ew, e.bridge))));
      }
      box.append(ul);
      map.append(box);
    }
    map.append(h('dl', { class: 'ti-dl' },
      h('dt', { text: 'Key assumptions' }), v('dd', 'judgments', 'assumptions', w, j.assumptions),
      h('dt', { text: 'Alternatives' }), v('dd', 'judgments', 'alternatives', w, j.alternatives),
      h('dt', { text: 'Indicators of change' }), v('dd', 'judgments', 'indicators_of_change', w, j.indicators_of_change),
      h('dt', { text: 'What if' }), v('dd', 'judgments', 'what_if', w, j.what_if),
      h('dt', { text: 'Markings' }), h('dd', {}, v('span', 'judgments', 'tlp', w, j.tlp), ' · ', v('span', 'judgments', 'pap', w, j.pap), ' · reviewed ', v('span', 'judgments', 'last_reviewed', w, j.last_reviewed))));
    card.append(map);
    return card;
  }

  function drawJudgments() {
    const list = document.getElementById('kj-list');
    const ids = ['judgments', 'evidence', 'items', 'confidence', 'exec_brief'];
    if (TI.failed(...ids)) { TI.failLine(list); return; }
    if (!TI.ready(...ids)) { TI.clear(list); list.classList.add('dash-skeleton'); return; }
    list.classList.remove('dash-skeleton');
    const J = TI.index(TI.rows('judgments'), 'judgment_id');
    const C = TI.index(TI.rows('confidence'), 'judgment_id');
    const evidence = TI.rows('evidence');
    TI.clear(list);
    for (const x of TI.rows('exec_brief')) {
      const j = J.get(x.judgment_id);
      if (j) list.append(judgmentCard(j, C.get(j.judgment_id), evidence));
    }
  }

  function drawTables() {
    const tc = document.getElementById('tbl-changes');
    const td = document.getElementById('tbl-disruption');
    if (!TI.tableState(tc, ['items', 'brief_stats']) | !TI.tableState(td, ['items'])) return;
    const items = TI.rows('items');
    const newest = TI.rows('brief_stats')[0].newest_item;
    const cut = new Date(Date.parse(newest + 'T00:00:00Z') - 7 * 864e5).toISOString().slice(0, 10);
    TI.table(tc, items, ITEM_COLS, { filter: (r) => r.date > cut, sort: 'date', dir: 'desc' });
    TI.table(td, items, ITEM_COLS.filter((c) => c.field !== 'veracity'), { filter: (r) => r.lane === 'Disruption', sort: 'date', dir: 'desc' });
  }

  // Live panel: the vertical tile follows the header selection; tables fill from the live calcs.
  function drawLive(sec) {
    const vertical = dash.params().vertical || 'financial';
    const vrt = TI.ready('verticals') ? TI.rows('verticals').find((x) => x.vertical_id === vertical) : null;
    const sector = vrt ? vrt.sectors : 'Financial Services';
    const vc = sec.querySelector('#live-vclaims');
    if (vc) vc.setAttribute('data-where', TI.where({ vertical_id: vertical }));
    const vn = sec.querySelector('#live-vname');
    if (vn) vn.textContent = vrt ? vrt.name.toLowerCase() : 'the selected vertical';
    const vs = sec.querySelector('#live-vsector');
    if (vs) vs.textContent = sector;
    const tr = sec.querySelector('#tbl-live-rw');
    if (tr && TI.tableState(tr, ['live_rw_by_group'])) {
      TI.table(tr, TI.rows('live_rw_by_group'), [
        { field: 'group', label: 'Group' },
        { field: 'claims', label: 'Claims', num: true, fmt: 'int' },
        { field: 'financial', label: 'Financial', num: true, fmt: 'int', hideSm: true },
        { field: 'countries', label: 'Countries', num: true, fmt: 'int' },
      ], { sort: 'claims', dir: 'desc', empty: 'No claims in the live set.' });
    }
    const tt = sec.querySelector('#tbl-live-tf');
    if (tt && TI.tableState(tt, ['live_tf_by_malware'])) {
      TI.table(tt, TI.rows('live_tf_by_malware'), [
        { field: 'malware', label: 'Family' },
        { field: 'iocs', label: 'Indicators', num: true, fmt: 'int' },
        { field: 'types', label: 'Types', hideSm: true },
        { field: 'threat', label: 'Threat type', hideSm: true },
        { field: 'newest', label: 'Newest', cls: 'ti-nowrap' },
      ], { sort: 'iocs', dir: 'desc', empty: 'No indicators in the live set.' });
    }
    const th = sec.querySelector('#tbl-live-health');
    if (th && TI.tableState(th, ['live_health_upstreams'])) {
      TI.table(th, TI.rows('live_health_upstreams'), [
        { field: 'feed', label: 'Upstream', cls: 'ti-mono' },
        { field: 'ok', label: 'State', attr: { 'data-up': (r) => r.ok }, cls: 'ti-up' },
        { field: 'status', label: 'HTTP', num: true },
        { field: 'ms', label: 'Latency ms', num: true, fmt: 'int' },
        { field: 'cache', label: 'Proxy cache' },
        { field: 'note', label: 'Note', hideSm: true },
      ], { sort: 'feed', dir: 'asc' });
    }
    const tc = sec.querySelector('#tbl-collector-uptime');
    if (tc && TI.tableState(tc, ['live_collector_uptime'])) {
      const pct = (v) => (v == null ? '—' : (Math.round(v * 10) / 10) + '%');
      TI.table(tc, TI.rows('live_collector_uptime'), [
        { field: 'feed', label: 'Upstream or job', cls: 'ti-mono' },
        { field: 'ok', label: 'Last check', attr: { 'data-up': (r) => r.ok }, cls: 'ti-up' },
        { field: 'uptime_24h', label: '24h', num: true, get: (r) => (r.kind === 'job' ? `${r.runs_24h - r.failed_24h}/${r.runs_24h} runs` : pct(r.uptime_24h)) },
        { field: 'uptime_7d', label: '7d', num: true, get: (r) => (r.kind === 'job' ? '' : pct(r.uptime_7d)), hideSm: true },
        { field: 'p50_ms', label: 'Median ms', num: true, fmt: 'int', get: (r) => (r.kind === 'job' ? r.ms : r.p50_ms), hideSm: true },
        { field: 'failing_streak', label: 'Failing streak', num: true, fmt: 'int', get: (r) => (r.kind === 'job' ? r.failed_24h : r.failing_streak) },
        { field: 'feeds', label: 'Feeds', hideSm: true },
      ], { sort: 'feed', dir: 'asc', empty: 'The collector record is not available.' });
    }
  }

  TI.page('brief', (sec) => {
    drawLive(sec);
    // SEC Item 1.05 disclosures and the ThreatFox gate (intel.js).
    if (TI.intel) TI.intel.briefCards(sec);
    // What the latest run changed (changes.js).
    if (TI.changes) TI.changes.brief(sec);
    TI.fillMarks(sec);
    drawJudgments();
    drawTables();
  });
  dash.onData(() => {
    TI.fillMarks(header);
    TI.draw('brief');
  });
})();
