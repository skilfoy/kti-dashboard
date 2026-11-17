/* Theaters: I&W board, theater assessment, indicators, cited events, reporting timeline, MERIDIAN comparison. */
(() => {
  const { h, v } = TI;
  let selected = null;
  // Let the map (and links) jump to a theater's assessment.
  TI._selectTheater = (id) => { selected = id; TI.draw('theaters'); };

  // Vertical-calibrated level for a theater, or null before the calc is ready.
  function calOf(id) {
    if (!TI.ready('theater_calibrated')) return null;
    const vertical = dash.params().vertical || 'financial';
    return TI.rows('theater_calibrated').find((r) => r.vertical_id === vertical && r.theater_id === id) || null;
  }
  function vName() {
    const vertical = dash.params().vertical || 'financial';
    const vrt = TI.ready('verticals') ? TI.rows('verticals').find((x) => x.vertical_id === vertical) : null;
    return vrt ? vrt.name : vertical;
  }
  function calBadge(c) {
    if (!c) return null;
    return h('span', { class: TI.lvClass(c.calibrated), title: `${vName()}: base ${c.base} x weight ${c.weight}` },
      vName() + ' ', v('span', 'theater_calibrated', 'calibrated', { key: c.key }, String(c.calibrated)));
  }

  function board(sec, theaters, roll) {
    const el = sec.querySelector('#th-board');
    TI.clear(el);
    for (const t of theaters) {
      const w = { theater_id: t.theater_id };
      const r = roll.get(t.theater_id) || { escalation_seen: 0, total: 0 };
      const pips = h('span', { class: 'ti-pips', 'aria-hidden': 'true' });
      pips.style.color = TI.LEVEL_VAR[t.threatcon];
      for (let i = 0; i < r.total; i++) pips.append(h('span', { class: 'ti-pip' + (i < r.escalation_seen ? ' on' : '') }));
      const b = h('button', { class: 'ti-th', type: 'button', 'data-lv': String(t.threatcon), 'aria-pressed': String(t.theater_id === selected) },
        v('span', 'theaters', 'name', w, t.name, 'ti-th-name'),
        h('span', { class: 'ti-th-row' },
          h('span', { class: TI.lvClass(t.threatcon) }, v('span', 'theaters', 'threatcon', w, String(t.threatcon)), ' ', v('span', 'theaters', 'label', w, t.label)),
          v('span', 'theaters', 'trend', w, t.trend, 'ti-trend')),
        h('span', { class: 'ti-th-row' }, calBadge(calOf(t.theater_id))),
        h('span', { class: 'ti-th-row' }, pips,
          v('span', 'indicator_rollup', 'escalation_seen', w, String(r.escalation_seen)), ' of ',
          v('span', 'indicator_rollup', 'total', w, String(r.total)), ' indicators'));
      b.querySelector('.ti-trend').setAttribute('data-trend', t.trend);
      b.addEventListener('click', () => { selected = t.theater_id; TI.draw('theaters'); });
      el.append(b);
    }
  }

  function detail(sec, t, conf) {
    const el = sec.querySelector('#theater-detail');
    TI.clear(el);
    const w = { theater_id: t.theater_id };
    const top = h('div', { class: 'ti-kj-top' }, v('h2', 'theaters', 'name', w, t.name, 'ti-kj-title'),
      h('div', { class: 'ti-kj-meta' },
        h('span', { class: TI.lvClass(t.threatcon) }, 'ThreatCon ', v('span', 'theaters', 'threatcon', w, String(t.threatcon)), ' ', v('span', 'theaters', 'label', w, t.label)),
        v('span', 'theaters', 'trend', w, t.trend, 'ti-trend'),
        calBadge(calOf(t.theater_id)),
        conf ? h('span', { class: 'ti-badge ti-conf-' + conf.confidence }, 'Confidence ', v('span', 'confidence', 'confidence', { judgment_id: t.judgment_id }, conf.confidence)) : null));
    top.querySelector('.ti-trend').setAttribute('data-trend', t.trend);
    el.append(top);
    el.append(h('p', { class: 'ti-lede', style: 'margin-top: var(--cds-gap-sm); color: var(--color-fg)' }, v('span', 'theaters', 'key_judgment', w, t.key_judgment)));
    const row = (label, field, val) => [h('dt', { text: label }), v('dd', 'theaters', field, w, val)];
    const dl = h('dl', { class: 'ti-dl' },
      row('Basis', 'basis', t.basis),
      row('Sponsor posture', 'sponsor_posture', t.sponsor_posture),
      row('Cyber nexus', 'cyber_nexus', t.cyber_nexus),
      row('Postulated scenario', 'scenario', t.scenario),
      row('So what', 'so_what', t.so_what),
      row('Outlook', 'outlook', t.outlook),
      row('Requirements', 'pirs', t.pirs),
      [h('dt', { text: 'MERIDIAN baseline' }), h('dd', {}, t.meridian_baseline == null ? 'Not covered' : v('span', 'theaters', 'meridian_baseline', w, String(t.meridian_baseline)))],
      TI.changes ? TI.changes.theaterRow(t) : null,
      row('Last reviewed', 'last_reviewed', t.last_reviewed),
      row('Review by', 'review_by', t.review_by));
    el.append(dl);
    if (t.judgment_id) {
      const go = h('button', { class: 'ti-more', type: 'button', style: 'margin-top: var(--cds-gap-sm)' }, 'Linked judgment ', v('span', 'theaters', 'judgment_id', w, t.judgment_id));
      go.addEventListener('click', () => TI.go('brief', 'key-judgments'));
      el.append(go);
    }
    // Lanes temperatures, OFAC actions, country profiles and pivots (context.js).
    if (TI.ctx) TI.ctx.theaterDetail(el, t);
  }

  function timeline(sec, items, tmap) {
    const box = sec.querySelector('#th-timeline');
    const order = [...tmap.values()].sort((a, b) => b.threatcon - a.threatcon || a.name.localeCompare(b.name));
    const newest = items.reduce((m, i) => (i.date > m ? i.date : m), '');
    const end = TI.parseDay(newest);
    const start = new Date(end.getTime() - 60 * 864e5);
    const pts = items.filter((i) => tmap.has(i.theater_id) && TI.parseDay(i.date) >= start);
    const rowH = 22;
    const height = order.length * rowH + 40;
    const { svg, w } = TI.svg(box, height);
    const lw = TI.textWidth(svg, order.map((t) => t.name)) + 12;
    const x = d3.scaleUtc([start, end], [lw, w - 12]);
    const y = d3.scaleBand(order.map((t) => t.theater_id), [8, height - 28]).padding(0.2);
    const g = svg.append('g');
    g.selectAll('line.ti-grid-line').data(x.ticks(6)).join('line').attr('class', 'ti-grid-line').attr('x1', (d) => x(d)).attr('x2', (d) => x(d)).attr('y1', 8).attr('y2', height - 28);
    g.selectAll('text.tick').data(x.ticks(6)).join('text').attr('x', (d) => x(d)).attr('y', height - 10).attr('text-anchor', 'middle').text((d) => TI.dayLabel(d));
    g.selectAll('text.name').data(order).join('text').attr('class', 'ti-lbl').attr('x', lw - 8).attr('y', (t) => y(t.theater_id) + y.bandwidth() / 2).attr('dy', '0.35em').attr('text-anchor', 'end').text((t) => t.name);
    const tip = TI.tip(box);
    g.selectAll('circle').data(pts).join('circle')
      .attr('cx', (i) => x(TI.parseDay(i.date)))
      .attr('cy', (i) => y(i.theater_id) + y.bandwidth() / 2 + ((i.item_id.charCodeAt(i.item_id.length - 1) % 3) - 1) * 4)
      .attr('r', 4.5)
      .style('fill', (i) => TI.LEVEL_VAR[tmap.get(i.theater_id).threatcon])
      .style('opacity', 0.85)
      .on('mousemove', (ev, i) => {
        const [mx, my] = d3.pointer(ev, box);
        tip.show(`${i.date} · ${tmap.get(i.theater_id).name}`, [{ text: i.title }, { text: `${i.source_name} · ${i.grade} · ${i.veracity}` }], mx, my);
      })
      .on('mouseleave', () => tip.hide())
      .on('click', (ev, i) => { selected = i.theater_id; TI.draw('theaters'); });
  }

  TI.page('theaters', (sec) => {
    const ids = ['theaters', 'indicator_rollup', 'theater_indicators', 'items', 'confidence'];
    const boardEl = sec.querySelector('#th-board');
    if (TI.failed(...ids)) { TI.failLine(boardEl); return; }
    if (!TI.ready(...ids)) { boardEl.classList.add('dash-skeleton'); return; }
    boardEl.classList.remove('dash-skeleton');
    const theaters = TI.rows('theaters').slice().sort((a, b) => b.threatcon - a.threatcon || a.name.localeCompare(b.name));
    const tmap = TI.index(theaters, 'theater_id');
    const roll = TI.index(TI.rows('indicator_rollup'), 'theater_id');
    const conf = TI.index(TI.rows('confidence'), 'judgment_id');
    const items = TI.rows('items');
    if (!selected || !tmap.has(selected)) selected = theaters[0].theater_id;
    board(sec, theaters, roll);
    const t = tmap.get(selected);
    detail(sec, t, t.judgment_id ? conf.get(t.judgment_id) : null);
    TI.table(sec.querySelector('#tbl-indicators'), TI.rows('theater_indicators'), [
      { field: 'indicator', label: 'Indicator', cls: 'ti-wrap' },
      { field: 'direction', label: 'Direction' },
      { field: 'state', label: 'State', attr: { 'data-state': (r) => r.state }, cls: 'ti-state' },
      { field: 'last_seen', label: 'Last seen', fmt: 'date', cls: 'ti-nowrap' },
      { field: 'note', label: 'Note', hideSm: true },
    ], { filter: (r) => r.theater_id === selected, empty: 'No indicators set.' });
    TI.table(sec.querySelector('#tbl-theater-items'), items, [
      { field: 'date', label: 'Date', fmt: 'date', cls: 'ti-nowrap' },
      { field: 'title', label: 'Item', link: 'url', cls: 'ti-wrap' },
      { field: 'source_name', label: 'Source', hideSm: true },
      { field: 'grade', label: 'Grade' },
      { field: 'veracity', label: 'Veracity', attr: { 'data-v': (r) => r.veracity }, cls: 'ti-ver' },
    ], { filter: (r) => r.theater_id === selected, sort: 'date', dir: 'desc' });
    // Machine leads for the selected theater, shown only while the tier's theater labels clear their evaluation thresholds.
    const tld = sec.querySelector('#tbl-theater-leads');
    if (tld && TI.tableState(tld, ['live_triage'])) {
      const all = TI.rows('live_triage') || [], meta = all.find((r) => r.kind === 'meta') || {}, ev = meta.eval || {};
      const note = sec.querySelector('#theater-leads-note');
      if (!ev.promoted) {
        if (note) note.textContent = 'The triage tier labels headlines with a theater, but its labels stay off this page until its agreement with the analyst\'s own labels clears the published thresholds (Method, machine triage).';
        TI.table(tld, [], [{ field: 'title', label: 'Lead' }], { empty: 'Theater labels are not yet shown.' });
      } else {
        TI.table(tld, all.filter((r) => r.kind === 'lead' && r.theater === selected && r.relevance >= 2), [
          { field: 'relevance', label: 'Rel.', num: true, fmt: 'int' },
          { field: 'published', label: 'Published', fmt: 'date', cls: 'ti-nowrap' },
          { field: 'title', label: 'Headline', link: 'link', cls: 'ti-wrap' },
          { field: 'source', label: 'Source', hideSm: true },
          { field: 'also', label: 'Also carried by', get: (r) => (r.also ? `${r.also} more` : ''), hideSm: true },
          { field: 'verify', label: 'Second model', get: (r) => (r.verify === 'confirmed' ? 'agrees' : r.verify === 'lowered' ? 'lowered from 3' : ''), hideSm: true },
        ], { sort: 'relevance', dir: 'desc', limit: 30, empty: 'No relevance 2 or 3 leads labelled with this theater in 72 hours.' });
      }
    }
    const tl = sec.querySelector('#th-timeline');
    if (TI.chartState(tl, ['items', 'theaters'])) timeline(sec, items, tmap);
    TI.table(sec.querySelector('#tbl-theaters'), theaters, [
      { field: 'name', label: 'Theater', cls: 'ti-wrap' },
      { field: 'threatcon', label: 'ThreatCon', num: true },
      { field: 'label', label: 'Level' },
      { field: 'trend', label: 'Trend' },
      { field: 'meridian_baseline', label: 'MERIDIAN base', num: true },
      { field: 'escalation_seen', label: 'Indicators seen', num: true, source: 'indicator_rollup', get: (r) => (roll.get(r.theater_id) || {}).escalation_seen },
      { field: 'total', label: 'Indicators set', num: true, source: 'indicator_rollup', get: (r) => (roll.get(r.theater_id) || {}).total },
      { field: 'review_by', label: 'Review by', fmt: 'date' },
    ], { sort: 'threatcon', dir: 'desc', selected, onClick: (r) => { selected = r.theater_id; TI.draw('theaters'); sec.querySelector('#theater-board').scrollIntoView({ block: 'start' }); } });
    if (TI.ctx) TI.ctx.theaterCards(sec);
    // Measured indications and warning (warning.js).
    if (TI.warn) TI.warn.draw(sec);
  });
  dash.onData(() => TI.draw('theaters'));
})();
