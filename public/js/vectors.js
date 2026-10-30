/* Vectors: Big 5 plus fraud lens and identity card, the media-volume heat map, and cited items by vector. */
(() => {
  const { h, v } = TI;
  let mode = 'incidents';
  let picked = '';

  function cards(sec, vectors, vi, cal, vname) {
    const el = sec.querySelector('#vec-cards');
    TI.clear(el);
    for (const x of vectors) {
      const w = { vector_id: x.vector_id };
      const n = vi.get(x.vector);
      const icoRow = (label, f, fb) => [h('dt', { text: label }), h('dd', {}, v('strong', 'vectors', f, w, x[f]), ' · ', v('span', 'vectors', fb, w, x[fb]))];
      const trend = v('span', 'vectors', 'trend', w, x.trend, 'ti-trend');
      trend.setAttribute('data-trend', x.trend);
      el.append(h('article', { class: 'ti-card ti-kj ti-fade' },
        h('div', { class: 'ti-kj-top' }, v('h3', 'vectors', 'vector', w, x.vector, 'ti-kj-title'),
          h('div', { class: 'ti-kj-meta' }, h('span', { class: TI.lvClass(x.level) }, v('span', 'vectors', 'level', w, String(x.level)), ' ', v('span', 'vectors', 'label', w, x.label)), trend, calBadge(cal.get(x.vector_id), vname))),
        h('div', { class: 'ti-cap ti-muted' }, 'Big 5: ', v('span', 'vectors', 'big5', w, x.big5), ' · ', v('span', 'vectors', 'pirs', w, x.pirs), ' · CSF ', v('span', 'vectors', 'csf', w, x.csf)),
        h('dl', { class: 'ti-dl' }, icoRow('Intent', 'intent', 'intent_basis'), icoRow('Capability', 'capability', 'capability_basis'), icoRow('Opportunity', 'opportunity', 'opportunity_basis'),
          h('dt', { text: 'Drivers' }), v('dd', 'vectors', 'drivers', w, x.drivers),
          h('dt', { text: 'So what' }), v('dd', 'vectors', 'so_what', w, x.so_what),
          h('dt', { text: 'Judgments' }), v('dd', 'vectors', 'judgments', w, x.judgments),
          h('dt', { text: 'Cited items' }), h('dd', {}, n ? v('span', 'vector_items', 'items', { vector: x.vector }, String(n.items)) : '0', n ? [' · newest ', v('span', 'vector_items', 'newest_item', { vector: x.vector }, n.newest_item)] : null))));
    }
  }

  // The vertical-calibrated level beside the base level, with the weight in the tooltip.
  function calBadge(c, vname) {
    if (!c) return null;
    const b = h('span', { class: TI.lvClass(c.calibrated), title: `${vname}: base ${c.base} x weight ${c.weight}` },
      vname + ' ', v('span', 'vector_calibrated', 'calibrated', { key: c.key }, String(c.calibrated)));
    return b;
  }

  function heat(sec, rows) {
    const box = sec.querySelector('#vec-heat');
    const vectors = [...new Set(rows.map((r) => r.vector))];
    const weeks = [...new Set(rows.map((r) => r.week))].sort();
    const rowH = 30;
    const height = vectors.length * rowH + 44;
    const { svg, w } = TI.svg(box, height);
    const lw = TI.textWidth(svg, vectors) + 14;
    const x = d3.scaleBand(weeks, [lw, w - 8]).padding(0.06);
    const y = d3.scaleBand(vectors, [4, height - 30]).padding(0.08);
    const max = d3.max(rows, (r) => r[mode]) || 1;
    const lo = TI.resolve('var(--color-panel)'), hi = TI.resolve(TI.color(0));
    const col = d3.scaleSequential([0, max], d3.interpolateRgb(lo, hi));
    const tip = TI.tip(box);
    svg.append('g').selectAll('rect').data(rows).join('rect').attr('class', 'ti-cell')
      .attr('x', (r) => x(r.week)).attr('y', (r) => y(r.vector)).attr('width', x.bandwidth()).attr('height', y.bandwidth()).attr('rx', 3)
      .style('fill', (r) => col(r[mode]))
      .on('mousemove', (ev, r) => {
        const [mx, my] = d3.pointer(ev, box);
        tip.show(`Week of ${r.week}${r.partial_week === 'Yes' ? ' (partial)' : ''}`, [{ text: `${r.vector}: ${TI.f.int(r.incidents)} clusters` }, { text: `Financial sector: ${TI.f.int(r.financial_sector)}` }], mx, my);
      })
      .on('mouseleave', () => tip.hide());
    svg.append('g').selectAll('text').data(vectors).join('text').attr('class', 'ti-lbl').attr('x', lw - 8).attr('y', (d) => y(d) + y.bandwidth() / 2).attr('dy', '0.35em').attr('text-anchor', 'end').text((d) => d);
    const every = Math.ceil(weeks.length / Math.max(2, Math.floor((w - lw) / 70)));
    svg.append('g').selectAll('text').data(weeks.filter((_, i) => i % every === 0)).join('text').attr('x', (d) => x(d) + x.bandwidth() / 2).attr('y', height - 10).attr('text-anchor', 'middle').text((d) => TI.dayLabel(TI.parseDay(d)));
  }

  function chips(sec, vectors) {
    const el = sec.querySelector('#vec-chips');
    if (el.childElementCount) {
      for (const c of el.children) c.setAttribute('aria-pressed', String(c.dataset.v === picked));
      return;
    }
    for (const name of [''].concat(vectors.map((x) => x.vector))) {
      const c = h('button', { class: 'ti-chip', type: 'button', 'data-v': name, 'aria-pressed': String(name === picked) }, name || 'All vectors');
      c.addEventListener('click', () => { picked = name; TI.draw('vectors'); });
      el.append(c);
    }
  }

  TI.page('vectors', (sec) => {
    const cardsEl = sec.querySelector('#vec-cards');
    if (TI.failed('vectors', 'vector_items')) TI.failLine(cardsEl);
    else if (TI.ready('vectors', 'vector_items')) {
      cardsEl.classList.remove('dash-skeleton');
      const vertical = dash.params().vertical || 'financial';
      const cal = TI.ready('vector_calibrated') ? TI.index(TI.rows('vector_calibrated').filter((r) => r.vertical_id === vertical), 'vector_id') : new Map();
      const vrt = TI.ready('verticals') ? TI.rows('verticals').find((x) => x.vertical_id === vertical) : null;
      cards(sec, TI.rows('vectors'), TI.index(TI.rows('vector_items'), 'vector'), cal, vrt ? vrt.name : vertical);
      chips(sec, TI.rows('vectors'));
    } else cardsEl.classList.add('dash-skeleton');
    const hb = sec.querySelector('#vec-heat');
    if (TI.chartState(hb, ['vector_baseline'])) heat(sec, TI.rows('vector_baseline'));
    const t = sec.querySelector('#tbl-vector-items');
    if (TI.tableState(t, ['items'])) {
      TI.table(t, TI.rows('items'), [
        { field: 'date', label: 'Date', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'vector', label: 'Vector' },
        { field: 'title', label: 'Item', link: 'url', cls: 'ti-wrap' },
        { field: 'source_name', label: 'Source', hideSm: true },
        { field: 'grade', label: 'Grade' },
      ], { filter: (r) => r.vector && (!picked || r.vector === picked), sort: 'date', dir: 'desc' });
    }
  });
  dash.onData(() => TI.draw('vectors'));
  TI.root.addEventListener('click', (ev) => {
    const b = ev.target.closest && ev.target.closest('#heat-all, #heat-fin');
    if (!b) return;
    mode = b.id === 'heat-fin' ? 'financial_sector' : 'incidents';
    document.getElementById('heat-all').setAttribute('aria-pressed', String(mode === 'incidents'));
    document.getElementById('heat-fin').setAttribute('aria-pressed', String(mode !== 'incidents'));
    TI.draw('vectors');
  });
})();
