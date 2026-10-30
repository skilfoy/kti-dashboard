/* Residual risk: inherent threat narrowed by owned-asset exposure and control coverage. Inputs are the
   AutoRecon asset inventory and the darknet-mcp-server exposure read (sample until the owner's ingests replace them). */
(() => {
  const { h } = TI;
  const d3 = window.d3;
  const ORDER = ['V-EXP', 'V-RAN', 'V-IDN', 'V-PHI', 'V-FRA', 'V-SUP', 'V-DDO', 'V-INS'];
  const bandColor = (b) => (b === 'High' ? 'var(--ti-crit)' : b === 'Medium' ? 'var(--ti-elev)' : 'var(--color-ok)');
  const vertical = () => dash.params().vertical || 'financial';
  const sortVec = (a, b) => ORDER.indexOf(a.vector_id) - ORDER.indexOf(b.vector_id);

  function residualChart(box, rows) {
    const data = rows.slice().sort(sortVec);
    const narrow = (box.clientWidth || 600) < 520; // phone: labels sit above the bars
    const rowH = narrow ? 50 : 40;
    const height = data.length * rowH + 26;
    const { svg, w } = TI.svg(box, height);
    const lw = narrow ? 4 : TI.textWidth(svg, data.map((d) => d.vector)) + 12;
    const x = d3.scaleLinear([0, Math.max(0.5, d3.max(data, (d) => d.residual) * 1.15)], [lw, w - 52]);
    const y = d3.scaleBand(data.map((d) => d.vector_id), [narrow ? 18 : 4, height - 22]).paddingInner(narrow ? 0.55 : 0.3).paddingOuter(0.1);
    svg.append('g').selectAll('line').data(x.ticks(4)).join('line').attr('class', 'ti-grid-line').attr('x1', x).attr('x2', x).attr('y1', 4).attr('y2', height - 22);
    svg.append('g').selectAll('text').data(x.ticks(4)).join('text').attr('x', x).attr('y', height - 8).attr('text-anchor', 'middle').text((t) => TI.f.pct(t));
    // Thresholds for the bands
    for (const [t, lbl] of [[0.2, 'Medium'], [0.4, 'High']]) {
      if (t > x.domain()[1]) continue;
      svg.append('line').attr('x1', x(t)).attr('x2', x(t)).attr('y1', 4).attr('y2', height - 22).attr('stroke', 'var(--cds-chart-axis)').attr('stroke-dasharray', '3 3');
      if (!narrow) svg.append('text').attr('x', x(t) + 3).attr('y', 12).text(lbl);
    }
    const tip = TI.tip(box);
    const g = svg.append('g');
    g.selectAll('rect').data(data).join('rect').attr('x', lw).attr('y', (d) => y(d.vector_id)).attr('height', y.bandwidth()).attr('rx', 4)
      .attr('width', (d) => Math.max(2, x(d.residual) - lw)).attr('fill', (d) => bandColor(d.band))
      .attr('data-source', 'residual_risk').attr('data-field', 'residual').attr('data-where', (d) => TI.where({ key: d.key }))
      .on('mousemove', (ev, d) => {
        const [mx, my] = d3.pointer(ev, box);
        tip.show(d.vector, [
          { text: `Residual ${TI.f.pct(d.residual)} (${d.band})`, color: bandColor(d.band) },
          { text: `Inherent ${TI.f.pct(d.inherent)} x exposure ${TI.f.pct(d.exposure)} x (1 - coverage ${TI.f.pct(d.coverage)})` },
          { text: `Exposure basis: ${d.exposure_basis}` },
          { text: 'NIST CSF 2.0 ' + d.csf },
        ], mx, my);
      })
      .on('mouseleave', () => tip.hide());
    if (narrow) g.selectAll('text.l').data(data).join('text').attr('class', 'ti-lbl').attr('x', lw).attr('y', (d) => y(d.vector_id) - 5).text((d) => d.vector);
    else g.selectAll('text.l').data(data).join('text').attr('class', 'ti-lbl').attr('x', lw - 8).attr('y', (d) => y(d.vector_id) + y.bandwidth() / 2).attr('dy', '0.35em').attr('text-anchor', 'end').text((d) => d.vector);
    g.selectAll('text.v').data(data).join('text').attr('x', (d) => x(d.residual) + 5).attr('y', (d) => y(d.vector_id) + y.bandwidth() / 2).attr('dy', '0.35em').text((d) => TI.f.pct(d.residual));
  }

  // Vertical x vector matrix: every sector's residual on one estate.
  function matrix(box, rows, verticals) {
    const vecs = [...new Map(rows.map((r) => [r.vector_id, r.vector])).entries()].sort((a, b) => ORDER.indexOf(a[0]) - ORDER.indexOf(b[0]));
    const narrow = (box.clientWidth || 600) < 520;
    const vs = verticals.map((v) => [v.vertical_id, narrow ? v.name.split(' ')[0] : v.name]);
    const cell = new Map(rows.map((r) => [r.vertical_id + '|' + r.vector_id, r]));
    const rowH = 30;
    const height = vs.length * rowH + (narrow ? 96 : 70);
    const { svg, w } = TI.svg(box, height);
    const lw = TI.textWidth(svg, vs.map((v) => v[1])) + 14;
    const x = d3.scaleBand(vecs.map((v) => v[0]), [lw, w - 4]).padding(0.06);
    const top = narrow ? 82 : 56;
    const y = d3.scaleBand(vs.map((v) => v[0]), [top, height - 4]).padding(0.08);
    const max = d3.max(rows, (r) => r.residual) || 0.5;
    const lo = TI.resolve('var(--color-panel)'), hi = TI.resolve('var(--ti-crit)');
    const col = d3.scaleSequential([0, max], d3.interpolateRgb(lo, hi));
    const tip = TI.tip(box);
    // Column heads: short vector labels, rotated when the band is narrow
    const short = (s) => s.replace(/ & .*/, '').replace(/ and .*/, '').replace(/,.*/, '');
    const heads = svg.append('g').selectAll('text').data(vecs).join('text').attr('class', 'ti-lbl')
      .text((v) => short(v[1]));
    if (x.bandwidth() < 90) heads.attr('transform', (v) => `translate(${x(v[0]) + x.bandwidth() / 2},${top - 6}) rotate(${narrow ? -60 : -28})`).attr('text-anchor', 'start');
    else heads.attr('x', (v) => x(v[0]) + x.bandwidth() / 2).attr('y', 46).attr('text-anchor', 'middle');
    svg.append('g').selectAll('text').data(vs).join('text').attr('class', 'ti-lbl').attr('x', lw - 8).attr('y', (v) => y(v[0]) + y.bandwidth() / 2).attr('dy', '0.35em').attr('text-anchor', 'end')
      .style('font-weight', (v) => (v[0] === vertical() ? 'var(--cds-font-weight-medium)' : null)).text((v) => v[1]);
    const cells = [];
    for (const [vid] of vs) for (const [cid] of vecs) { const r = cell.get(vid + '|' + cid); if (r) cells.push(r); }
    const g = svg.append('g');
    g.selectAll('rect').data(cells).join('rect').attr('class', 'ti-cell').attr('rx', 3)
      .attr('x', (r) => x(r.vector_id)).attr('y', (r) => y(r.vertical_id)).attr('width', x.bandwidth()).attr('height', y.bandwidth())
      .style('fill', (r) => col(r.residual))
      .attr('data-source', 'residual_risk').attr('data-field', 'residual').attr('data-where', (r) => TI.where({ key: r.key }))
      .on('mousemove', (ev, r) => {
        const [mx, my] = d3.pointer(ev, box);
        const vn = (vs.find((v) => v[0] === r.vertical_id) || [])[1];
        tip.show(`${vn} · ${r.vector}`, [{ text: `Residual ${TI.f.pct(r.residual)} (${r.band})`, color: bandColor(r.band) }, { text: `Inherent ${TI.f.pct(r.inherent)}, exposure ${TI.f.pct(r.exposure)}, coverage ${TI.f.pct(r.coverage)}` }, { text: 'Click to switch the header vertical' }], mx, my);
      })
      .on('mouseleave', () => tip.hide())
      .on('click', (ev, r) => {
        const sel = document.getElementById('ti-vertical');
        if (sel) { sel.value = r.vertical_id; sel.dispatchEvent(new Event('change', { bubbles: true })); }
      })
      .style('cursor', 'pointer');
    g.selectAll('text').data(cells).join('text').attr('x', (r) => x(r.vector_id) + x.bandwidth() / 2).attr('y', (r) => y(r.vertical_id) + y.bandwidth() / 2).attr('dy', '0.35em').attr('text-anchor', 'middle')
      .style('fill', (r) => (r.residual > max * 0.55 ? 'var(--color-bg)' : 'var(--color-fg)')).style('pointer-events', 'none')
      .text((r) => (x.bandwidth() >= 40 ? TI.f.pct(r.residual) : x.bandwidth() >= 22 ? String(Math.round(r.residual * 100)) : ''));
    const yy = y(vertical());
    if (yy != null) svg.append('rect').attr('x', lw - 2).attr('y', yy - 2).attr('width', w - lw - 2).attr('height', y.bandwidth() + 4).attr('rx', 4).attr('fill', 'none').attr('stroke', 'var(--color-fg)').attr('stroke-width', 1.5).style('pointer-events', 'none');
  }

  TI.page('residual', (sec) => {
    TI.fillMarks(sec);
    const banner = sec.querySelector('#resid-banner');
    if (banner && TI.ready('residual_summary')) banner.hidden = !TI.rows('residual_summary')[0].sample;
    const rc = sec.querySelector('#resid-chart');
    if (TI.chartState(rc, ['residual_risk'])) residualChart(rc, TI.rows('residual_risk').filter((r) => r.vertical_id === vertical()));
    const rm = sec.querySelector('#resid-matrix');
    if (TI.chartState(rm, ['residual_risk', 'verticals'])) matrix(rm, TI.rows('residual_risk'), TI.rows('verticals'));
    const ta = sec.querySelector('#tbl-assets');
    if (TI.tableState(ta, ['asset_exposure'])) {
      TI.table(ta, TI.rows('asset_exposure'), [
        { field: 'host', label: 'Asset', cls: 'ti-wrap ti-mono' },
        { field: 'product', label: 'Product' },
        { field: 'version', label: 'Version', hideSm: true },
        { field: 'exposure', label: 'Exposure' },
        { field: 'site', label: 'Site', hideSm: true },
        { field: 'kev_cves', label: 'KEV CVEs', num: true, fmt: 'int' },
        { field: 'ew_cves', label: 'Early-warning', num: true, fmt: 'int', hideSm: true },
        { field: 'ransomware_linked', label: 'Ransomware', attr: { class: (r) => (r.ransomware_linked === 'Yes' ? 'ti-yes' : '') } },
        { field: 'example_cve', label: 'Example', cls: 'ti-mono' },
        { field: 'at_risk', label: 'At risk', attr: { class: (r) => (r.at_risk === 'Yes' ? 'ti-yes' : '') } },
      ], { sort: 'kev_cves', dir: 'desc' });
    }
    const tc = sec.querySelector('#tbl-controls');
    if (TI.tableState(tc, ['controls', 'residual_risk'])) {
      const rr = TI.index(TI.rows('residual_risk').filter((r) => r.vertical_id === vertical()), 'vector_id');
      TI.table(tc, TI.rows('controls'), [
        { field: 'vector', label: 'Vector' },
        { field: 'csf', label: 'NIST CSF 2.0' },
        { field: 'coverage', label: 'Control coverage', num: true, fmt: 'pct' },
        { field: 'residual', label: 'Residual (this vertical)', num: true, fmt: 'pct', source: 'residual_risk', get: (r) => (rr.get(r.vector_id) || {}).residual },
        { field: 'band', label: 'Band', source: 'residual_risk', get: (r) => (rr.get(r.vector_id) || {}).band, cls: 'ti-band', attr: { 'data-band': (r) => (rr.get(r.vector_id) || {}).band || '' } },
        { field: 'basis', label: 'Basis', cls: 'ti-wrap', hideSm: true },
      ], { sort: 'residual', dir: 'desc' });
    }
    const te = sec.querySelector('#tbl-exposure');
    if (TI.tableState(te, ['exposure_darkweb'])) {
      TI.table(te, TI.rows('exposure_darkweb'), [
        { field: 'kind', label: 'Signal' },
        { field: 'metric', label: 'Count', num: true, fmt: 'int' },
        { field: 'detail', label: 'Detail', cls: 'ti-wrap' },
        { field: 'source_tool', label: 'darknet-mcp tools', cls: 'ti-mono', hideSm: true },
        { field: 'severity', label: 'Severity', attr: { class: (r) => 'ti-sev-' + r.severity } },
        { field: 'observed', label: 'Observed', fmt: 'date', hideSm: true },
        { field: 'csf', label: 'CSF', hideSm: true },
      ], { sort: 'metric', dir: 'desc' });
    }
    drawLive(sec);
  });

  // Live exposure monitor panel. The watchlist inputs re-parametrize the live_exposure query through dash.setParams.
  function drawLive(sec) {
    const sum = TI.ready('live_exposure_summary') ? TI.rows('live_exposure_summary')[0] : null;
    const configured = sum && sum.configured;
    const tiles = sec.querySelector('#resid-live-tiles');
    const boxEl = sec.querySelector('#resid-live-box');
    const note = sec.querySelector('#resid-watch-note');
    if (tiles) tiles.hidden = !configured;
    if (boxEl) boxEl.hidden = !configured;
    if (note) {
      if (TI.failed('live_exposure')) note.textContent = 'Live exposure is unavailable: the threat-feeds service did not answer.';
      else if (TI.status('live_exposure') === 'loading' || (dash.data('live_exposure').refreshing)) note.textContent = 'Checking…';
      else if (!configured) note.textContent = 'Enter at least one domain, supplier or egress IP, then Monitor.';
      else note.textContent = `Watching ${sum.domains || '—'}${sum.vendors ? `, ${sum.vendors} suppliers` : ''}${sum.ips ? `, ${sum.ips} IPs` : ''}.`;
    }
    const t = sec.querySelector('#tbl-resid-live');
    if (t && configured && TI.tableState(t, ['live_exposure_rows'])) {
      TI.table(t, TI.rows('live_exposure_rows'), [
        { field: 'signal', label: 'Signal' },
        { field: 'what', label: 'What', cls: 'ti-wrap' },
        { field: 'detail', label: 'Detail', cls: 'ti-wrap', hideSm: true },
        { field: 'when', label: 'When', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'flag', label: 'Flag', attr: { class: (r) => (/(Passwords|Flagged|Supplier)/.test(r.flag) ? 'ti-yes' : '') } },
      ], { sort: 'when', dir: 'desc', limit: 100, empty: 'No exposure found for the current watchlist.' });
    }
  }

  // The live_exposure query's args carry {{exp_domains}}, {{exp_vendors}} and {{exp_ips}}; setParams fills them and
  // re-runs the query. Values are sanitised to comma-separated tokens so the literal substituted into the URL is safe.
  const clean = (s, rx) => String(s || '').toLowerCase().split(/[\s,;]+/).map((x) => x.trim()).filter((x) => x && rx.test(x)).join(',');
  const DOM = /^[a-z0-9.-]+\.[a-z]{2,}$/;
  const IPR = /^\d{1,3}(\.\d{1,3}){3}$/;
  function applyWatch() {
    const g = (id) => (document.getElementById(id) || {}).value || '';
    const exp_domains = clean(g('resid-domains'), DOM);
    const exp_vendors = clean(g('resid-vendors'), DOM);
    const exp_ips = clean(g('resid-ips'), IPR);
    try { localStorage.setItem('ti-exposure', JSON.stringify({ exp_domains, exp_vendors, exp_ips })); } catch { /* private mode */ }
    dash.setParams({ exp_domains, exp_vendors, exp_ips });
  }
  function fillInputs() {
    const p = dash.params();
    for (const [id, key] of [['resid-domains', 'exp_domains'], ['resid-vendors', 'exp_vendors'], ['resid-ips', 'exp_ips']]) {
      const el = document.getElementById(id);
      if (el && el !== document.activeElement && !el.value && p[key]) el.value = p[key];
    }
  }
  TI.root.addEventListener('click', (ev) => {
    if (!ev.target.closest || !ev.target.closest('#resid-watch-apply')) return;
    applyWatch();
    const note = document.getElementById('resid-watch-note');
    if (note) note.textContent = 'Checking…';
  });
  // Restore a saved watchlist once, so a reopened dashboard keeps the operator's scope.
  (function restore() {
    let saved = null;
    try { saved = JSON.parse(localStorage.getItem('ti-exposure') || 'null'); } catch { /* ignore */ }
    if (saved && (saved.exp_domains || saved.exp_vendors || saved.exp_ips)) dash.setParams(saved);
  })();
  dash.onData(() => { fillInputs(); TI.draw('residual'); });
})();
