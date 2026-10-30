/* Vulnerabilities: ladder, CVSS-alone check, remediation window, edge lens, KEV, pre-KEV early warning, ICS. */
(() => {
  // CISA ICS advisory sector names for each critical-infrastructure vertical.
  const ICS_SECTOR = {
    financial: /financial/i, energy: /energy/i, water: /water/i, healthcare: /health/i, telecom: /communications/i,
    government: /government|defense/i, manufacturing: /manufacturing/i, transportation: /transportation/i,
  };
  let epssNotKev = false;
  let icsVertical = false;
  const { h } = TI;
  const flags = { edge: false, rw: false, weap: false, due: false };

  function ladder(box, rows) {
    const data = rows.slice().sort((a, b) => a.rung - b.rung);
    const height = data.length * 36 + 28;
    const { svg, w } = TI.svg(box, height);
    const lw = TI.textWidth(svg, data.map((d) => d.stage)) + 12;
    const vw = TI.textWidth(svg, data.map((d) => TI.f.int(d.cves))) + 10;
    const x = d3.scaleLog([1, d3.max(data, (d) => d.cves) * 1.05], [lw, w - vw]);
    const y = d3.scaleBand(data.map((d) => d.stage), [4, height - 24]).padding(0.28);
    const decades = [1, 10, 100, 1000, 10000, 100000, 1000000].filter((t) => t <= x.domain()[1]);
    svg.append('g').selectAll('line').data(decades).join('line').attr('class', 'ti-grid-line').attr('x1', x).attr('x2', x).attr('y1', 4).attr('y2', height - 24);
    svg.append('g').selectAll('text').data(decades).join('text').attr('x', x).attr('y', height - 8).attr('text-anchor', 'middle').text((t) => TI.f.int(t));
    const g = svg.append('g');
    g.selectAll('rect').data(data).join('rect').attr('x', lw).attr('y', (d) => y(d.stage)).attr('height', y.bandwidth()).attr('rx', 4)
      .attr('width', (d) => Math.max(2, x(Math.max(1, d.cves)) - lw))
      .style('fill', (d) => (d.rung >= 4 ? 'var(--cds-chart-status-critical)' : d.rung === 3 ? TI.color(1) : 'var(--cds-chart-muted)'));
    g.selectAll('text.l').data(data).join('text').attr('class', 'ti-lbl').attr('x', lw - 8).attr('y', (d) => y(d.stage) + y.bandwidth() / 2).attr('dy', '0.35em').attr('text-anchor', 'end').text((d) => d.stage);
    g.selectAll('text.v').data(data).join('text').attr('class', 'ti-lbl').attr('x', (d) => x(Math.max(1, d.cves)) + 6).attr('y', (d) => y(d.stage) + y.bandwidth() / 2).attr('dy', '0.35em').text((d) => TI.f.int(d.cves));
  }

  function cvss(box, rows) {
    const data = rows.slice().sort((a, b) => a.order - b.order);
    const series = [['all_cves_share', 'All CVEs, 12 months', 'var(--cds-chart-muted)'], ['kev_share', 'All KEV', TI.color(0)], ['ransomware_share', 'Ransomware-linked KEV', 'var(--cds-chart-status-critical)']];
    const height = data.length * 54 + 30;
    const { svg, w } = TI.svg(box, height);
    const lw = TI.textWidth(svg, data.map((d) => d.band)) + 12;
    const x = d3.scaleLinear([0, 0.6], [lw, w - 44]);
    const y = d3.scaleBand(data.map((d) => d.band), [4, height - 26]).padding(0.18);
    const ys = d3.scaleBand(series.map((s) => s[0]), [0, y.bandwidth()]).padding(0.12);
    svg.append('g').selectAll('line').data(x.ticks(3)).join('line').attr('class', 'ti-grid-line').attr('x1', x).attr('x2', x).attr('y1', 4).attr('y2', height - 26);
    svg.append('g').selectAll('text').data(x.ticks(3)).join('text').attr('x', x).attr('y', height - 8).attr('text-anchor', 'middle').text((t) => TI.f.pct(t));
    const tip = TI.tip(box);
    for (const [k, label, color] of series) {
      svg.append('g').selectAll('rect').data(data).join('rect').attr('x', lw).attr('y', (d) => y(d.band) + ys(k)).attr('height', ys.bandwidth()).attr('rx', 3)
        .attr('width', (d) => Math.max(1, x(Math.min(0.6, d[k] || 0)) - lw)).style('fill', color)
        .on('mousemove', (ev, d) => { const [mx, my] = d3.pointer(ev, box); tip.show(d.band, series.map((s) => ({ text: `${s[1]}: ${TI.f.pct(d[s[0]])}`, color: s[2] })), mx, my); })
        .on('mouseleave', () => tip.hide());
      svg.append('g').selectAll('text').data(data).join('text').attr('x', (d) => x(Math.min(0.6, d[k] || 0)) + 4).attr('y', (d) => y(d.band) + ys(k) + ys.bandwidth() / 2).attr('dy', '0.35em').text((d) => TI.f.pct(d[k]));
    }
    svg.append('g').selectAll('text').data(data).join('text').attr('class', 'ti-lbl').attr('x', lw - 8).attr('y', (d) => y(d.band) + y.bandwidth() / 2).attr('dy', '0.35em').attr('text-anchor', 'end').text((d) => d.band);
    const legend = h('div', { class: 'ti-legend' });
    for (const [, label, color] of series) { const sw = h('span', { class: 'ti-sw' }); sw.style.background = color; legend.append(h('span', {}, sw, label)); }
    box.append(legend);
  }

  function windowChart(box, rows) {
    const data = rows.slice().sort((a, b) => a.month.localeCompare(b.month));
    const height = 260;
    const { svg, w } = TI.svg(box, height);
    const m = { l: 34, r: 40, t: 12, b: 26 };
    const x = d3.scaleBand(data.map((d) => d.month), [m.l, w - m.r]).padding(0.25);
    const yb = d3.scaleLinear([0, d3.max(data, (d) => d.added) * 1.15], [height - m.b, m.t]);
    const yl = d3.scaleLinear([0, 24], [height - m.b, m.t]);
    svg.append('g').selectAll('line').data(yb.ticks(4)).join('line').attr('class', 'ti-grid-line').attr('x1', m.l).attr('x2', w - m.r).attr('y1', yb).attr('y2', yb);
    svg.append('g').selectAll('text').data(yb.ticks(4)).join('text').attr('x', m.l - 6).attr('y', yb).attr('dy', '0.35em').attr('text-anchor', 'end').text((t) => TI.f.int(t));
    svg.append('g').selectAll('text').data(yl.ticks(4)).join('text').attr('x', w - m.r + 6).attr('y', yl).attr('dy', '0.35em').text((t) => t + 'd');
    const tip = TI.tip(box);
    svg.append('g').selectAll('rect').data(data).join('rect').attr('x', (d) => x(d.month)).attr('width', x.bandwidth()).attr('y', (d) => yb(d.added)).attr('height', (d) => yb(0) - yb(d.added)).attr('rx', 3)
      .style('fill', 'var(--cds-chart-muted)')
      .on('mousemove', (ev, d) => { const [mx, my] = d3.pointer(ev, box); tip.show(TI.monthLabel(TI.parseDay(d.month + '-01')), [{ text: `${TI.f.int(d.added)} added, ${TI.f.int(d.edge_devices)} edge devices` }, { text: `Median remediation window ${TI.f.int(d.median_window_days)} days`, color: TI.color(0) }], mx, my); })
      .on('mouseleave', () => tip.hide());
    const line = d3.line().defined((d) => d.median_window_days != null).x((d) => x(d.month) + x.bandwidth() / 2).y((d) => yl(d.median_window_days));
    svg.append('path').datum(data).attr('d', line).attr('fill', 'none').style('stroke', TI.color(0)).attr('stroke-width', 2).attr('stroke-linecap', 'round').attr('stroke-linejoin', 'round');
    const every = Math.ceil(data.length / Math.max(2, Math.floor((w - m.l - m.r) / 64)));
    svg.append('g').selectAll('text').data(data.filter((_, i) => i % every === 0)).join('text').attr('x', (d) => x(d.month) + x.bandwidth() / 2).attr('y', height - 8).attr('text-anchor', 'middle').text((d) => d3.utcFormat('%b %y')(TI.parseDay(d.month + '-01')));
    const last = data[data.length - 1];
    if (last && last.median_window_days != null) svg.append('text').attr('class', 'ti-lbl').attr('x', x(last.month) + x.bandwidth() / 2).attr('y', yl(last.median_window_days) - 8).attr('text-anchor', 'end').text(`${last.median_window_days}-day window`);
  }

  const KEV_COLS = [
    { field: 'cve', label: 'CVE', link: 'nvd_url', cls: 'ti-nowrap ti-mono' },
    { field: 'vendor', label: 'Vendor' },
    { field: 'product', label: 'Product', cls: 'ti-wrap' },
    { field: 'date_added', label: 'Added', fmt: 'date', cls: 'ti-nowrap' },
    { field: 'due_date', label: 'Due', fmt: 'date', cls: 'ti-nowrap', hideSm: true },
    { field: 'edge_class', label: 'Edge class', hideSm: true },
    { field: 'milestone', label: 'Milestone', hideSm: true },
    { field: 'weaponized', label: 'Weaponized' },
    { field: 'epss', label: 'EPSS', num: true, fmt: 'epss' },
    { field: 'cvss', label: 'CVSS', num: true, fmt: 'dec1' },
    { field: 'ssvc_exploitation', label: 'SSVC exploitation', hideSm: true },
    { field: 'publish_to_kev_days', label: 'Days to KEV', num: true, fmt: 'int', hideSm: true },
    { field: 'data_gaps', label: 'Data gaps', hideSm: true },
  ];

  TI.page('vulnerabilities', (sec) => {
    TI.fillMarks(sec);
    const lb = sec.querySelector('#vu-ladder');
    if (TI.chartState(lb, ['vuln_ladder'])) ladder(lb, TI.rows('vuln_ladder'));
    const cb = sec.querySelector('#vu-cvss');
    if (TI.chartState(cb, ['cvss_shares'])) cvss(cb, TI.rows('cvss_shares'));
    // Weaponization timing (weapon.js).
    if (TI.weapon) TI.weapon.draw(sec);
    const wb = sec.querySelector('#vu-window');
    if (TI.chartState(wb, ['kev_monthly'])) windowChart(wb, TI.rows('kev_monthly'));
    const te = sec.querySelector('#tbl-edge');
    if (TI.tableState(te, ['edge_lens'])) {
      TI.table(te, TI.rows('edge_lens'), [
        { field: 'edge_class', label: 'Class' },
        { field: 'cves', label: 'KEV entries', num: true, fmt: 'int' },
        { field: 'added_365d', label: 'Added, 365 days', num: true, fmt: 'int' },
        { field: 'ransomware_known', label: 'Ransomware-linked', num: true, fmt: 'int' },
        { field: 'weaponized', label: 'Weaponized', num: true, fmt: 'int' },
        { field: 'median_lag_days', label: 'Median days to KEV', num: true, fmt: 'int' },
        { field: 'last_added', label: 'Last added', fmt: 'date' },
      ], { sort: 'added_365d', dir: 'desc' });
    }
    const tk = sec.querySelector('#tbl-kev');
    if (TI.tableState(tk, ['kev', 'kev_stats'])) {
      const q = TI.search(sec.querySelector('#kev-q'));
      const asOf = TI.rows('kev_stats')[0].as_of;
      // ATT&CK techniques CTID maps for the CVE, when the KEV mapping covers it (defense.js).
      const atk = TI.ready('kev_attack_cve') ? TI.index(TI.rows('kev_attack_cve'), 'cve') : new Map();
      const wpn = TI.ready('weaponization') ? TI.index(TI.rows('weaponization'), 'cve') : new Map();
      const cols = KEV_COLS.slice();
      cols.splice(8, 0, { field: 'weapon_date', label: 'Weaponized on', source: 'weaponization', fmt: 'date', cls: 'ti-nowrap', hideSm: true, get: (r) => (wpn.get(r.cve) || {}).weaponized || null },
        { field: 'attack_exploit', label: 'ATT&CK exploitation', source: 'kev_attack_cve', cls: 'ti-mono', hideSm: true, get: (r) => (atk.get(r.cve) || {}).exploit_ids || null },
        { field: 'attack_impact', label: 'ATT&CK impact', source: 'kev_attack_cve', cls: 'ti-mono ti-wrap', hideSm: true, get: (r) => (atk.get(r.cve) || {}).impact_ids || null });
      if (tk.tHead && tk.tHead.rows[0].cells.length !== cols.length) tk.deleteTHead();
      TI.table(tk, TI.rows('kev'), cols, {
        sort: 'date_added', dir: 'desc', countEl: sec.querySelector('#kev-count'),
        filter: (r) => q(r, ['cve', 'vendor', 'product', 'name']) && (!flags.edge || r.edge_class !== 'Other') && (!flags.rw || r.ransomware === 'Known') && (!flags.weap || r.weaponized === 'Yes') && (!flags.due || r.due_date >= asOf),
      });
    }
    const tw = sec.querySelector('#tbl-ew');
    if (TI.tableState(tw, ['early_warning'])) {
      const q = TI.search(sec.querySelector('#ew-q'));
      const st = sec.querySelector('#ew-stage').value;
      TI.table(tw, TI.rows('early_warning'), [
        { field: 'cve', label: 'CVE', link: 'url', cls: 'ti-nowrap ti-mono' },
        { field: 'vendor', label: 'Vendor' },
        { field: 'product', label: 'Product', cls: 'ti-wrap' },
        { field: 'published', label: 'Published', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'stage', label: 'Stage' },
        { field: 'signals', label: 'Signals', cls: 'ti-wrap', hideSm: true },
        { field: 'epss', label: 'EPSS', num: true, fmt: 'epss' },
        { field: 'cvss', label: 'CVSS', num: true, fmt: 'dec1' },
        { field: 'edge_class', label: 'Edge class', hideSm: true },
      ], { sort: 'epss', dir: 'desc', countEl: sec.querySelector('#ew-count'), filter: (r) => q(r, ['cve', 'vendor', 'product', 'description']) && (!st || r.stage === st) });
    }
    const tle = sec.querySelector('#tbl-live-epss');
    if (tle && TI.tableState(tle, ['live_epss_kev'])) {
      TI.table(tle, TI.rows('live_epss_kev'), [
        { field: 'cve', label: 'CVE', cls: 'ti-nowrap ti-mono' },
        { field: 'epss', label: 'EPSS', num: true, fmt: 'epss' },
        { field: 'percentile', label: 'Percentile', num: true, fmt: 'epss', hideSm: true },
        { field: 'in_kev', label: 'In KEV' },
        { field: 'vendor', label: 'Vendor', hideSm: true },
        { field: 'product', label: 'Product', cls: 'ti-wrap', hideSm: true },
        { field: 'ransomware', label: 'Ransomware use', hideSm: true },
      ], { sort: 'epss', dir: 'desc', countEl: sec.querySelector('#epss-count'), filter: (r) => !epssNotKev || r.in_kev === 'No', empty: 'No CVEs in the live set.' });
    }
    const ti = sec.querySelector('#tbl-ics');
    if (TI.tableState(ti, ['ics_advisories'])) {
      const q = TI.search(sec.querySelector('#ics-q'));
      const vre = ICS_SECTOR[dash.params().vertical || 'financial'];
      TI.table(ti, TI.rows('ics_advisories'), [
        { field: 'advisory_id', label: 'Advisory', link: 'url', cls: 'ti-nowrap ti-mono' },
        { field: 'published', label: 'Published', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'vendor', label: 'Vendor' },
        { field: 'title', label: 'Title', cls: 'ti-wrap' },
        { field: 'sectors', label: 'Sectors', cls: 'ti-wrap', hideSm: true },
        { field: 'cve_count', label: 'CVEs', num: true, fmt: 'int' },
        { field: 'max_cvss', label: 'Max CVSS', num: true, fmt: 'dec1' },
        { field: 'in_kev', label: 'In KEV' },
      ], { sort: 'published', dir: 'desc', countEl: sec.querySelector('#ics-count'), filter: (r) => q(r, ['vendor', 'products', 'title', 'sectors', 'cves']) && (!icsVertical || (vre && vre.test(r.sectors || ''))) });
    }
  });
  dash.onData(() => TI.draw('vulnerabilities'));
  TI.root.addEventListener('click', (ev) => {
    const b = ev.target.closest && ev.target.closest('#epss-notkev, #ics-vertical');
    if (!b) return;
    if (b.id === 'epss-notkev') epssNotKev = !epssNotKev; else icsVertical = !icsVertical;
    b.setAttribute('aria-pressed', String(b.id === 'epss-notkev' ? epssNotKev : icsVertical));
    TI.draw('vulnerabilities');
  });
  TI.root.addEventListener('input', (ev) => { if (['kev-q', 'ew-q', 'ics-q', 'ew-stage'].includes(ev.target.id)) TI.draw('vulnerabilities'); });
  TI.root.addEventListener('click', (ev) => {
    const b = ev.target.closest && ev.target.closest('#kev-edge, #kev-rw, #kev-weap, #kev-due');
    if (!b) return;
    const k = b.id.slice(4);
    flags[k] = !flags[k];
    b.setAttribute('aria-pressed', String(flags[k]));
    TI.draw('vulnerabilities');
  });
})();
