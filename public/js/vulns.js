/* Vulnerabilities: ladder, CVSS-alone check, remediation window, edge lens, KEV, pre-KEV early warning, open-source
   disclosures against the CVE record, weakness base rates by product family, ICS. */
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
  const oss = { ahead: true, unmeasured: false };
  let brSmall = false;
  const pct1 = TI.f.pct1;
  const SOURCE_NAME = { osv: 'OSV.dev', 'oss-security': 'oss-security', hacktivity: 'HackerOne' };

  // Weakness base rates (build_baserates.py): each KEV and early-warning CVE's product family, first CWE and the
  // exploitation rate of that CWE in that family, or across all families when the family cell is small.
  function baseCols(wc) {
    const g = (r) => wc.get(r.cve) || {};
    const tip = (r) => {
      const b = g(r);
      if (!b.cve) return 'Not in the base-rate build';
      if (!b.cwe) return 'No CWE in the CVE record or the KEV entry';
      if (b.base_scope === 'none') return `${b.cwe}: fewer than 30 CVEs in the window, in its family or across all families`;
      const where = b.base_scope === 'family' ? `in ${b.family}` : 'across all families (its family holds fewer than 30)';
      const lift = b.base_scope === 'family' && b.lift != null ? `, ${TI.f.dec1(b.lift)} times the family's rate` : '';
      const more = b.more_cwes ? `; the CVE lists ${b.more_cwes} more CWE${b.more_cwes > 1 ? 's' : ''}` : '';
      return `${b.cwe} ${where}: ${pct1(b.base_rate)} of ${TI.f.int(b.base_cves)} CVEs exploited, 95% interval ${pct1(b.base_lo)} to ${pct1(b.base_hi)}${lift}${more}`;
    };
    return [
      { field: 'family', label: 'Family', source: 'weakness_cve', cls: 'ti-wrap', hideSm: true, get: (r) => g(r).family || null },
      { field: 'cwe', label: 'CWE', source: 'weakness_cve', cls: 'ti-nowrap ti-mono', hideSm: true, get: (r) => g(r).cwe || null },
      { field: 'base_rate', label: 'Base rate', source: 'weakness_cve', num: true, fmt: 'pct1', get: (r) => g(r).base_rate ?? null, attr: { title: tip } },
    ];
  }
  const after = (cols, field, extra) => { const i = cols.findIndex((c) => c.field === field); cols.splice(i < 0 ? cols.length : i + 1, 0, ...extra); return cols; };

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
      if (TI.ready('weakness_cve')) after(cols, 'cvss', baseCols(TI.index(TI.rows('weakness_cve'), 'cve')));
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
      const ewCols = [
        { field: 'cve', label: 'CVE', link: 'url', cls: 'ti-nowrap ti-mono' },
        { field: 'vendor', label: 'Vendor' },
        { field: 'product', label: 'Product', cls: 'ti-wrap' },
        { field: 'published', label: 'Published', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'stage', label: 'Stage' },
        { field: 'signals', label: 'Signals', cls: 'ti-wrap', hideSm: true },
        { field: 'epss', label: 'EPSS', num: true, fmt: 'epss' },
        { field: 'cvss', label: 'CVSS', num: true, fmt: 'dec1' },
        { field: 'edge_class', label: 'Edge class', hideSm: true },
      ];
      if (TI.ready('weakness_cve')) after(ewCols, 'cvss', baseCols(TI.index(TI.rows('weakness_cve'), 'cve')));
      if (tw.tHead && tw.tHead.rows[0].cells.length !== ewCols.length) tw.deleteTHead();
      TI.table(tw, TI.rows('early_warning'), ewCols, { sort: 'epss', dir: 'desc', countEl: sec.querySelector('#ew-count'), filter: (r) => q(r, ['cve', 'vendor', 'product', 'description']) && (!st || r.stage === st) });
    }
    drawOss(sec);
    drawBaseRates(sec);
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
  // Open-source disclosures against the CVE record (collector job osswatch, live_osswatch).
  function drawOss(sec) {
    const to = sec.querySelector('#tbl-oss');
    if (!to || !TI.tableState(to, ['live_osswatch'])) return;
    const all = TI.rows('live_osswatch') || [];
    const m = all.find((r) => r.kind === 'meta') || {};
    const asof = sec.querySelector('#oss-asof');
    if (asof) asof.textContent = m.generated ? 'collected ' + String(m.generated).slice(0, 16).replace('T', ' ') + ' UTC' : '';
    const st = TI.obj(m.by_state) || {};
    const sum = sec.querySelector('#oss-sum');
    if (sum) {
      const lead = m.with_record ? ` Of the ${TI.f.int(m.with_record)} with a CVE record, ${TI.f.int(m.lead_n)} had it published a day or more after the disclosure${m.median_lead_days != null ? ` (median ${TI.f.dec1(m.median_lead_days)} days)` : ''}, ${TI.f.int(m.same_day)} within a day, and ${TI.f.int(m.cve_first)} after the CVE.` : '';
      sum.textContent = `${TI.f.int(m.wide)} disclosures in widely deployed projects in ${TI.f.int(m.window_days)} days, ${TI.f.int(m.ahead_wide)} of them ahead of a complete CVE record: ${TI.f.int(st.none || 0)} with no CVE id, ${TI.f.int(st.reserved || 0)} with an id reserved and no record, ${TI.f.int(st.incomplete || 0)} with an incomplete record.${lead} HackerOne was read ${m.hacktivity_auth === 'API token' ? 'with an API token' : 'anonymously'}.`;
    }
    const srcs = all.filter((r) => r.kind === 'source');
    const so = sec.querySelector('#oss-sources');
    if (so && srcs.length) {
      const osv = srcs.filter((s) => String(s.id).startsWith('osv:'));
      const one = (id, name) => { const s = srcs.find((x) => x.id === id); return s ? `${name} ${s.ok ? 'answered' : 'did not answer' + (s.note ? ' (' + s.note + ')' : '')}` : null; };
      so.textContent = 'Sources this run: ' + [`OSV.dev ${osv.filter((s) => s.ok).length} of ${osv.length} ecosystems answered`, one('oss-security', 'oss-security'), one('hacktivity', 'HackerOne'),
        one('cve-services', 'CVE Services'), one('ecosystems', 'ecosyste.ms'), one('ossfuzz', 'the OSS-Fuzz project list')].filter(Boolean).join('; ') + '.';
    }
    const q = TI.search(sec.querySelector('#oss-q'));
    const src = (sec.querySelector('#oss-src') || {}).value || '';
    TI.table(to, all.filter((r) => r.kind === 'disclosure'), [
      { field: 'published', label: 'Disclosed', fmt: 'date', cls: 'ti-nowrap' },
      { field: 'source', label: 'Source', get: (r) => SOURCE_NAME[r.source] || r.source },
      { field: 'ecosystem', label: 'Ecosystem', hideSm: true },
      { field: 'project', label: 'Project', cls: 'ti-wrap' },
      { field: 'title', label: 'Title', link: 'link', cls: 'ti-wrap' },
      { field: 'cve', label: 'CVE', cls: 'ti-nowrap ti-mono' },
      { field: 'cve_label', label: 'CVE record', cls: 'ti-wrap', attr: { title: (r) => { const g = TI.list(r.cve_gaps); return g.length ? 'Missing: ' + g.join(', ') : (r.cve_checked_at ? 'Checked ' + String(r.cve_checked_at).slice(0, 16).replace('T', ' ') + ' UTC' : ''); } } },
      { field: 'lead_days', label: 'Lead, days', num: true, fmt: 'dec1' },
      { field: 'severity', label: 'Severity', hideSm: true },
      { field: 'reach_note', label: 'Reach', cls: 'ti-wrap', hideSm: true },
    ], { sort: 'published', dir: 'desc', countEl: sec.querySelector('#oss-count'), empty: 'No disclosures match.',
      filter: (r) => q(r, ['project', 'title', 'cve', 'ecosystem', 'program']) && (!src || r.source === src) && (!oss.ahead || r.ahead === true) && (oss.unmeasured ? r.reach !== 'limited' : r.reach === 'wide') });
  }
  // Weakness base rates by product family (weakness_families, weakness_rates), with bug-bounty disclosures of the same
  // CWE over 30 days from the disclosure watch when it has loaded.
  function drawBaseRates(sec) {
    const tf = sec.querySelector('#tbl-br-fam'), tr = sec.querySelector('#tbl-br'), sel = sec.querySelector('#br-family');
    if (!tf || !tr || !sel) return;
    if (TI.tableState(tf, ['weakness_families'])) {
      const fams = TI.rows('weakness_families');
      const top = fams.find((f) => f.family === 'All families') || {};
      const win = sec.querySelector('#br-window');
      if (win) win.textContent = `${top.window || ''}: ${TI.f.int(top.cves)} CVEs, ${TI.f.pct(top.cwe_coverage)} with a CWE, ${pct1(top.exploited_rate)} exploited${top.cvelist_as_of ? '; CVE List V5 as of ' + top.cvelist_as_of : ''}.`;
      if (!sel.options.length) {
        for (const f of fams.filter((x) => x.family !== 'Unclassified')) sel.append(h('option', { value: f.family, text: f.family }));
        sel.value = 'Network edge';
      }
      TI.table(tf, fams, [
        { field: 'family', label: 'Family', cls: 'ti-wrap', attr: { title: (r) => r.note || '' } },
        { field: 'cves', label: 'CVEs', num: true, fmt: 'int' },
        { field: 'cwe_coverage', label: 'With a CWE', num: true, fmt: 'pct' },
        { field: 'exploited_rate', label: 'Exploited', num: true, fmt: 'pct1' },
        { field: 'weaponized_rate', label: 'Weaponized', num: true, fmt: 'pct1', hideSm: true },
        { field: 'poc_rate', label: 'PoC public', num: true, fmt: 'pct1', hideSm: true },
        { field: 'top_cwes', label: 'Most common CWEs', cls: 'ti-wrap', hideSm: true },
      ], { onClick: (r) => { if (r.family !== 'Unclassified') { sel.value = r.family; TI.draw('vulnerabilities'); } } });
    }
    if (!TI.tableState(tr, ['weakness_rates'])) return;
    const bb = new Map();
    if (TI.ready('live_osswatch')) for (const w of (TI.rows('live_osswatch') || []).filter((r) => r.kind === 'weakness' && r.cwe)) bb.set(w.cwe, (bb.get(w.cwe) || 0) + (w.reports || 0));
    const fam = sel.value || 'Network edge';
    const q = TI.search(sec.querySelector('#br-q'));
    TI.table(tr, TI.rows('weakness_rates'), [
      { field: 'cwe', label: 'CWE', cls: 'ti-nowrap ti-mono' },
      { field: 'cwe_name', label: 'Weakness', cls: 'ti-wrap' },
      { field: 'cves', label: 'CVEs', num: true, fmt: 'int' },
      { field: 'share', label: 'Share', num: true, fmt: 'pct', hideSm: true },
      { field: 'exploited', label: 'Exploited', num: true, fmt: 'int', hideSm: true },
      { field: 'exploited_rate', label: 'Rate', num: true, fmt: 'pct1', attr: { title: (r) => `95% interval ${pct1(r.exploited_lo)} to ${pct1(r.exploited_hi)}${r.small ? '; fewer than 30 CVEs' : ''}` } },
      { field: 'interval', label: '95% interval', cls: 'ti-nowrap', hideSm: true, get: (r) => `${pct1(r.exploited_lo)} to ${pct1(r.exploited_hi)}` },
      { field: 'lift', label: 'Lift', num: true, fmt: 'dec1' },
      { field: 'weaponized_rate', label: 'Weaponized', num: true, fmt: 'pct1', hideSm: true },
      { field: 'poc_rate', label: 'PoC public', num: true, fmt: 'pct1', hideSm: true },
      { field: 'bounty_30d', label: 'Bug-bounty reports, 30 days', num: true, fmt: 'int', hideSm: true, source: 'live_osswatch', get: (r) => (bb.size ? bb.get(r.cwe) || 0 : null) },
    ], { sort: 'cves', dir: 'desc', countEl: sec.querySelector('#br-count'), filter: (r) => r.family === fam && (brSmall || !r.small) && q(r, ['cwe', 'cwe_name']) });
  }
  dash.onData(() => TI.draw('vulnerabilities'));
  TI.root.addEventListener('click', (ev) => {
    const b = ev.target.closest && ev.target.closest('#oss-ahead, #oss-unmeasured, #br-small');
    if (!b) return;
    if (b.id === 'br-small') { brSmall = !brSmall; b.setAttribute('aria-pressed', String(brSmall)); } else { const k = b.id === 'oss-ahead' ? 'ahead' : 'unmeasured'; oss[k] = !oss[k]; b.setAttribute('aria-pressed', String(oss[k])); }
    TI.draw('vulnerabilities');
  });
  TI.root.addEventListener('click', (ev) => {
    const b = ev.target.closest && ev.target.closest('#epss-notkev, #ics-vertical');
    if (!b) return;
    if (b.id === 'epss-notkev') epssNotKev = !epssNotKev; else icsVertical = !icsVertical;
    b.setAttribute('aria-pressed', String(b.id === 'epss-notkev' ? epssNotKev : icsVertical));
    TI.draw('vulnerabilities');
  });
  TI.root.addEventListener('input', (ev) => { if (['kev-q', 'ew-q', 'ics-q', 'ew-stage', 'oss-q', 'oss-src', 'br-q', 'br-family'].includes(ev.target.id)) TI.draw('vulnerabilities'); });
  TI.root.addEventListener('click', (ev) => {
    const b = ev.target.closest && ev.target.closest('#kev-edge, #kev-rw, #kev-weap, #kev-due');
    if (!b) return;
    const k = b.id.slice(4);
    flags[k] = !flags[k];
    b.setAttribute('aria-pressed', String(flags[k]));
    TI.draw('vulnerabilities');
  });
})();
