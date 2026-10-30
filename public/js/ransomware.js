/* Ransomware: claim volumes by group (small multiples), sector shift, countries, and the group table. */
(() => {
  function multiples(box, rows) {
    const groups = [...new Set(rows.map((r) => r.group))].filter((g) => g !== 'all other groups');
    const months = [...new Set(rows.map((r) => r.month))].sort();
    const W = Math.max(280, box.clientWidth || 600);
    const cols = W > 1100 ? 5 : W > 800 ? 4 : W > 520 ? 3 : 2;
    const pw = W / cols, ph = 92;
    const rowsN = Math.ceil(groups.length / cols);
    const { svg } = TI.svg(box, rowsN * ph + 8);
    const max = d3.max(rows.filter((r) => r.group !== 'all other groups'), (r) => r.claims) || 1;
    const tip = TI.tip(box);
    groups.forEach((g, i) => {
      const ox = (i % cols) * pw, oy = Math.floor(i / cols) * ph;
      const x = d3.scaleBand(months, [ox + 6, ox + pw - 10]).padding(0.15);
      const y = d3.scaleLinear([0, max], [oy + ph - 14, oy + 22]);
      const data = rows.filter((r) => r.group === g);
      svg.append('text').attr('class', 'ti-lbl').attr('x', ox + 6).attr('y', oy + 12).text(g);
      svg.append('line').attr('class', 'ti-axis-line').attr('x1', ox + 6).attr('x2', ox + pw - 10).attr('y1', y(0)).attr('y2', y(0));
      svg.append('g').selectAll('rect').data(data).join('rect')
        .attr('x', (d) => x(d.month)).attr('width', x.bandwidth()).attr('y', (d) => y(d.claims)).attr('height', (d) => y(0) - y(d.claims)).attr('rx', 1.5)
        .style('fill', (d) => (d.partial_month === 'Yes' ? 'var(--cds-chart-muted)' : TI.color(0)))
        .on('mousemove', (ev, d) => { const [mx, my] = d3.pointer(ev, box); tip.show(`${g} · ${TI.monthLabel(TI.parseDay(d.month + '-01'))}${d.partial_month === 'Yes' ? ' (partial)' : ''}`, [{ text: `${TI.f.int(d.claims)} claims` }], mx, my); })
        .on('mouseleave', () => tip.hide());
      svg.append('text').attr('x', ox + 6).attr('y', oy + ph - 2).text(d3.utcFormat('%b %y')(TI.parseDay(months[0] + '-01')));
      svg.append('text').attr('x', ox + pw - 10).attr('y', oy + ph - 2).attr('text-anchor', 'end').text(d3.utcFormat('%b %y')(TI.parseDay(months[months.length - 1] + '-01')));
    });
  }

  function sectors(box, rows) {
    const data = rows.slice().sort((a, b) => (a.sector === 'Not identified') - (b.sector === 'Not identified') || b.claims_last_90d - a.claims_last_90d);
    const height = data.length * 26 + 24;
    const { svg, w } = TI.svg(box, height);
    const lw = TI.textWidth(svg, data.map((d) => d.sector)) + 12;
    const vw = TI.textWidth(svg, data.map((d) => TI.f.int(d.claims_last_90d))) + 10;
    const x = d3.scaleLinear([0, d3.max(data, (d) => Math.max(d.claims_last_90d, d.claims_prior_90d))], [lw, w - vw]);
    const y = d3.scaleBand(data.map((d) => d.sector), [4, height - 20]).padding(0.2);
    const tip = TI.tip(box);
    svg.append('g').selectAll('rect.a').data(data).join('rect').attr('x', lw).attr('y', (d) => y(d.sector)).attr('height', y.bandwidth() * 0.62).attr('rx', 3)
      .attr('width', (d) => Math.max(1, x(d.claims_last_90d) - lw))
      .style('fill', (d) => (d.sector === 'Financial Services' ? 'var(--cds-chart-status-critical)' : TI.color(0)))
      .on('mousemove', (ev, d) => { const [mx, my] = d3.pointer(ev, box); tip.show(d.sector, [{ text: `Last 90 days: ${TI.f.int(d.claims_last_90d)}` }, { text: `Prior 90 days: ${TI.f.int(d.claims_prior_90d)}` }], mx, my); })
      .on('mouseleave', () => tip.hide());
    svg.append('g').selectAll('rect.b').data(data).join('rect').attr('x', lw).attr('y', (d) => y(d.sector) + y.bandwidth() * 0.72).attr('height', y.bandwidth() * 0.22).attr('rx', 1)
      .attr('width', (d) => Math.max(1, x(d.claims_prior_90d) - lw)).style('fill', 'var(--cds-chart-muted)');
    svg.append('g').selectAll('text.l').data(data).join('text').attr('class', 'ti-lbl').attr('x', lw - 8).attr('y', (d) => y(d.sector) + y.bandwidth() / 2).attr('dy', '0.35em').attr('text-anchor', 'end').text((d) => d.sector);
    svg.append('g').selectAll('text.v').data(data).join('text').attr('x', (d) => x(d.claims_last_90d) + 6).attr('y', (d) => y(d.sector) + y.bandwidth() * 0.31).attr('dy', '0.35em').text((d) => TI.f.int(d.claims_last_90d));
  }

  TI.page('ransomware', (sec) => {
    TI.fillMarks(sec);
    // SEC 8-K disclosures, the leak-site cross-check and Ransomwhere payments (intel.js).
    if (TI.intel) TI.intel.ransomwareCards(sec);
    const mb = sec.querySelector('#rw-multiples');
    if (TI.chartState(mb, ['ransomware_monthly'])) multiples(mb, TI.rows('ransomware_monthly'));
    const sb = sec.querySelector('#rw-sectors');
    if (TI.chartState(sb, ['ransomware_sectors'])) sectors(sb, TI.rows('ransomware_sectors'));
    const tc = sec.querySelector('#tbl-rw-countries');
    if (TI.tableState(tc, ['ransomware_countries'])) {
      TI.table(tc, TI.rows('ransomware_countries'), [
        { field: 'country', label: 'Country' },
        { field: 'claims_last_90d', label: 'Last 90 days', num: true, fmt: 'int' },
        { field: 'claims_prior_90d', label: 'Prior 90 days', num: true, fmt: 'int' },
      ], { sort: 'claims_last_90d', dir: 'desc' });
    }
    const tg = sec.querySelector('#tbl-rw-groups');
    if (TI.tableState(tg, ['ransomware_groups'])) {
      const q = TI.search(sec.querySelector('#rw-q'));
      TI.table(tg, TI.rows('ransomware_groups'), [
        { field: 'group', label: 'Group' },
        { field: 'claims_last_90d', label: 'Last 90 days', num: true, fmt: 'int' },
        { field: 'claims_prior_90d', label: 'Prior 90 days', num: true, fmt: 'int' },
        { field: 'change', label: 'Change', num: true, fmt: 'signedInt' },
        { field: 'status', label: 'Status' },
        { field: 'top_sector', label: 'Top sector', hideSm: true },
        { field: 'top_country', label: 'Top country', hideSm: true },
        { field: 'us_share', label: 'US share', num: true, fmt: 'pct', hideSm: true },
        { field: 'financial_claims_90d', label: 'Financial, 90 days', num: true, fmt: 'int' },
        { field: 'first_seen', label: 'First seen', fmt: 'date', hideSm: true },
        { field: 'claims_all_time', label: 'All claims', num: true, fmt: 'int', hideSm: true },
      ], { sort: 'claims_last_90d', dir: 'desc', countEl: sec.querySelector('#rw-count'), filter: (r) => q(r, ['group', 'top_sector', 'top_country']) });
    }
  });
  dash.onData(() => TI.draw('ransomware'));
  TI.root.addEventListener('input', (ev) => { if (ev.target.id === 'rw-q' || ev.target.id === 'sec8k-kind') TI.draw('ransomware'); });
})();
