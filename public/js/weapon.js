/* Weaponization timing on the Vulnerabilities page: how fast public PoCs and weaponization follow publication, how
   often weaponization beats CISA's KEV listing, and which early-warning CVEs are weaponized but not yet in KEV
   (Automating CTI p340-345; Ali and Bhatti p175-178). */
(() => {
  const med = (xs) => { const a = xs.filter((x) => x != null && isFinite(x)).sort((p, q) => p - q); if (!a.length) return null; const m = a.length >> 1; return a.length % 2 ? a[m] : (a[m - 1] + a[m]) / 2; };

  dash.calc('weapon_lags', {
    title: 'Days from publication to PoC, weaponization and KEV, by year',
    description: 'For KEV CVEs published since KEV opened (3 November 2021), by publication year: medians of days from CVE publication to the first public GitHub repository naming the CVE (PoC-in-GitHub), to the first Nuclei template or Metasploit exploit module (weaponized), and to the KEV listing; and how many were weaponized before, or on or after, the KEV listing. Older CVEs are left out because KEV began with a backfill, so their lag measures the catalog\'s start date.',
    inputs: ['weaponization'],
    fn: (rows) => {
      const by = new Map();
      for (const r of rows) {
        if (r.in_kev !== 'Yes' || r.cohort !== 'Since KEV launch' || !r.published) continue;
        const y = +String(r.published).slice(0, 4);
        if (y < 2022) continue;  // Nov-Dec 2021 is a two-month cohort
        if (!by.has(y)) by.set(y, []);
        by.get(y).push(r);
      }
      return [...by.entries()].sort((a, b) => a[0] - b[0]).map(([y, rs]) => {
        const first = rs.filter((r) => r.weapon_before_kev === 'Yes').length, after = rs.filter((r) => r.weapon_before_kev === 'No').length;
        return { year: String(y), kev_cves: rs.length, with_poc: rs.filter((r) => r.poc_first).length, with_weapon: rs.filter((r) => r.weaponized).length,
          med_pub_poc: med(rs.map((r) => r.days_pub_to_poc)), med_pub_weapon: med(rs.map((r) => r.days_pub_to_weapon)), med_pub_kev: med(rs.map((r) => r.days_pub_to_kev)),
          weapon_first: first, weapon_after: after, weapon_first_share: first + after ? Math.round((first / (first + after)) * 1000) / 1000 : null };
      });
    },
  });

  dash.calc('weapon_summary', {
    title: 'Weaponization against KEV, summary',
    description: 'KEV CVEs published since KEV opened that have a public weaponization date; how many were weaponized before the KEV listing and the median lead in days among those; early-warning CVEs (not in KEV) with a weaponization date, and those weaponized in the 90 days to the build date.',
    inputs: ['weaponization'],
    fn: (rows) => {
      const since = rows.filter((r) => r.in_kev === 'Yes' && r.cohort === 'Since KEV launch' && r.weapon_before_kev);
      const first = since.filter((r) => r.weapon_before_kev === 'Yes');
      const ew = rows.filter((r) => r.in_kev === 'No' && r.weaponized);
      return [{ kev_both: since.length, kev_first: first.length, kev_first_share: since.length ? Math.round((first.length / since.length) * 1000) / 1000 : null,
        median_lead_first: med(first.map((r) => r.weapon_lead_days)), ew_weaponized: ew.length, ew_weaponized_90d: ew.filter((r) => r.days_since_weapon != null && r.days_since_weapon <= 90).length,
        ew_poc_only: rows.filter((r) => r.in_kev === 'No' && r.poc_first && !r.weaponized).length }];
    },
  });

  // Three medians per publication year, so the shrinking window reads at a glance.
  function lagChart(box, rows) {
    const series = [['med_pub_poc', 'First public PoC repository', TI.color(1)], ['med_pub_weapon', 'Weaponized (Nuclei or Metasploit)', TI.color(0)], ['med_pub_kev', 'Listed in KEV', 'var(--cds-chart-muted)']];
    const rowH = 3 * 11 + 16;
    const height = rows.length * rowH + 34;
    const { svg, w } = TI.svg(box, height);
    const labels = rows.map((d) => `${d.year} (${d.kev_cves})`);
    const lw = TI.textWidth(svg, labels) + 14;
    const rw = TI.textWidth(svg, rows.map((d) => `${TI.f.pct(d.weapon_first_share)} weaponized first`)) + 14;
    const max = d3.max(rows, (d) => d3.max(series, ([f]) => d[f] || 0)) || 1;
    const x = d3.scaleLinear([0, max * 1.08], [lw, w - rw - 30]);
    const tip = TI.tip(box);
    const g = svg.append('g');
    rows.forEach((d, i) => {
      const y0 = 6 + i * rowH;
      g.append('text').attr('class', 'ti-lbl').attr('x', lw - 8).attr('y', y0 + 17).attr('text-anchor', 'end').text(labels[i]);
      series.forEach(([f, l, c], j) => {
        const v = d[f];
        g.append('rect').attr('x', lw).attr('y', y0 + j * 11).attr('height', 9).attr('rx', 2).attr('width', v == null ? 0 : Math.max(1, x(v) - lw)).style('fill', c)
          .on('mousemove', (ev) => { const [mx, my] = d3.pointer(ev, box); tip.show(`CVEs published in ${d.year}`, [{ color: c, text: `${l}: median ${v == null ? '—' : TI.f.int(v)} days after publication` }, { text: `${TI.f.int(d.kev_cves)} in KEV; ${TI.f.int(d.with_poc)} with a PoC repository, ${TI.f.int(d.with_weapon)} weaponized` }, { text: `${TI.f.int(d.weapon_first)} weaponized before the KEV listing, ${TI.f.int(d.weapon_after)} on or after` }], mx, my); })
          .on('mouseleave', () => tip.hide());
        if (v != null) g.append('text').attr('x', x(v) + 4).attr('y', y0 + j * 11 + 8).style('font-size', '10px').text(TI.f.int(Math.round(v)));
      });
      g.append('text').attr('class', 'ti-lbl').attr('x', w - rw + 4).attr('y', y0 + 17).text(`${TI.f.pct(d.weapon_first_share)} weaponized first`);
    });
    svg.append('g').attr('transform', `translate(0,${height - 26})`).call(d3.axisBottom(x).ticks(6).tickSizeOuter(0)).call((a) => a.select('.domain').attr('class', 'ti-axis-line'));
    const leg = box.parentElement.querySelector('.ti-legend');
    if (leg && !leg.childNodes.length) { for (const [, l, c] of series) { const sw = TI.h('span', { class: 'ti-sw' }); sw.style.background = c; leg.append(TI.h('span', {}, sw, l)); } leg.append(TI.h('span', { text: '· median days after CVE publication; hover a bar for counts' })); }
  }

  TI.weapon = {
    draw(sec) {
      const box = sec.querySelector('#vu-weapon');
      if (!box) return;
      if (TI.chartState(box, ['weapon_lags'])) lagChart(box, TI.rows('weapon_lags'));
      const note = sec.querySelector('#vw-note');
      if (note && TI.ready('weapon_summary')) {
        const s = TI.rows('weapon_summary')[0] || {};
        const v = (f, t) => TI.v('span', 'weapon_summary', f, null, t);
        TI.clear(note).append('Of ', v('kev_both', TI.f.int(s.kev_both)), ' KEV CVEs published since KEV opened that have a public weaponization date, ', v('kev_first', TI.f.int(s.kev_first)),
          ' (', v('kev_first_share', TI.f.pct(s.kev_first_share)), ') were weaponized before CISA listed them, by a median ', v('median_lead_first', TI.f.int(s.median_lead_first)),
          ' days. ', v('ew_weaponized', TI.f.int(s.ew_weaponized)), ' early-warning CVEs outside KEV are weaponized, ', v('ew_weaponized_90d', TI.f.int(s.ew_weaponized_90d)), ' of them in the last 90 days.');
      }
      const pv = sec.querySelector('#vw-prov');
      if (pv && TI.ready('weaponization_sources')) {
        TI.clear(pv).append('Read at commits: ');
        TI.rows('weaponization_sources').forEach((r, i) => {
          if (i) pv.append(' · ');
          pv.append(TI.h('a', { href: r.commit ? `${r.url}/tree/${r.commit}` : r.url, target: '_blank', rel: 'noopener noreferrer', text: r.name }), ` ${String(r.commit || '').slice(0, 10)} (${String(r.commit_date || '').slice(0, 10)}, ${r.terms})`);
        });
      }
      const wf = sec.querySelector('#tbl-weap-first');
      if (TI.tableState(wf, ['weaponization'])) {
        const q = TI.search(sec.querySelector('#weap-q'));
        TI.table(wf, TI.rows('weaponization').map((r) => ({ ...r, url: 'https://nvd.nist.gov/vuln/detail/' + r.cve })), [
          { field: 'cve', label: 'CVE', link: 'url', cls: 'ti-mono ti-nowrap' },
          { field: 'vendor', label: 'Vendor' },
          { field: 'product', label: 'Product', cls: 'ti-wrap' },
          { field: 'published', label: 'Published', fmt: 'date', cls: 'ti-nowrap', hideSm: true },
          { field: 'poc_first', label: 'First PoC repo', fmt: 'date', cls: 'ti-nowrap', hideSm: true },
          { field: 'nuclei_added', label: 'Nuclei', fmt: 'date', cls: 'ti-nowrap' },
          { field: 'msf_added', label: 'Metasploit', fmt: 'date', cls: 'ti-nowrap' },
          { field: 'kev_added', label: 'KEV', fmt: 'date', cls: 'ti-nowrap' },
          { field: 'weapon_lead_days', label: 'Lead, days', num: true, fmt: 'int' },
          { field: 'ransomware', label: 'Ransomware', hideSm: true },
        ], { sort: 'kev_added', dir: 'desc', countEl: sec.querySelector('#weap-first-count'),
          filter: (r) => r.in_kev === 'Yes' && r.cohort === 'Since KEV launch' && r.weapon_before_kev === 'Yes' && q(r, ['cve', 'vendor', 'product']) });
      }
      const we = sec.querySelector('#tbl-weap-ew');
      if (TI.tableState(we, ['weaponization', 'early_warning'])) {
        const ew = TI.index(TI.rows('early_warning'), 'cve');
        TI.table(we, TI.rows('weaponization').filter((r) => r.in_kev === 'No' && r.weaponized).map((r) => ({ ...r, url: 'https://nvd.nist.gov/vuln/detail/' + r.cve,
          epss: (ew.get(r.cve) || {}).epss, signals: (ew.get(r.cve) || {}).signals })), [
          { field: 'cve', label: 'CVE', link: 'url', cls: 'ti-mono ti-nowrap' },
          { field: 'vendor', label: 'Vendor' },
          { field: 'product', label: 'Product', cls: 'ti-wrap' },
          { field: 'published', label: 'Published', fmt: 'date', cls: 'ti-nowrap', hideSm: true },
          { field: 'poc_first', label: 'First PoC repo', fmt: 'date', cls: 'ti-nowrap', hideSm: true },
          { field: 'weaponized', label: 'Weaponized', fmt: 'date', cls: 'ti-nowrap' },
          { field: 'days_since_weapon', label: 'Days since', num: true, fmt: 'int' },
          { field: 'epss', label: 'EPSS', num: true, fmt: 'epss' },
          { field: 'signals', label: 'Other signals', cls: 'ti-wrap', hideSm: true },
        ], { sort: 'weaponized', dir: 'desc', countEl: sec.querySelector('#weap-ew-count') });
      }
    },
  };
  TI.root.addEventListener('input', (ev) => { if (ev.target.id === 'weap-q') TI.draw('vulnerabilities'); });
})();
