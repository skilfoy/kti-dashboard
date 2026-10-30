/* Actors: nexus mix, release diff, groups with two-curator attribution, profile and playbook, technique prevalence, campaigns. */
(() => {
  const { h, v } = TI;
  let selected = null;
  const TACTICS = ['reconnaissance', 'resource_development', 'initial_access', 'execution', 'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access', 'discovery', 'lateral_movement', 'collection', 'command_and_control', 'exfiltration', 'impact'];
  const tacLabel = (t) => t.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase()).replace(' and ', ' and ');

  function nexusChart(box, rows) {
    const data = rows.slice(0, 11);
    const height = data.length * 26 + 22;
    const { svg, w } = TI.svg(box, height);
    const lw = TI.textWidth(svg, data.map((d) => d.nexus)) + 12;
    const vw = TI.textWidth(svg, data.map((d) => String(d.groups))) + 10;
    const x = d3.scaleLinear([0, d3.max(data, (d) => d.groups)], [lw, w - vw]);
    const y = d3.scaleBand(data.map((d) => d.nexus), [4, height - 18]).padding(0.22);
    const tip = TI.tip(box);
    const g = svg.append('g');
    g.selectAll('rect.t').data(data).join('rect').attr('x', lw).attr('y', (d) => y(d.nexus)).attr('height', y.bandwidth()).attr('rx', 3)
      .attr('width', (d) => Math.max(1, x(d.groups) - lw)).style('fill', 'var(--cds-chart-muted)')
      .on('mousemove', (ev, d) => { const [mx, my] = d3.pointer(ev, box); tip.show(d.nexus, [{ text: `${d.groups} groups, ${d.state_attributed} state-attributed` }, { text: `${d.new_relationships} new technique relationships in v20` }], mx, my); })
      .on('mouseleave', () => tip.hide());
    g.selectAll('rect.s').data(data).join('rect').attr('x', lw).attr('y', (d) => y(d.nexus)).attr('height', y.bandwidth()).attr('rx', 3)
      .attr('width', (d) => (d.state_attributed ? Math.max(1, x(d.state_attributed) - lw) : 0)).style('fill', TI.color(0)).style('pointer-events', 'none');
    g.selectAll('text.l').data(data).join('text').attr('class', 'ti-lbl').attr('x', lw - 8).attr('y', (d) => y(d.nexus) + y.bandwidth() / 2).attr('dy', '0.35em').attr('text-anchor', 'end').text((d) => d.nexus);
    g.selectAll('text.v').data(data).join('text').attr('x', (d) => x(d.groups) + 6).attr('y', (d) => y(d.nexus) + y.bandwidth() / 2).attr('dy', '0.35em').text((d) => d.groups);
  }

  function tacticsChart(box, g) {
    const data = TACTICS.map((t) => ({ t, n: g['t_' + t] || 0 }));
    const height = data.length * 20 + 20;
    const { svg, w } = TI.svg(box, height);
    const lw = TI.textWidth(svg, data.map((d) => tacLabel(d.t))) + 12;
    const x = d3.scaleLinear([0, Math.max(1, d3.max(data, (d) => d.n))], [lw, w - 34]);
    const y = d3.scaleBand(data.map((d) => d.t), [2, height - 16]).padding(0.2);
    svg.append('g').selectAll('rect').data(data).join('rect').attr('x', lw).attr('y', (d) => y(d.t)).attr('height', y.bandwidth()).attr('rx', 3)
      .attr('width', (d) => (d.n ? Math.max(2, x(d.n) - lw) : 0)).style('fill', TI.color(0));
    svg.append('g').selectAll('text.l').data(data).join('text').attr('class', 'ti-lbl').attr('x', lw - 8).attr('y', (d) => y(d.t) + y.bandwidth() / 2).attr('dy', '0.35em').attr('text-anchor', 'end').text((d) => tacLabel(d.t));
    svg.append('g').selectAll('text.v').data(data).join('text').attr('x', (d) => (d.n ? x(d.n) + 5 : lw + 4)).attr('y', (d) => y(d.t) + y.bandwidth() / 2).attr('dy', '0.35em').text((d) => (d.n ? d.n : 'gap'));
  }

  function profile(sec, g) {
    const el = sec.querySelector('#actor-profile');
    TI.clear(el);
    const w = { group_id: g.group_id };
    el.append(h('div', { class: 'ti-kj-top' }, v('h2', 'attack_groups', 'name', w, g.name, 'ti-kj-title'),
      h('div', { class: 'ti-kj-meta' }, v('span', 'attack_groups', 'nexus', w, g.nexus, 'ti-badge'), v('span', 'attack_groups', 'state_link', w, g.state_link, 'ti-badge'), v('span', 'attack_groups', 'attribution_agreement', w, g.attribution_agreement, 'ti-badge'))));
    el.append(h('p', { class: 'ti-cap ti-muted' }, 'Also: ', v('span', 'attack_groups', 'aliases', w, g.aliases || 'None listed')));
    const row = (label, field, val) => [h('dt', { text: label }), v('dd', 'attack_groups', field, w, val == null || val === '' ? '—' : String(val))];
    el.append(h('dl', { class: 'ti-dl' },
      row('ATT&CK states', 'attribution_as_stated', g.attribution_as_stated),
      row('MISP country', 'misp_country', g.misp_country || 'Not stated'),
      row('CFR sponsor', 'cfr_sponsor', g.cfr_sponsor || 'Not stated'),
      row('CFR incident type', 'cfr_incident_type', g.cfr_incident_type || 'Not stated'),
      row('CFR targets', 'cfr_target_categories', g.cfr_target_categories || 'Not stated'),
      row('Motivation', 'motivation', g.motivation),
      row('Summary', 'summary', g.summary),
      row('Techniques', 'techniques', g.techniques),
      row('Software', 'software', g.software),
      row('Latest campaign', 'latest_campaign', g.latest_campaign || 'None in ATT&CK'),
      row('Campaign last seen', 'latest_campaign_last_seen', g.latest_campaign_last_seen || '—'),
      row('New in v20', 'new_in_release', g.new_in_release),
      row('Tactic gaps', 'tactic_gaps', g.tactic_gaps)));
    el.append(h('p', { class: 'ti-cap' }, h('a', { href: g.url, target: '_blank', rel: 'noopener noreferrer', text: 'ATT&CK page' }), g.misp_url ? [' · ', h('a', { href: g.misp_url, target: '_blank', rel: 'noopener noreferrer', text: 'MISP galaxy entry' })] : null));
    // ORKL report search for this group, on request (intel.js).
    if (TI.intel) TI.intel.actorEnrich(el, g);
  }

  TI.page('actors', (sec) => {
    // Unit 42 notes and Gen Threat Labs families (intel.js).
    if (TI.intel) TI.intel.actorsCards(sec);
    const nb = sec.querySelector('#ac-nexus');
    if (TI.chartState(nb, ['nexus_counts'])) nexusChart(nb, TI.rows('nexus_counts'));
    const tg = sec.querySelector('#tbl-groups');
    if (!TI.tableState(tg, ['attack_groups'])) return;
    const groups = TI.rows('attack_groups');
    const nsel = sec.querySelector('#ac-nexus-f');
    if (nsel.options.length === 1) for (const n of [...new Set(groups.map((g) => g.nexus))].sort()) nsel.append(h('option', { text: n }));
    if (!selected) selected = (groups.find((g) => g.name === 'APT38') || groups[0]).group_id;
    const q = TI.search(sec.querySelector('#ac-q'));
    const nx = nsel.value, ag = sec.querySelector('#ac-agree').value;
    const pick = (r) => { selected = r.group_id; TI.draw('actors'); sec.querySelector('#actor-profile').scrollIntoView({ block: 'nearest' }); };
    TI.table(tg, groups, [
      { field: 'name', label: 'Group' },
      { field: 'nexus', label: 'ATT&CK nexus' },
      { field: 'misp_country', label: 'MISP country', hideSm: true },
      { field: 'cfr_sponsor', label: 'CFR sponsor', hideSm: true },
      { field: 'attribution_agreement', label: 'Agreement' },
      { field: 'state_link', label: 'State link', hideSm: true },
      { field: 'motivation', label: 'Motivation', hideSm: true },
      { field: 'techniques', label: 'Techniques', num: true, fmt: 'int' },
      { field: 'new_in_release', label: 'New in v20', num: true, fmt: 'int' },
      { field: 'latest_campaign_last_seen', label: 'Last campaign', fmt: 'date', hideSm: true },
    ], { sort: 'techniques', dir: 'desc', selected, onClick: pick, countEl: sec.querySelector('#ac-count'),
      filter: (r) => q(r, ['name', 'aliases', 'nexus']) && (!nx || r.nexus === nx) && (!ag || r.attribution_agreement === ag) });
    TI.table(sec.querySelector('#tbl-diff'), groups, [
      { field: 'name', label: 'Group' },
      { field: 'nexus', label: 'Nexus' },
      { field: 'new_group', label: 'New group' },
      { field: 'new_in_release', label: 'New relationships', num: true, fmt: 'int' },
      { field: 'techniques', label: 'Techniques', num: true, fmt: 'int' },
    ], { sort: 'new_in_release', dir: 'desc', onClick: pick, filter: (r) => r.new_in_release > 0 || r.new_group === 'Yes' });
    const g = groups.find((x) => x.group_id === selected) || groups[0];
    profile(sec, g);
    const tb = sec.querySelector('#ac-tactics');
    TI.clear(tb);
    tacticsChart(tb, g);
    const tgt = sec.querySelector('#tbl-gt');
    if (TI.tableState(tgt, ['attack_group_techniques'])) {
      TI.table(tgt, TI.rows('attack_group_techniques'), [
        { field: 'technique_id', label: 'ID', cls: 'ti-mono ti-nowrap' },
        { field: 'technique', label: 'Technique', cls: 'ti-wrap' },
        { field: 'tactics', label: 'Tactics', hideSm: true },
        { field: 'new_in_release', label: 'New in v20' },
      ], { sort: 'new_in_release', dir: 'desc', filter: (r) => r.group_id === g.group_id });
    }
    const tt = sec.querySelector('#tbl-tech');
    if (TI.tableState(tt, ['attack_techniques'])) {
      const qt = TI.search(sec.querySelector('#tech-q'));
      TI.table(tt, TI.rows('attack_techniques'), [
        { field: 'technique_id', label: 'ID', link: 'url', cls: 'ti-mono ti-nowrap' },
        { field: 'name', label: 'Technique', cls: 'ti-wrap' },
        { field: 'groups_using', label: 'Groups', num: true, fmt: 'int' },
        { field: 'groups_china', label: 'China', num: true, fmt: 'int' },
        { field: 'groups_russia', label: 'Russia', num: true, fmt: 'int' },
        { field: 'groups_iran', label: 'Iran', num: true, fmt: 'int' },
        { field: 'groups_dprk', label: 'DPRK', num: true, fmt: 'int' },
        { field: 'new_users_in_release', label: 'New users', num: true, fmt: 'int', hideSm: true },
      ], { sort: 'groups_using', dir: 'desc', limit: 150, countEl: sec.querySelector('#tech-count'), filter: (r) => qt(r, ['technique_id', 'name', 'tactics']) });
    }
    const tc = sec.querySelector('#tbl-camp');
    if (TI.tableState(tc, ['attack_campaigns'])) {
      TI.table(tc, TI.rows('attack_campaigns'), [
        { field: 'name', label: 'Campaign', link: 'url' },
        { field: 'attributed_to', label: 'Attributed to' },
        { field: 'first_seen', label: 'First seen', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'last_seen', label: 'Last seen', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'summary', label: 'Summary', cls: 'ti-wrap', hideSm: true },
      ], { sort: 'last_seen', dir: 'desc' });
    }
  });
  dash.onData(() => TI.draw('actors'));
  TI.root.addEventListener('input', (ev) => { if (['ac-q', 'ac-nexus-f', 'ac-agree', 'tech-q'].includes(ev.target.id)) TI.draw('actors'); });
})();
