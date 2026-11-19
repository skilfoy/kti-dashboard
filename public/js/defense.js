/* Defense: threat-informed defense for the selected vertical. Which ATT&CK techniques to defend first, where public
   detection and test content runs out, which telemetry and controls buy down the most of the threat model, what to
   hunt for next, and an ATT&CK Navigator layer of the result. */

// ---- Calculations (every vertical computed; the page shows the selected one) ----
(() => {
  // The theaters whose ThreatCon stands for a state nexus as ATT&CK states it. A nexus with no theater here (Vietnam,
  // Turkey, "Not stated") carries only the background weight.
  const NEXUS_THEATERS = {
    Iran: ['T-HRM', 'T-RSY', 'T-LEV'], Russia: ['T-UKR', 'T-EUH', 'T-BAL'], China: ['T-TWN', 'T-SCS'], 'North Korea': ['T-KOR'],
    Pakistan: ['T-AFP', 'T-SAS'], India: ['T-SAS'], Lebanon: ['T-LEV'], 'Gaza / Hamas': ['T-LEV'],
  };
  const BACKGROUND = 0.2, IN_SCOPE = 0.6, TOP = 100;
  const r3 = (x) => Math.round(x * 1000) / 1000;
  const byVertical = (rows) => { const m = new Map(); for (const r of rows) { if (!m.has(r.vertical_id)) m.set(r.vertical_id, []); m.get(r.vertical_id).push(r); } return m; };
  const parent = (t) => String(t).split('.')[0];
  // Group -> techniques it uses, with each sub-technique also counted for its parent (a parent row stands for its family).
  const usesByTechnique = (pairs) => {
    const m = new Map();
    const add = (t, g) => { if (!m.has(t)) m.set(t, new Set()); m.get(t).add(g); };
    for (const p of pairs) { add(p.technique_id, p.group_id); if (String(p.technique_id).includes('.')) add(parent(p.technique_id), p.group_id); }
    return m;
  };

  dash.calc('defense_group_weight', {
    title: 'Threat-model weight of each ATT&CK group, by vertical',
    description: 'For each vertical, each ATT&CK group weighs the largest of three terms. State nexus: the highest calibrated ThreatCon / 5 among the theaters its stated nexus maps to (Iran: Hormuz, Red Sea, Levant; Russia: Ukraine, Europe hybrid, Balkans; China: Taiwan Strait, South China Sea; North Korea: Korean Peninsula; Pakistan: Af-Pak, South Asia; India: South Asia; Lebanon and Hamas: Levant), halved when neither ATT&CK\'s description nor the MISP galaxy names one of the vertical\'s sectors as a target. Financial motive: for groups whose motivation includes Financial, the higher calibrated level of the Ransomware & malware and Fraud vectors / 5, times 0.75 when no sector of the vertical is named. Background: 0.2. Groups at 0.6 or more are in scope.',
    inputs: ['attack_groups', 'theaters', 'theater_calibrated', 'vector_calibrated', 'verticals', 'defense_group_sectors'],
    fn: (groups, theaters, tcal, vcal, verticals, sectors) => {
      const tname = new Map(theaters.map((t) => [t.theater_id, t.name]));
      const sec = new Map(sectors.map((r) => [r.group_id + '|' + r.vertical_id, r]));
      const tc = byVertical(tcal), vc = byVertical(vcal);
      const out = [];
      for (const v of verticals) {
        const tl = new Map((tc.get(v.vertical_id) || []).map((r) => [r.theater_id, r.calibrated]));
        const vl = new Map((vc.get(v.vertical_id) || []).map((r) => [r.vector_id, r.calibrated]));
        for (const g of groups) {
          const st = sec.get(g.group_id + '|' + v.vertical_id);
          let wn = 0, nb = '';
          for (const th of NEXUS_THEATERS[g.nexus] || []) {
            const lv = tl.get(th);
            if (lv != null && lv / 5 > wn) { wn = lv / 5; nb = `${g.nexus}: ${tname.get(th) || th} at ${lv}`; }
          }
          if (wn && !st) { wn /= 2; nb += ', no sector of this vertical named'; }
          let wc = 0, cb = '';
          if (/Financial/.test(g.motivation || '')) {
            for (const [id, label] of [['V-RAN', 'Ransomware & malware'], ['V-FRA', 'Fraud']]) {
              const lv = vl.get(id);
              if (lv != null && lv / 5 > wc) { wc = lv / 5; cb = `Financial motive: ${label} at ${lv}`; }
            }
            if (wc && !st) { wc *= 0.75; cb += ', no sector of this vertical named'; }
          }
          const weight = Math.max(wn, wc, BACKGROUND);
          const kind = wn <= BACKGROUND && wc <= BACKGROUND ? 'Background' : wn >= wc ? 'State nexus' : 'Financial motive';
          out.push({ key: v.vertical_id + '|' + g.group_id, vertical_id: v.vertical_id, group_id: g.group_id, name: g.name, nexus: g.nexus, motivation: g.motivation,
            weight: r3(weight), basis_kind: kind, basis: kind === 'Background' ? 'Background weight' : kind === 'State nexus' ? nb : cb,
            sector_named: st ? 'Yes' : 'No', sector_source: st ? st.source : null, sector_evidence: st ? st.evidence : null,
            in_scope: weight >= IN_SCOPE ? 'Yes' : 'No', techniques: g.techniques });
        }
      }
      return out;
    },
  });

  dash.calc('defense_priority', {
    title: 'Defensive priority of each ATT&CK technique, by vertical',
    description: 'The CTID Top ATT&CK Techniques method with its components recomputed from current ATT&CK v20, this dashboard\'s threat model and current public detection content. Priority = prevalence + choke point + actionability, each 0 to 1 (maximum 3). Prevalence = mean of threat use (sum of the weights of groups using the technique or a sub-technique over all group weight, scaled to the most-used technique) and report breadth (share of the CTID TIE dataset\'s CTI reports that observe it, scaled to the most-reported). Choke point = CTID\'s score (0 where CTID scored none). Actionability = mean of min(1, ATT&CK mitigations / 3) and min(1, (Sigma + Elastic + Splunk rules + ATT&CK analytics) / 10). Gap flags: no public rule in Sigma, Elastic or Splunk; no Atomic Red Team test. Shift = rank under equal group weights (plain ATT&CK frequency) minus rank for the vertical. Pre-compromise = every tactic is Reconnaissance or Resource Development, activity outside the defended estate.',
    inputs: ['defense_techniques', 'attack_group_techniques', 'defense_group_weight'],
    fn: (tech, pairs, gw) => {
      const uses = usesByTechnique(pairs);
      const maxShare = Math.max(1e-9, ...tech.map((t) => +t.tie_share || 0));
      const action = (t) => (Math.min(1, (+t.mitigations || 0) / 3) + Math.min(1, ((+t.community || 0) + (+t.attack_analytics || 0)) / 10)) / 2;
      // Baseline: the same score with every group weighing 1, plain ATT&CK frequency (Thomas p202-206). A vertical's
      // shift is how far its threat model moves a technique against that baseline.
      const maxUse = Math.max(1, ...tech.map((t) => (uses.get(t.technique_id) || new Set()).size));
      const baseRank = new Map(tech.map((t) => [t.technique_id, ((uses.get(t.technique_id) || new Set()).size / maxUse + (+t.tie_share || 0) / maxShare) / 2 + (+t.choke || 0) + action(t)])
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([id], i) => [id, i + 1]));
      const PRE = new Set(['Reconnaissance', 'Resource Development']);
      const out = [];
      for (const [vid, rows] of byVertical(gw)) {
        const w = new Map(rows.map((r) => [r.group_id, +r.weight]));
        const name = new Map(rows.map((r) => [r.group_id, r.name]));
        const W = rows.reduce((s, r) => s + +r.weight, 0) || 1;
        const raw = new Map(tech.map((t) => [t.technique_id, [...(uses.get(t.technique_id) || [])].reduce((s, g) => s + (w.get(g) || 0), 0) / W]));
        const maxRaw = Math.max(1e-9, ...raw.values());
        const list = tech.map((t) => {
          const users = [...(uses.get(t.technique_id) || [])].filter((g) => w.has(g));
          const inScope = users.filter((g) => w.get(g) >= IN_SCOPE).sort((a, b) => w.get(b) - w.get(a) || String(name.get(a)).localeCompare(String(name.get(b))));
          const pThreat = raw.get(t.technique_id) / maxRaw;
          const breadth = (+t.tie_share || 0) / maxShare;
          const prevalence = (pThreat + breadth) / 2;
          const choke = +t.choke || 0;
          const act = action(t);
          const pre = String(t.tactics || '').split(',').map((x) => x.trim()).filter(Boolean).every((x) => PRE.has(x));
          const noRule = !(+t.community > 0), noTest = !(+t.atomic > 0);
          return { key: vid + '|' + t.technique_id, vertical_id: vid, technique_id: t.technique_id, name: t.name, tactics: t.tactics, is_sub: t.is_sub, url: t.url,
            p_threat: r3(pThreat), breadth: r3(breadth), prevalence: r3(prevalence), choke: r3(choke), actionability: r3(act), priority: r3(prevalence + choke + act),
            pre_compromise: pre ? 'Yes' : 'No', base_rank: baseRank.get(t.technique_id),
            groups_all: users.length, groups_in_scope: inScope.length, top_groups: inScope.slice(0, 4).map((g) => name.get(g)).join(', '),
            community: +t.community || 0, sigma: +t.sigma || 0, elastic: +t.elastic || 0, splunk: +t.splunk || 0, atomic: +t.atomic || 0, mitigations: +t.mitigations || 0,
            analytics: +t.attack_analytics || 0, kev_cves: +t.kev_cves || 0, ransom_top10: t.ransom_top10, platforms: t.platforms,
            gap: noRule && noTest ? 'No rule, no test' : noRule ? 'No public rule' : noTest ? 'No Atomic test' : '' };
        });
        list.sort((a, b) => b.priority - a.priority || b.prevalence - a.prevalence || a.technique_id.localeCompare(b.technique_id));
        list.forEach((r, i) => { r.rank = i + 1; r.shift = r.base_rank - r.rank; });
        out.push(...list);
      }
      return out;
    },
  });

  dash.calc('defense_actor_cov', {
    title: 'Public detection and test coverage of in-scope groups, by vertical',
    description: 'For each in-scope group (weight 0.6 or more), the techniques inside the estate ATT&CK records it using (Reconnaissance-only and Resource Development-only techniques counted apart), how many have at least one Sigma, Elastic or Splunk rule and how many have an Atomic Red Team test, and the uncovered techniques ordered by CTI report breadth.',
    inputs: ['defense_group_weight', 'attack_group_techniques', 'defense_techniques'],
    fn: (gw, pairs, tech) => {
      const t = new Map(tech.map((x) => [x.technique_id, x]));
      const by = new Map();
      for (const p of pairs) { if (!by.has(p.group_id)) by.set(p.group_id, new Set()); by.get(p.group_id).add(p.technique_id); }
      const out = [];
      for (const g of gw) {
        if (g.in_scope !== 'Yes') continue;
        const all = [...(by.get(g.group_id) || [])].filter((x) => t.has(x));
        const ts = all.filter((x) => !String(t.get(x).tactics || '').split(',').map((y) => y.trim()).filter(Boolean).every((y) => y === 'Reconnaissance' || y === 'Resource Development'));
        const det = ts.filter((x) => +t.get(x).community > 0), tst = ts.filter((x) => +t.get(x).atomic > 0);
        const gaps = ts.filter((x) => !(+t.get(x).community > 0)).sort((a, b) => (+t.get(b).tie_share || 0) - (+t.get(a).tie_share || 0) || a.localeCompare(b));
        out.push({ key: g.key, vertical_id: g.vertical_id, group_id: g.group_id, name: g.name, nexus: g.nexus, basis: g.basis, weight: g.weight, sector_evidence: g.sector_evidence,
          techniques: ts.length, pre_compromise: all.length - ts.length, detected: det.length, tested: tst.length, detected_share: ts.length ? r3(det.length / ts.length) : null,
          tested_share: ts.length ? r3(tst.length / ts.length) : null, gap_count: gaps.length, gap_ids: gaps.slice(0, 10).join(', ') });
      }
      return out;
    },
  });

  dash.calc('defense_tactic_cov', {
    title: 'Threat-weighted public coverage by tactic, by vertical',
    description: 'For each ATT&CK v20 tactic, the share of threat use (the prevalence calculation\'s threat-use term, summed over the tactic\'s leaf techniques: sub-techniques, and techniques that have none) that falls on techniques with at least one public rule, and on techniques with an Atomic Red Team test. Leaves keep a parent\'s rolled-up rule count from hiding an uncovered sub-technique. A technique serving several tactics counts in each.',
    inputs: ['defense_priority'],
    fn: (pr) => {
      const hasSubs = new Set(pr.filter((r) => r.is_sub === 'Yes').map((r) => parent(r.technique_id)));
      const ORDER = ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Stealth', 'Defense Impairment', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact'];
      const out = [];
      for (const [vid, rows] of byVertical(pr)) {
        const acc = new Map();
        for (const r of rows) {
          if (!(r.p_threat > 0) || hasSubs.has(r.technique_id)) continue;  // leaves only
          for (const tac of String(r.tactics || '').split(',').map((s) => s.trim()).filter(Boolean)) {
            const a = acc.get(tac) || { n: 0, w: 0, wd: 0, wt: 0, gaps: 0 };
            a.n += 1; a.w += r.p_threat; if (r.community > 0) a.wd += r.p_threat; else a.gaps += 1; if (r.atomic > 0) a.wt += r.p_threat;
            acc.set(tac, a);
          }
        }
        for (const tac of ORDER) {
          const a = acc.get(tac);
          if (!a) continue;
          out.push({ key: vid + '|' + tac, vertical_id: vid, tactic: tac, order: ORDER.indexOf(tac) + 1, techniques: a.n, threat_use: r3(a.w),
            detected_share: a.w ? r3(a.wd / a.w) : null, tested_share: a.w ? r3(a.wt / a.w) : null, no_rule: a.gaps });
        }
      }
      return out;
    },
  });

  dash.calc('defense_telemetry_rank', {
    title: 'Telemetry to collect first, by vertical',
    description: `ATT&CK v20 data components ranked by the summed priority of the top ${TOP} techniques whose ATT&CK detection analytics read them (the public half of a DeTT&CT visibility assessment, Bhardwaj p179-182). Served = how many of the top ${TOP} need the component.`,
    inputs: ['defense_priority', 'defense_telemetry'],
    fn: (pr, tele) => {
      const byT = new Map();
      for (const r of tele) { if (!byT.has(r.technique_id)) byT.set(r.technique_id, []); byT.get(r.technique_id).push(r); }
      const allServed = new Map();
      for (const r of tele) allServed.set(r.dc_id, (allServed.get(r.dc_id) || 0) + 1);
      const out = [];
      for (const [vid, rows] of byVertical(pr)) {
        const acc = new Map();
        for (const p of rows) {
          if (p.rank > TOP) continue;
          for (const t of byT.get(p.technique_id) || []) {
            const a = acc.get(t.dc_id) || { name: t.data_component, served: 0, weighted: 0, logs: new Map(), plat: new Set(), ids: [] };
            a.served += 1; a.weighted += p.priority; a.ids.push([p.rank, p.technique_id]);
            for (const l of String(t.log_sources || '').split(',').map((s) => s.trim()).filter(Boolean)) a.logs.set(l, (a.logs.get(l) || 0) + 1);
            for (const pl of String(t.platforms || '').split(',').map((s) => s.trim()).filter(Boolean)) a.plat.add(pl);
            acc.set(t.dc_id, a);
          }
        }
        const list = [...acc.entries()].map(([id, a]) => ({ key: vid + '|' + id, vertical_id: vid, dc_id: id, data_component: a.name, top_served: a.served, weighted: r3(a.weighted),
          all_served: allServed.get(id) || 0, log_sources: [...a.logs.entries()].sort((x, y) => y[1] - x[1]).slice(0, 4).map((x) => x[0]).join(', '),
          platforms: [...a.plat].sort().join(', '), top_ids: a.ids.sort((x, y) => x[0] - y[0]).slice(0, 6).map((x) => x[1]).join(', '),
          url: 'https://attack.mitre.org/datacomponents/' + id }));
        list.sort((a, b) => b.weighted - a.weighted || b.top_served - a.top_served);
        list.forEach((r, i) => { r.rank = i + 1; });
        out.push(...list);
      }
      return out;
    },
  });

  dash.calc('defense_cri_rank', {
    title: 'CRI Profile statements by threat-weighted coverage, by vertical',
    description: `Each CRI Profile v2.1 diagnostic statement ranked by the share of the top ${TOP} techniques' prevalence that the techniques it mitigates carry (CTID Mappings Explorer CRI Profile mappings, carried to ATT&CK v20).`,
    inputs: ['defense_priority', 'cri_crosswalk'],
    fn: (pr, cri) => {
      const out = [];
      for (const [vid, rows] of byVertical(pr)) {
        const top = rows.filter((r) => r.rank <= TOP);
        const tot = top.reduce((s, r) => s + r.prevalence, 0) || 1;
        const list = cri.map((c) => {
          const ids = new Set(String(c.technique_ids || '').split(',').map((s) => s.trim()).filter(Boolean));
          const hit = top.filter((r) => ids.has(r.technique_id));
          return { key: vid + '|' + c.cri_id, vertical_id: vid, cri_id: c.cri_id, function: c.function, function_id: c.function_id, function_name: c.function_name, statement: c.statement,
            techniques: ids.size, covered_top: hit.length, weighted_share: r3(hit.reduce((s, r) => s + r.prevalence, 0) / tot), top_ids: hit.slice(0, 6).map((r) => r.technique_id).join(', ') };
        });
        list.sort((a, b) => b.weighted_share - a.weighted_share || b.covered_top - a.covered_top || a.cri_id.localeCompare(b.cri_id));
        list.forEach((r, i) => { r.rank = i + 1; });
        out.push(...list);
      }
      return out;
    },
  });

  dash.calc('defense_kev_exploit', {
    title: 'KEV entries by exploitation technique',
    description: 'CISA KEV vulnerabilities grouped by the ATT&CK technique CTID maps as the way each is exploited (KEV mappings 07/28/2025 on ATT&CK 16.1, carried to v20): entries, ransomware-linked entries, the newest KEV addition and the most frequent vendors.',
    inputs: ['kev_attack'],
    fn: (rows) => {
      const acc = new Map();
      for (const r of rows) {
        if (r.mapping_type !== 'exploitation_technique') continue;
        const a = acc.get(r.technique_id) || { name: r.technique_name, cves: new Set(), ran: new Set(), last: '', vendors: new Map() };
        a.cves.add(r.cve); if (r.ransomware === 'Known') a.ran.add(r.cve);
        if (r.date_added && r.date_added > a.last) a.last = r.date_added;
        if (r.vendor) a.vendors.set(r.vendor, (a.vendors.get(r.vendor) || 0) + 1);
        acc.set(r.technique_id, a);
      }
      return [...acc.entries()].map(([t, a]) => ({ technique_id: t, technique_name: a.name, cves: a.cves.size, ransomware: a.ran.size, last_added: a.last || null,
        vendors: [...a.vendors.entries()].sort((x, y) => y[1] - x[1]).slice(0, 3).map((x) => x[0]).join(', ') })).sort((a, b) => b.cves - a.cves);
    },
  });

  dash.calc('kev_attack_cve', {
    title: 'ATT&CK techniques for each KEV entry',
    description: 'For each CISA KEV CVE CTID has mapped (KEV mappings 07/28/2025 on ATT&CK 16.1, carried to v20), the techniques it is exploited through and the techniques its exploitation achieves (primary and secondary impact).',
    inputs: ['kev_attack'],
    fn: (rows) => {
      const acc = new Map();
      for (const r of rows) {
        const a = acc.get(r.cve) || { exploit: new Set(), impact: new Set() };
        (r.mapping_type === 'exploitation_technique' ? a.exploit : a.impact).add(r.technique_id);
        acc.set(r.cve, a);
      }
      return [...acc.entries()].map(([cve, a]) => ({ cve, exploit_ids: [...a.exploit].sort().join(', ') || null, impact_ids: [...a.impact].sort().join(', ') || null }));
    },
  });

  dash.calc('defense_summary', {
    title: 'Threat-informed defense summary, by vertical',
    description: 'Counts for the Defense page tiles: in-scope groups; techniques at least one in-scope group uses; of the top 50 priorities, those with no public rule and those with no Atomic Red Team test; the first-ranked data component and CRI statement; the tactic inside the estate (Reconnaissance and Resource Development left out) with the lowest threat-weighted public rule coverage; the top-50 technique the vertical\'s threat model raises most against plain ATT&CK frequency.',
    inputs: ['defense_priority', 'defense_group_weight', 'defense_telemetry_rank', 'defense_cri_rank', 'defense_tactic_cov'],
    fn: (pr, gw, tele, cri, tac) => {
      const out = [];
      const T = byVertical(tele), C = byVertical(cri), A = byVertical(tac), G = byVertical(gw);
      for (const [vid, rows] of byVertical(pr)) {
        const top50 = rows.filter((r) => r.rank <= 50);
        const t1 = (T.get(vid) || [])[0] || {}, c1 = (C.get(vid) || [])[0] || {};
        const weak = (A.get(vid) || []).filter((r) => r.detected_share != null && !['Reconnaissance', 'Resource Development'].includes(r.tactic)).sort((a, b) => a.detected_share - b.detected_share)[0] || {};
        const rise = top50.filter((r) => r.shift > 0).sort((a, b) => b.shift - a.shift)[0] || {};
        out.push({ vertical_id: vid, in_scope_groups: (G.get(vid) || []).filter((g) => g.in_scope === 'Yes').length,
          techniques_in_scope: rows.filter((r) => r.groups_in_scope > 0).length, top50_no_rule: top50.filter((r) => !(r.community > 0)).length,
          top50_no_test: top50.filter((r) => !(r.atomic > 0)).length, top_technique: rows[0] ? `${rows[0].technique_id} ${rows[0].name}` : null,
          top_dc: t1.data_component || null, top_dc_served: t1.top_served || 0, top_cri: c1.cri_id || null, top_cri_share: c1.weighted_share ?? null,
          weak_tactic: weak.tactic || null, weak_share: weak.detected_share ?? null,
          top_rise: rise.technique_id ? `${rise.technique_id} ${rise.name}` : null, top_rise_shift: rise.shift || 0, top_rise_rank: rise.rank || null });
      }
      return out;
    },
  });
})();

// ---- Page ----
(() => {
  const { h, v } = TI;
  const parent = (t) => String(t).split('.')[0];
  let selected = null;        // technique id
  let layerMode = 'priority'; // Navigator score
  const vertical = () => dash.params().vertical || 'financial';
  const vname = () => { const r = TI.ready('verticals') ? TI.rows('verticals').find((x) => x.vertical_id === vertical()) : null; return r ? r.name : vertical(); };
  const forV = (id) => (TI.rows(id) || []).filter((r) => r.vertical_id === vertical());
  const ids = (s) => [...new Set(String(s || '').toUpperCase().match(/T\d{4}(?:\.\d{3})?/g) || [])];
  const band = (p) => (p >= 0.5 ? 'High' : p >= 0.25 ? 'Medium' : 'Low');
  const plural = (n, one, many) => `${TI.f.int(n)} ${n === 1 ? one : many || one + 's'}`;
  const base = () => { const m = new Map(); for (const s of TI.rows('defense_sources') || []) if (s.blob_base) m.set(s.source_id, s.blob_base); return m; };
  const SRC = { Sigma: 'S-SIGMA', Elastic: 'S-ELASTIC', Splunk: 'S-SPLUNK', 'Atomic Red Team': 'S-ART' };

  // ---------------------------------------------------------------- saving and copying exports
  function saveFile(name, text, type, note) {
    let ok = false;
    try {
      const url = URL.createObjectURL(new Blob([text], { type }));
      const a = h('a', { href: url, download: name });
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 4000);
      ok = true;
    } catch { ok = false; }
    if (note) note.textContent = ok ? `Saved ${name}. If no file arrived, copy the text below instead.` : 'This browser blocked the file; copy the text below instead.';
  }
  function copyText(text, btn) {
    const done = (msg) => { btn.textContent = msg; setTimeout(() => { btn.textContent = 'Copy'; }, 1800); };
    try { navigator.clipboard.writeText(text).then(() => done('Copied'), () => done('Select the text and copy')); } catch { done('Select the text and copy'); }
  }
  const csv = (rows, cols) => [cols.map((c) => c[1]).join(','), ...rows.map((r) => cols.map(([f]) => {
    const x = r[f] == null ? '' : String(r[f]);
    return /[",\n]/.test(x) ? '"' + x.replace(/"/g, '""') + '"' : x;
  }).join(','))].join('\n');

  function showSigma(sec, r) {
    const box = sec.querySelector('#def-sigma-detail');
    if (!box) return;
    box.hidden = false;
    sec.querySelector('#def-sigma-title').textContent = `${r.title} (${r.ok ? 'accepted draft' : 'rejected'})`;
    sec.querySelector('#def-sigma-yaml').textContent = r.ok ? String(r.yaml || '') : `# Rejected by the checker:\n${TI.list(r.failures).map((x) => '# - ' + x).join('\n')}`;
    const dl = sec.querySelector('#def-sigma-dl');
    dl.hidden = !r.ok;
    dl.href = `/api/sigma?id=${encodeURIComponent(r.id)}&format=yaml`;
    const refs = TI.list(r.references);
    const p = sec.querySelector('#def-sigma-src');
    p.textContent = refs.length ? 'Sources: ' : '';
    refs.forEach((u, i) => { if (i) p.append(', '); p.append(h('a', { href: u, target: '_blank', rel: 'noopener noreferrer', text: (u.match(/^https?:\/\/([^/]+)/) || [])[1] || u })); });
    p.append(` · drafted by ${r.model || 'a free model'}, unreviewed.`);
  }
  // ---------------------------------------------------------------- charts
  // Top priorities with their three drivers stacked, so a reader sees why each ranks where it does (Fleurat ch13).
  function driversChart(box, rows) {
    const data = rows.slice(0, 15);
    const height = data.length * 24 + 34;
    const { svg, w } = TI.svg(box, height);
    const label = (d) => `${d.technique_id} ${d.name}`;
    const lw = Math.min(w * 0.46, TI.textWidth(svg, data.map(label)) + 12);
    const x = d3.scaleLinear([0, 3], [lw, w - 40]);
    const y = d3.scaleBand(data.map((d) => d.technique_id), [4, height - 30]).padding(0.22);
    const parts = [['prevalence', 'Prevalence', TI.color(0)], ['choke', 'Choke point', TI.color(1)], ['actionability', 'Actionability', TI.color(2)]];
    const tip = TI.tip(box);
    const g = svg.append('g');
    for (const d of data) {
      let x0 = 0;
      for (const [f, , col] of parts) {
        const val = d[f] || 0;
        g.append('rect').attr('x', x(x0)).attr('y', y(d.technique_id)).attr('height', y.bandwidth()).attr('width', Math.max(0, x(x0 + val) - x(x0))).style('fill', col)
          .on('mousemove', (ev) => { const [mx, my] = d3.pointer(ev, box); tip.show(label(d), [{ text: `Priority ${TI.f.dec2(d.priority)} of 3, rank ${d.rank}` }, ...parts.map(([pf, pl, pc]) => ({ color: pc, text: `${pl} ${TI.f.dec2(d[pf])}` })), { text: d.gap ? `Gap: ${d.gap}` : `${plural(d.community, 'public rule')}, ${plural(d.atomic, 'Atomic test')}` }], mx, my); })
          .on('mouseleave', () => tip.hide()).on('click', () => pick(d.technique_id));
        x0 += val;
      }
      const lab = g.append('text').attr('class', 'ti-lbl').attr('x', lw - 8).attr('y', y(d.technique_id) + y.bandwidth() / 2).attr('dy', '0.35em').attr('text-anchor', 'end');
      let s = label(d);
      lab.text(s);
      while (lab.node().getComputedTextLength() > lw - 12 && s.length > 8) { s = s.slice(0, -2); lab.text(s + '…'); }
      g.append('text').attr('x', x(d.priority) + 6).attr('y', y(d.technique_id) + y.bandwidth() / 2).attr('dy', '0.35em').text(TI.f.dec2(d.priority) + (d.gap ? ' ·' : ''));
    }
    svg.append('g').attr('transform', `translate(0,${height - 26})`).call(d3.axisBottom(x).ticks(6).tickSizeOuter(0)).call((a) => a.select('.domain').attr('class', 'ti-axis-line'));
    const leg = box.parentElement.querySelector('.ti-legend');
    if (leg && !leg.childNodes.length) for (const [, l, c] of parts) { const sw = h('span', { class: 'ti-sw' }); sw.style.background = c; leg.append(h('span', {}, sw, l)); }
    if (leg && !leg.querySelector('.ti-gapkey')) leg.append(h('span', { class: 'ti-gapkey', text: '· after a score: no public rule or no Atomic test' }));
  }

  // Threat-weighted public coverage per tactic: the ATT&CK matrix read as a defense-gap map (Arici 6.3.2).
  function tacticChart(box, rows) {
    const data = rows.slice().sort((a, b) => a.order - b.order);
    const height = data.length * 24 + 34;
    const { svg, w } = TI.svg(box, height);
    const lw = TI.textWidth(svg, data.map((d) => d.tactic)) + 12;
    const x = d3.scaleLinear([0, 1], [lw, w - 54]);
    const y = d3.scaleBand(data.map((d) => d.tactic), [4, height - 30]).padding(0.25);
    const tip = TI.tip(box);
    const g = svg.append('g');
    g.selectAll('rect.bg').data(data).join('rect').attr('x', lw).attr('y', (d) => y(d.tactic)).attr('height', y.bandwidth()).attr('width', x(1) - lw).attr('rx', 3).style('fill', 'var(--cds-chart-muted)');
    g.selectAll('rect.d').data(data).join('rect').attr('x', lw).attr('y', (d) => y(d.tactic)).attr('height', y.bandwidth()).attr('rx', 3)
      .attr('width', (d) => Math.max(0, x(d.detected_share || 0) - lw)).style('fill', TI.color(0))
      .on('mousemove', (ev, d) => { const [mx, my] = d3.pointer(ev, box); tip.show(d.tactic, [{ text: `${TI.f.pct(d.detected_share)} of threat use on techniques with a public rule` }, { text: `${TI.f.pct(d.tested_share)} on techniques with an Atomic test` }, { text: `${plural(d.techniques, 'technique')} in use, ${d.no_rule} with no public rule` }], mx, my); })
      .on('mouseleave', () => tip.hide());
    g.selectAll('line.t').data(data).join('line').attr('x1', (d) => x(d.tested_share || 0)).attr('x2', (d) => x(d.tested_share || 0)).attr('y1', (d) => y(d.tactic) - 2).attr('y2', (d) => y(d.tactic) + y.bandwidth() + 2)
      .style('stroke', 'var(--color-fg)').style('stroke-width', 2).style('pointer-events', 'none');
    g.selectAll('text.l').data(data).join('text').attr('class', 'ti-lbl').attr('x', lw - 8).attr('y', (d) => y(d.tactic) + y.bandwidth() / 2).attr('dy', '0.35em').attr('text-anchor', 'end').text((d) => d.tactic);
    g.selectAll('text.v').data(data).join('text').attr('x', x(1) + 6).attr('y', (d) => y(d.tactic) + y.bandwidth() / 2).attr('dy', '0.35em').text((d) => TI.f.pct(d.detected_share));
    svg.append('g').attr('transform', `translate(0,${height - 26})`).call(d3.axisBottom(x).ticks(5, '.0%').tickSizeOuter(0)).call((a) => a.select('.domain').attr('class', 'ti-axis-line'));
  }

  // ---------------------------------------------------------------- hunt hypothesis (Tiepolo and Sorensen p48-52)
  function hypothesis(p, groups, tele, kev) {
    const who = p.top_groups
      ? `${p.top_groups}${p.groups_in_scope > 4 ? ` and ${p.groups_in_scope - 4} more in-scope groups` : ''} (${groups})`
      : `${TI.f.pct(p.breadth)} of the most-reported technique's CTI report breadth in the CTID TIE dataset`;
    const plat = String(p.platforms || '').split(',').slice(0, 4).join(',').trim() || 'enterprise';
    const via = kev.length ? `, including through exploited vulnerabilities such as ${kev.slice(0, 2).join(' and ')}` : '';
    const lead = p.top_groups ? `Based on intelligence that ${who} use ${p.name} (${p.technique_id})` : `Based on CTI reporting that observes ${p.name} (${p.technique_id}) at ${who}`;
    const scope = tele.length ? tele.slice(0, 3).map((t) => `${t.data_component} (${t.log_sources || 'no log source named'})`).join('; ') : 'no data component named by ATT&CK analytics';
    return {
      text: `${lead}, we hypothesize that an adversary may be using ${p.name} against our ${plat} estate${via}, relevant to ${vname()}.`,
      scope, content: `Sigma ${p.sigma}, Elastic ${p.elastic}, Splunk ${p.splunk}; ATT&CK analytics ${p.analytics}`,
      validate: p.atomic ? `${plural(p.atomic, 'Atomic Red Team test')} exercise it` : 'No Atomic Red Team test; validation needs a custom test',
    };
  }

  function groupBasis(p) {
    const gw = forV('defense_group_weight');
    const names = String(p.top_groups || '').split(',').map((s) => s.trim()).filter(Boolean);
    const bases = [...new Set(gw.filter((g) => names.includes(g.name)).map((g) => g.basis))];
    return bases.slice(0, 2).join('; ') || 'in scope';
  }

  // ---------------------------------------------------------------- technique detail
  function detail(sec, p) {
    const el = sec.querySelector('#def-detail');
    TI.clear(el);
    if (!p) { el.append(h('p', { class: 'ti-muted', text: 'Pick a technique in any table on this page.' })); return; }
    const w = { key: p.key };
    const tech = TI.index(TI.rows('defense_techniques'), 'technique_id').get(p.technique_id) || {};
    el.append(h('div', { class: 'ti-kj-top' }, h('h2', { class: 'ti-kj-title' }, v('span', 'defense_priority', 'technique_id', w, p.technique_id, 'ti-mono'), ' ', v('span', 'defense_priority', 'name', w, p.name)),
      h('div', { class: 'ti-kj-meta' }, v('span', 'defense_priority', 'rank', w, `Rank ${p.rank}`, 'ti-badge'), v('span', 'defense_priority', 'priority', w, `Priority ${TI.f.dec2(p.priority)}`, 'ti-badge'),
        p.gap ? v('span', 'defense_priority', 'gap', w, p.gap, 'ti-badge ti-yes') : null, p.ransom_top10 === 'Yes' ? v('span', 'defense_priority', 'ransom_top10', w, 'CTID ransomware top 10', 'ti-badge') : null)));
    const row = (label, field, val, src = 'defense_priority', where = w) => [h('dt', { text: label }), v('dd', src, field, where, val == null || val === '' ? '—' : String(val))];
    const tw = { technique_id: p.technique_id };
    el.append(h('dl', { class: 'ti-dl' },
      row('Tactics', 'tactics', p.tactics), row('Platforms', 'platforms', p.platforms),
      row('Prevalence', 'prevalence', `${TI.f.dec2(p.prevalence)} (threat use ${TI.f.dec2(p.p_threat)}, report breadth ${TI.f.dec2(p.breadth)})`),
      row('Choke point', 'choke', TI.f.dec2(p.choke)), row('Actionability', 'actionability', `${TI.f.dec2(p.actionability)} (${plural(p.mitigations, 'mitigation')}, ${plural(p.community, 'public rule')}, ${plural(p.analytics, 'ATT&CK analytic')})`),
      row('In-scope groups', 'top_groups', p.groups_in_scope ? `${p.groups_in_scope}: ${p.top_groups}${p.groups_in_scope > 4 ? ', …' : ''}` : 'None'),
      row('All groups using it', 'groups_all', p.groups_all),
      row('CTI reports observing it', 'tie_reports', `${TI.f.int(tech.tie_reports)} of the TIE dataset's reports`, 'defense_techniques', tw),
      row('Detection strategy', 'strategy', tech.strategy ? `${tech.strategy_ids}: ${tech.strategy}` : 'None in ATT&CK', 'defense_techniques', tw),
      row('CRI Profile statements', 'cri_ids', tech.cri_ids ? String(tech.cri_ids).split(',').join(', ') : 'None mapped', 'defense_techniques', tw),
      row('NIST 800-53 / CIS', 'nist', `${tech.nist || 0} controls / ${tech.cis || 0} safeguards mapped`, 'defense_techniques', tw)));
    const links = [h('a', { href: p.url, target: '_blank', rel: 'noopener noreferrer', text: 'ATT&CK page' })];
    if (tech.strategy_url) links.push(' · ', h('a', { href: tech.strategy_url, target: '_blank', rel: 'noopener noreferrer', text: 'Detection strategy' }));
    el.append(h('p', { class: 'ti-cap' }, links));

    // Hunt hypothesis
    const tele = (TI.rows('defense_telemetry') || []).filter((r) => r.technique_id === p.technique_id).sort((a, b) => b.analytics - a.analytics);
    const kev = (TI.rows('kev_attack') || []).filter((r) => r.technique_id === p.technique_id && r.mapping_type === 'exploitation_technique').sort((a, b) => String(b.date_added).localeCompare(String(a.date_added)));
    const hy = hypothesis(p, groupBasis(p), tele, kev.map((k) => k.cve));
    el.append(h('h4', { class: 'ti-h4', text: 'Hunt hypothesis' }), h('div', { class: 'ti-kj' },
      h('p', {}, h('span', { class: 'ti-kj-label', text: 'Hypothesis' }), hy.text),
      h('p', {}, h('span', { class: 'ti-kj-label', text: 'Data to scope' }), hy.scope),
      h('p', {}, h('span', { class: 'ti-kj-label', text: 'Queries to start from' }), hy.content),
      h('p', {}, h('span', { class: 'ti-kj-label', text: 'Validate' }), hy.validate)));

    // Content catalog
    const bases = base();
    // A parent shows its own items first, then its sub-techniques' items, three per source.
    const items = [];
    const perSrc = new Map();
    for (const r of (TI.rows('defense_content') || []).filter((x) => x.technique_id === p.technique_id || parent(x.technique_id) === p.technique_id)
      .sort((a, b) => (a.technique_id === p.technique_id ? 0 : 1) - (b.technique_id === p.technique_id ? 0 : 1) || a.rank - b.rank || a.technique_id.localeCompare(b.technique_id))) {
      const n = perSrc.get(r.source) || 0;
      if (n >= 3) continue;
      perSrc.set(r.source, n + 1);
      items.push(r);
    }
    const tc = el.appendChild(h('div', { class: 'ti-tbox ti-short' }, h('table', { class: 'ti-table', id: 'tbl-def-content', 'data-source': 'defense_content', 'data-row-key': 'key' })));
    el.insertBefore(h('h4', { class: 'ti-h4', text: p.is_sub === 'No' ? 'Public content for this technique and its sub-techniques (top three per source)' : 'Public content for this technique (top three per source)' }), tc);
    TI.table(tc.firstChild, items.map((r) => ({ ...r, href: (bases.get(SRC[r.source]) || '') + r.path, of: `${r.rank} of ${r.total}` })), [
      { field: 'source', label: 'Source' },
      { field: 'technique_id', label: 'Tagged', cls: 'ti-mono ti-nowrap' },
      { field: 'title', label: 'Rule or test', link: 'href', cls: 'ti-wrap' },
      { field: 'level', label: 'Level or type' },
      { field: 'status', label: 'Status', hideSm: true },
      { field: 'logsource', label: 'Log source', hideSm: true },
      { field: 'of', label: 'Of', cls: 'ti-nowrap' },
    ], { empty: 'No Sigma, Elastic or Splunk rule and no Atomic Red Team test carries this technique id.' });

    // Telemetry
    const tt = el.appendChild(h('div', { class: 'ti-tbox ti-short' }, h('table', { class: 'ti-table', id: 'tbl-def-dc', 'data-source': 'defense_telemetry', 'data-row-key': 'key' })));
    el.insertBefore(h('h4', { class: 'ti-h4', text: 'Telemetry its ATT&CK analytics read' }), tt);
    TI.table(tt.firstChild, tele.map((r) => ({ ...r, href: 'https://attack.mitre.org/datacomponents/' + r.dc_id })), [
      { field: 'dc_id', label: 'ID', link: 'href', cls: 'ti-mono ti-nowrap' },
      { field: 'data_component', label: 'Data component' },
      { field: 'analytics', label: 'Analytics', num: true, fmt: 'int' },
      { field: 'log_sources', label: 'Log sources', cls: 'ti-wrap' },
      { field: 'platforms', label: 'Platforms', hideSm: true },
    ], { sort: 'analytics', dir: 'desc', empty: 'ATT&CK names no data component for this technique.' });

    // KEV
    if (kev.length) {
      const tk = el.appendChild(h('div', { class: 'ti-tbox ti-short' }, h('table', { class: 'ti-table', id: 'tbl-def-kev', 'data-source': 'kev_attack', 'data-row-key': 'key' })));
      el.insertBefore(h('h4', { class: 'ti-h4', text: `Exploited vulnerabilities CTID maps to this technique (${kev.length})` }), tk);
      TI.table(tk.firstChild, kev.map((r) => ({ ...r, href: 'https://nvd.nist.gov/vuln/detail/' + r.cve })), [
        { field: 'cve', label: 'CVE', link: 'href', cls: 'ti-mono ti-nowrap' },
        { field: 'vendor', label: 'Vendor' },
        { field: 'product', label: 'Product', cls: 'ti-wrap' },
        { field: 'capability', label: 'Weakness', hideSm: true },
        { field: 'ransomware', label: 'Ransomware use' },
        { field: 'date_added', label: 'Added to KEV', fmt: 'date', cls: 'ti-nowrap' },
      ], { sort: 'date_added', dir: 'desc', limit: 40 });
    }
  }

  // ---------------------------------------------------------------- inference (CTID TIE co-occurrence, hypotheses only)
  function inference(sec, prIdx) {
    const input = sec.querySelector('#def-observed');
    if (!input.value && selected) input.value = selected;
    const obs = ids(input.value).filter((t) => prIdx.has(t) || (TI.rows('defense_techniques') || []).some((x) => x.technique_id === t));
    const co = TI.rows('defense_cooccur') || [];
    const acc = new Map();
    for (const r of co) {
      if (!obs.includes(r.technique_id) || obs.includes(r.related_id)) continue;
      const a = acc.get(r.related_id) || { name: r.related_name, score: 0, by: [], best: 0 };
      a.score += r.score; a.by.push(`${r.technique_id} (${TI.f.pct(r.p_related)}, lift ${TI.f.dec1(r.lift)})`); a.best = Math.max(a.best, r.p_related);
      acc.set(r.related_id, a);
    }
    const rows = [...acc.entries()].map(([t, a]) => {
      const p = prIdx.get(t) || {};
      return { technique_id: t, name: a.name, score: Math.round(a.score * 1000) / 1000, by: a.by.join('; '), best: a.best, rank: p.rank, gap: p.gap || '', url: p.url };
    });
    const note = sec.querySelector('#def-inf-note');
    note.textContent = obs.length ? `Observed: ${obs.join(', ')}. ${plural(rows.length, 'candidate')} to look for next.` : 'Enter one or more ATT&CK technique ids seen in an intrusion.';
    TI.table(sec.querySelector('#tbl-def-inf'), rows, [
      { field: 'technique_id', label: 'ID', link: 'url', cls: 'ti-mono ti-nowrap' },
      { field: 'name', label: 'Technique to look for', cls: 'ti-wrap' },
      { field: 'score', label: 'Score', num: true, fmt: 'dec2' },
      { field: 'best', label: 'Best co-occurrence', num: true, fmt: 'pct' },
      { field: 'by', label: 'Suggested by (share of reports, lift)', cls: 'ti-wrap', hideSm: true },
      { field: 'rank', label: 'Priority rank', num: true, fmt: 'int' },
      { field: 'gap', label: 'Gap', hideSm: true },
    ], { sort: 'score', dir: 'desc', limit: 25, onClick: (r) => pick(r.technique_id), empty: obs.length ? 'No technique co-occurs with these often enough to suggest (15 shared reports and lift above 1.2).' : 'No observed techniques yet.' });
  }

  // ---------------------------------------------------------------- purple-team register (Tiepolo and Sorensen p572-575)
  function registerRows(pr) {
    const tele = TI.rows('defense_telemetry') || [];
    const content = TI.rows('defense_content') || [];
    const bases = base();
    return pr.filter((p) => p.atomic > 0 && p.groups_in_scope > 0).slice(0, 15).map((p) => {
      const dc = tele.filter((t) => t.technique_id === p.technique_id).sort((a, b) => b.analytics - a.analytics).slice(0, 2);
      const test = content.find((c) => c.technique_id === p.technique_id && c.source === 'Atomic Red Team')
        || content.filter((c) => parent(c.technique_id) === p.technique_id && c.source === 'Atomic Red Team').sort((a, b) => a.rank - b.rank || a.technique_id.localeCompare(b.technique_id))[0];
      return { technique_id: p.technique_id, name: p.name, rank: p.rank, justification: `${p.top_groups} (${groupBasis(p)})`,
        scenario: test ? `${test.technique_id !== p.technique_id ? test.technique_id + ': ' : ''}${test.title}${p.atomic > 1 ? ` and ${p.atomic - 1} more` : ''}` : `${p.atomic} tests`, scenario_url: test ? (bases.get('S-ART') || '') + test.path : null,
        telemetry: dc.map((d) => d.data_component).join(', ') || 'Not named', content: `Sigma ${p.sigma} · Elastic ${p.elastic} · Splunk ${p.splunk}`,
        hypothesis: `Running the test on ${String(p.platforms || '').split(',')[0] || 'a representative host'} produces ${dc[0] ? dc[0].data_component : 'telemetry'} that existing content alerts on`,
        severity: band(p.prevalence), result: 'Not run' };
    });
  }

  // ---------------------------------------------------------------- ATT&CK Navigator layer (Bhardwaj p140-147)
  function layer(pr) {
    const top = new Set(pr.filter((p) => p.rank <= 100).map((p) => p.technique_id));
    const techniques = pr.filter((p) => (layerMode === 'priority' ? top.has(p.technique_id) : !(p.community > 0) && p.p_threat > 0)).map((p) => ({
      techniqueID: p.technique_id, score: layerMode === 'priority' ? +p.priority.toFixed(2) : +p.prevalence.toFixed(2), enabled: true, showSubtechniques: false,
      comment: `Rank ${p.rank}. Prevalence ${p.prevalence}, choke ${p.choke}, actionability ${p.actionability}. In-scope groups: ${p.top_groups || 'none'}. Public rules ${p.community}, Atomic tests ${p.atomic}.${p.gap ? ' Gap: ' + p.gap + '.' : ''}`,
      metadata: [{ name: 'priority', value: String(p.priority) }, { name: 'gap', value: p.gap || 'none' }],
    }));
    const run = TI.ready('latest_run') ? (TI.rows('latest_run')[0] || {}) : {};
    return {
      name: layerMode === 'priority' ? `Threat-informed priorities: ${vname()}` : `Public detection gaps: ${vname()}`,
      versions: { attack: '20', navigator: '5.1.0', layer: '4.5' }, domain: 'enterprise-attack',
      description: layerMode === 'priority'
        ? `Top 100 techniques for ${vname()} by prevalence + choke point + actionability (0-3), CTID Top ATT&CK Techniques method recomputed from ATT&CK v20, this dashboard's threat model and current Sigma, Elastic and Splunk content.`
        : `Techniques in-scope or background groups use that no Sigma, Elastic or Splunk rule carries, scored by prevalence (0-1). A public content gap; the organization's own rule inventory decides its real gap.`,
      sorting: 3, layout: { layout: 'side', aggregateFunction: 'max', showID: true, showName: true, showAggregateScores: false, countUnscored: false },
      hideDisabled: false, techniques,
      gradient: { colors: ['#fff7bc', '#fec44f', '#d95f0e'], minValue: 0, maxValue: layerMode === 'priority' ? 3 : 1 },
      legendItems: [], metadata: [{ name: 'vertical', value: vname() }, { name: 'run', value: String(run.run_id || '') }, { name: 'source', value: 'Global threat intelligence dashboard, Defense page' }],
      links: [], showTacticRowBackground: false, tacticRowBackground: '#dddddd', selectTechniquesAcrossTactics: true, selectSubtechniquesWithParent: false, selectVisibleTechniques: false,
    };
  }

  function pick(t) {
    selected = t;
    TI.draw('defense');
    const el = document.getElementById('def-detail');
    if (el) el.scrollIntoView({ block: 'nearest' });
  }

  TI.page('defense', (sec) => {
    const tj = sec.querySelector('#tbl-judgment-detect');
    if (tj && TI.tableState(tj, ['judgment_detection'])) {
      const pc = (x) => (x == null ? 'n/a' : Math.round(x * 100) + '%');
      TI.table(tj, TI.rows('judgment_detection'), [
        { field: 'judgment_id', label: 'Judgment', cls: 'ti-nowrap', get: (r) => `${r.judgment_id} ${r.title}`, attr: {} },
        { field: 'vector', label: 'Vector', hideSm: true },
        { field: 'groups', label: 'Named ATT&CK groups', cls: 'ti-wrap', hideSm: true },
        { field: 'techniques', label: 'Techniques', num: true },
        { field: 'coverage', label: 'With a Sigma rule', num: true, get: (r) => (r.techniques ? `${r.with_sigma} (${pc(r.coverage)})` : '—'), attr: { 'data-status': (r) => (r.coverage == null ? '' : r.coverage >= 0.8 ? 'ok' : r.coverage >= 0.5 ? 'review' : 'fail') } },
        { field: 'with_stable', label: 'Stable', num: true, hideSm: true },
        { field: 'with_high', label: 'High severity', num: true, hideSm: true },
        { field: 'sigma_rules', label: 'Sigma rules', num: true, fmt: 'int' },
        { field: 'gaps', label: 'Techniques without a Sigma rule', cls: 'ti-wrap', get: (r) => r.scope_note || r.gaps || 'none' },
        { field: 'top_rules', label: 'Example rules', cls: 'ti-wrap', hideSm: true },
      ], { sort: 'exec_rank', dir: 'asc', empty: 'No judgments.' });
    }
    const vn = vname();
    for (const el of sec.querySelectorAll('.def-vname')) el.textContent = vn;
    const need = ['defense_priority', 'defense_techniques'];
    // Tiles
    const tiles = sec.querySelector('#def-tiles');
    TI.clear(tiles);
    if (TI.failed(...need)) { tiles.append(h('div', { class: 'ti-failed', text: 'Failed to load' })); }
    else if (!TI.ready('defense_summary')) { tiles.classList.add('dash-skeleton'); }
    else {
      tiles.classList.remove('dash-skeleton');
      const s = (TI.rows('defense_summary') || []).find((r) => r.vertical_id === vertical()) || {};
      const w = { vertical_id: vertical() };
      const tile = (label, field, val, sub) => h('div', { class: 'ti-tile' }, h('div', { class: 'ti-tile-label', text: label }), v('div', 'defense_summary', field, w, val, 'ti-big'), h('div', { class: 'ti-tile-sub' }, sub));
      tiles.append(
        tile('In-scope groups', 'in_scope_groups', TI.f.int(s.in_scope_groups), [v('span', 'defense_summary', 'techniques_in_scope', w, TI.f.int(s.techniques_in_scope)), ' techniques they use']),
        tile('Top 50 with no public rule', 'top50_no_rule', TI.f.int(s.top50_no_rule), [v('span', 'defense_summary', 'top50_no_test', w, TI.f.int(s.top50_no_test)), ' with no Atomic test']),
        tile('Rises most for this vertical', 'top_rise', s.top_rise ? s.top_rise.split(' ')[0] : '—', s.top_rise ? [s.top_rise.split(' ').slice(1).join(' '), ', up ', v('span', 'defense_summary', 'top_rise_shift', w, TI.f.int(s.top_rise_shift)), ' places to rank ', v('span', 'defense_summary', 'top_rise_rank', w, TI.f.int(s.top_rise_rank))] : 'No top-50 technique moves up'),
        tile('Weakest tactic inside the estate', 'weak_tactic', s.weak_tactic || '—', [v('span', 'defense_summary', 'weak_share', w, TI.f.pct(s.weak_share)), ' of its threat use has a public rule']),
        tile('Telemetry to collect first', 'top_dc', s.top_dc || '—', [v('span', 'defense_summary', 'top_dc_served', w, TI.f.int(s.top_dc_served)), ' of the top 100 read it']),
        tile('CRI statement covering most', 'top_cri', s.top_cri || '—', [v('span', 'defense_summary', 'top_cri_share', w, TI.f.pct(s.top_cri_share)), ' of top-100 prevalence']));
    }

    const tp = sec.querySelector('#tbl-def-pri');
    if (!TI.tableState(tp, need)) return;
    const pr = forV('defense_priority');
    const prIdx = new Map(pr.map((p) => [p.technique_id, p]));
    if (!selected || !prIdx.has(selected)) selected = pr[0] && pr[0].technique_id;

    const db = sec.querySelector('#def-drivers');
    if (TI.chartState(db, ['defense_priority'])) driversChart(db, pr);
    const tb = sec.querySelector('#def-tactics');
    if (TI.chartState(tb, ['defense_tactic_cov'])) tacticChart(tb, forV('defense_tactic_cov'));

    // Priorities
    const tsel = sec.querySelector('#def-tactic');
    if (tsel.options.length === 1) for (const t of [...new Set(pr.flatMap((p) => String(p.tactics).split(',').map((s) => s.trim())))].filter(Boolean).sort()) tsel.append(h('option', { text: t }));
    const q = TI.search(sec.querySelector('#def-q'));
    const tac = tsel.value, gap = sec.querySelector('#def-gap').value, scope = sec.querySelector('#def-scope').value;
    const PRI_COLS = [
      { field: 'rank', label: 'Rank', num: true, fmt: 'int' },
      { field: 'technique_id', label: 'ID', link: 'url', cls: 'ti-mono ti-nowrap' },
      { field: 'name', label: 'Technique', cls: 'ti-wrap' },
      { field: 'tactics', label: 'Tactics', hideSm: true },
      { field: 'priority', label: 'Priority', num: true, fmt: 'dec2' },
      { field: 'prevalence', label: 'Prevalence', num: true, fmt: 'dec2', hideSm: true },
      { field: 'choke', label: 'Choke', num: true, fmt: 'dec2', hideSm: true },
      { field: 'actionability', label: 'Action', num: true, fmt: 'dec2', hideSm: true },
      { field: 'shift', label: 'Shift', num: true, fmt: 'signedInt', hideSm: true },
      { field: 'groups_in_scope', label: 'In-scope groups', num: true, fmt: 'int' },
      { field: 'community', label: 'Public rules', num: true, fmt: 'int' },
      { field: 'atomic', label: 'Atomic tests', num: true, fmt: 'int' },
      { field: 'kev_cves', label: 'KEV CVEs', num: true, fmt: 'int', hideSm: true },
      { field: 'gap', label: 'Gap' },
    ];
    const priFilter = (r) => q(r, ['technique_id', 'name', 'top_groups']) && (!tac || String(r.tactics).includes(tac)) && (!gap || (gap === 'any' ? !!r.gap : r.gap === gap))
      && (!scope || (scope === 'in' ? r.groups_in_scope > 0 : scope === 'parents' ? r.is_sub === 'No' : scope === 'rise' ? r.shift >= 10 : r.ransom_top10 === 'Yes'));
    TI.table(tp, pr, PRI_COLS, { sort: 'rank', dir: 'asc', limit: 200, selected: vertical() + '|' + selected, onClick: (r) => pick(r.technique_id), countEl: sec.querySelector('#def-count'), filter: priFilter });

    // Blind spots: high threat use, no public rule or no test
    const tg = sec.querySelector('#tbl-def-gaps');
    TI.table(tg, pr.filter((p) => p.gap && p.p_threat >= 0.15 && p.pre_compromise === 'No'), [
      { field: 'technique_id', label: 'ID', link: 'url', cls: 'ti-mono ti-nowrap' },
      { field: 'name', label: 'Technique', cls: 'ti-wrap' },
      { field: 'p_threat', label: 'Threat use', num: true, fmt: 'dec2' },
      { field: 'groups_in_scope', label: 'In-scope groups', num: true, fmt: 'int' },
      { field: 'top_groups', label: 'Groups', cls: 'ti-wrap', hideSm: true },
      { field: 'gap', label: 'Gap' },
      { field: 'analytics', label: 'ATT&CK analytics', num: true, fmt: 'int', hideSm: true },
    ], { sort: 'p_threat', dir: 'desc', onClick: (r) => pick(r.technique_id), countEl: sec.querySelector('#def-gaps-count'), empty: 'Every technique with threat use of 0.15 or more has a public rule and an Atomic test.' });

    // Actor coverage
    const ta = sec.querySelector('#tbl-def-actors');
    if (TI.tableState(ta, ['defense_actor_cov'])) {
      TI.table(ta, forV('defense_actor_cov'), [
        { field: 'name', label: 'Group' },
        { field: 'basis', label: 'Why in scope', cls: 'ti-wrap' },
        { field: 'sector_evidence', label: 'Stated targeting', cls: 'ti-wrap', hideSm: true },
        { field: 'weight', label: 'Weight', num: true, fmt: 'dec2' },
        { field: 'techniques', label: 'Techniques', num: true, fmt: 'int' },
        { field: 'detected_share', label: 'With public rule', num: true, fmt: 'pct' },
        { field: 'tested_share', label: 'With Atomic test', num: true, fmt: 'pct' },
        { field: 'gap_count', label: 'No rule', num: true, fmt: 'int' },
        { field: 'pre_compromise', label: 'Pre-compromise', num: true, fmt: 'int', hideSm: true },
        { field: 'gap_ids', label: 'Uncovered, most reported first', cls: 'ti-wrap ti-mono', hideSm: true },
      ], { sort: 'weight', dir: 'desc', countEl: sec.querySelector('#def-actors-count'), onClick: (r) => { const first = ids(r.gap_ids)[0]; if (first) pick(first); } });
    }

    // Telemetry ranking
    const tt = sec.querySelector('#tbl-def-tele');
    if (TI.tableState(tt, ['defense_telemetry_rank'])) {
      TI.table(tt, forV('defense_telemetry_rank'), [
        { field: 'rank', label: 'Rank', num: true, fmt: 'int' },
        { field: 'dc_id', label: 'ID', link: 'url', cls: 'ti-mono ti-nowrap' },
        { field: 'data_component', label: 'Data component' },
        { field: 'top_served', label: 'Top-100 techniques', num: true, fmt: 'int' },
        { field: 'weighted', label: 'Summed priority', num: true, fmt: 'dec1' },
        { field: 'log_sources', label: 'Log sources ATT&CK names', cls: 'ti-wrap', hideSm: true },
        { field: 'top_ids', label: 'Highest-ranked techniques', cls: 'ti-wrap ti-mono', hideSm: true },
      ], { sort: 'rank', dir: 'asc', limit: 40, onClick: (r) => { const first = ids(r.top_ids)[0]; if (first) pick(first); } });
    }

    // CRI crosswalk
    const tc = sec.querySelector('#tbl-def-cri');
    if (TI.tableState(tc, ['defense_cri_rank'])) {
      const fsel = sec.querySelector('#def-cri-f');
      const cri = forV('defense_cri_rank');
      if (fsel.options.length === 1) for (const [f, n] of [...new Map(cri.map((c) => [c.function_id, c.function_name])).entries()].filter(([f]) => f).sort()) fsel.append(h('option', { value: f, text: `${f} ${n || ''}`.trim() }));
      const fv = fsel.value;
      TI.table(tc, cri, [
        { field: 'rank', label: 'Rank', num: true, fmt: 'int' },
        { field: 'cri_id', label: 'Statement', cls: 'ti-mono ti-nowrap' },
        { field: 'function_id', label: 'Category', cls: 'ti-mono ti-nowrap', hideSm: true },
        { field: 'statement', label: 'Diagnostic statement', cls: 'ti-wrap' },
        { field: 'weighted_share', label: 'Top-100 prevalence', num: true, fmt: 'pct' },
        { field: 'covered_top', label: 'Top-100 techniques', num: true, fmt: 'int' },
        { field: 'techniques', label: 'All techniques', num: true, fmt: 'int', hideSm: true },
        { field: 'top_ids', label: 'Highest-ranked covered', cls: 'ti-wrap ti-mono', hideSm: true },
      ], { sort: 'rank', dir: 'asc', filter: (r) => !fv || r.cri_id.startsWith(fv), countEl: sec.querySelector('#def-cri-count'), onClick: (r) => { const first = ids(r.top_ids)[0]; if (first) pick(first); } });
    }

    // KEV entry techniques
    const tk = sec.querySelector('#tbl-def-kevx');
    if (TI.tableState(tk, ['defense_kev_exploit'])) {
      TI.table(tk, TI.rows('defense_kev_exploit').map((r) => ({ ...r, rank: (prIdx.get(r.technique_id) || {}).rank, url: (prIdx.get(r.technique_id) || {}).url })), [
        { field: 'technique_id', label: 'ID', link: 'url', cls: 'ti-mono ti-nowrap' },
        { field: 'technique_name', label: 'Exploited through', cls: 'ti-wrap' },
        { field: 'cves', label: 'KEV CVEs', num: true, fmt: 'int' },
        { field: 'ransomware', label: 'Ransomware-linked', num: true, fmt: 'int' },
        { field: 'last_added', label: 'Newest', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'vendors', label: 'Most frequent vendors', cls: 'ti-wrap', hideSm: true },
        { field: 'rank', label: 'Priority rank', num: true, fmt: 'int' },
      ], { sort: 'cves', dir: 'desc', onClick: (r) => pick(r.technique_id) });
    }

    // Detail, inference, register
    detail(sec, prIdx.get(selected));
    const ti = sec.querySelector('#tbl-def-inf');
    if (TI.tableState(ti, ['defense_cooccur', 'defense_priority'])) inference(sec, prIdx);
    // Sigma drafts (neon/parts/37o-sigma.mjs, live_sigma).
    const tsg = sec.querySelector('#tbl-def-sigma');
    if (tsg && TI.tableState(tsg, ['live_sigma'])) {
      const f = (sec.querySelector('#def-sigma-f') || {}).value ?? 'ok';
      const all = (TI.rows('live_sigma') || []).filter((r) => r.kind === 'rule').map((r) => ({ ...r, ok: String(r.ok) === 'true', gap: String(r.gap) === 'true',
        status: String(r.ok) === 'true' ? 'Accepted' : 'Rejected', ls: Object.values(TI.obj(r.logsource)).join(' / '), tech: TI.list(r.techniques).map((t) => t + (TI.obj(r.public_sigma)[t] === 0 ? ' (gap)' : '')).join(', '),
        graph: '#graph?id=' + encodeURIComponent(r.subject), why: String(r.ok) === 'true' ? '' : TI.list(r.failures).join('; ') }));
      const rows = all.filter((r) => (f === 'ok' ? r.ok : f === 'gap' ? r.ok && r.gap : f === 'rejected' ? !r.ok : true));
      const attempts = (TI.rows('live_sigma') || []).filter((r) => r.kind === 'attempt');
      sec.querySelector('#def-sigma-count').textContent = `${all.filter((r) => r.ok).length} accepted, ${all.filter((r) => !r.ok).length} rejected, ${attempts.length} subjects tried`;
      TI.table(tsg, rows, [
        { field: 'created_at', label: 'Drafted', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'name', label: 'Subject', link: 'graph' },
        { field: 'title', label: 'Rule', cls: 'ti-wrap' },
        { field: 'ls', label: 'Log source', hideSm: true },
        { field: 'tech', label: 'ATT&CK', cls: 'ti-wrap' },
        { field: 'level', label: 'Level', hideSm: true },
        { field: f === 'ok' || f === 'gap' ? 'status' : 'why', label: f === 'ok' || f === 'gap' ? 'Status' : 'Checker', cls: 'ti-wrap', hideSm: f === 'ok' || f === 'gap', get: (r) => (f === 'ok' || f === 'gap' ? r.status : r.ok ? 'Accepted' : r.why) },
      ], { sort: 'created_at', dir: 'desc', limit: 60, selected: sec._sigmaSel, onClick: (r) => { sec._sigmaSel = r.id; showSigma(sec, r); TI.draw('defense'); },
        empty: f === 'rejected' ? 'No rule has been rejected.' : 'No draft yet: the job drafts at most one subject an hour once three publishers name it.' });
      const sel = all.find((r) => r.id === sec._sigmaSel);
      if (sel) showSigma(sec, sel);
    }
    const tr = sec.querySelector('#tbl-def-reg');
    if (TI.tableState(tr, ['defense_priority', 'defense_telemetry', 'defense_content'])) {
      const reg = registerRows(pr);
      sec._reg = reg;
      TI.table(tr, reg, [
        { field: 'technique_id', label: 'Behavior', cls: 'ti-mono ti-nowrap' },
        { field: 'name', label: 'Technique', cls: 'ti-wrap' },
        { field: 'justification', label: 'Intelligence justification', cls: 'ti-wrap' },
        { field: 'scenario', label: 'Scenario (Atomic Red Team)', link: 'scenario_url', cls: 'ti-wrap' },
        { field: 'telemetry', label: 'Telemetry relied on', cls: 'ti-wrap', hideSm: true },
        { field: 'content', label: 'Public content', hideSm: true },
        { field: 'hypothesis', label: 'Testable hypothesis', cls: 'ti-wrap', hideSm: true },
        { field: 'severity', label: 'Prevalence band' },
        { field: 'result', label: 'Result' },
      ], { onClick: (r) => pick(r.technique_id) });
    }

    // Navigator layer
    const out = sec.querySelector('#def-layer-out');
    for (const b of sec.querySelectorAll('#def-layer-mode .ti-chip')) b.setAttribute('aria-pressed', String(b.dataset.mode === layerMode));
    out.value = JSON.stringify(layer(pr), null, 1);
    sec.querySelector('#def-layer-count').textContent = plural(JSON.parse(out.value).techniques.length, 'technique');

    // Sources
    const ts = sec.querySelector('#tbl-def-src');
    if (TI.tableState(ts, ['defense_sources'])) {
      TI.table(ts, TI.rows('defense_sources').map((r) => ({ ...r, ver: r.version && /^[0-9a-f]{40}$/.test(r.version) ? r.version.slice(0, 10) : r.version })), [
        { field: 'name', label: 'Source', link: 'url' },
        { field: 'ver', label: 'Version or commit', cls: 'ti-mono ti-nowrap' },
        { field: 'version_date', label: 'Dated', fmt: 'date', cls: 'ti-nowrap', hideSm: true },
        { field: 'items', label: 'Items', num: true, fmt: 'int' },
        { field: 'terms', label: 'Terms', cls: 'ti-wrap', hideSm: true },
        { field: 'note', label: 'Note', cls: 'ti-wrap', hideSm: true },
      ]);
    }
  });

  dash.onData(() => TI.draw('defense'));
  TI.root.addEventListener('input', (ev) => { if (['def-q', 'def-tactic', 'def-gap', 'def-scope', 'def-cri-f', 'def-observed', 'def-sigma-f'].includes(ev.target.id)) TI.draw('defense'); });
  TI.root.addEventListener('focusin', (ev) => { if (ev.target.id === 'def-layer-out') ev.target.select(); });
  TI.root.addEventListener('click', (ev) => {
    const b = ev.target.closest('button');
    if (!b || !b.closest('#defense')) return;
    const sec = document.getElementById('defense');
    if (b.closest('#def-layer-mode') && b.dataset.mode) { layerMode = b.dataset.mode; TI.draw('defense'); return; }
    const note = sec.querySelector('#def-export-note');
    const pr = forV('defense_priority');
    const slug = vertical().replace(/[^a-z0-9]+/gi, '-');
    if (b.id === 'def-layer-save') saveFile(`attack-layer-${layerMode}-${slug}.json`, sec.querySelector('#def-layer-out').value, 'application/json', note);
    else if (b.id === 'def-layer-copy') copyText(sec.querySelector('#def-layer-out').value, b);
    else if (b.id === 'def-sigma-copy') copyText(sec.querySelector('#def-sigma-yaml').textContent, b);
    else if (b.id === 'def-pri-csv') saveFile(`defense-priorities-${slug}.csv`, csv(pr, [['rank', 'rank'], ['technique_id', 'technique_id'], ['name', 'name'], ['tactics', 'tactics'], ['priority', 'priority'], ['prevalence', 'prevalence'], ['p_threat', 'threat_use'], ['breadth', 'report_breadth'], ['choke', 'choke_point'], ['actionability', 'actionability'], ['shift', 'shift_vs_plain_frequency'], ['pre_compromise', 'pre_compromise'], ['groups_in_scope', 'in_scope_groups'], ['top_groups', 'groups'], ['sigma', 'sigma'], ['elastic', 'elastic'], ['splunk', 'splunk'], ['atomic', 'atomic_tests'], ['kev_cves', 'kev_cves'], ['gap', 'gap']]), 'text/csv', sec.querySelector('#def-pri-note'));
    else if (b.id === 'def-reg-csv') saveFile(`purple-team-register-${slug}.csv`, csv(sec._reg || [], [['technique_id', 'behavior'], ['name', 'technique'], ['justification', 'intelligence_justification'], ['scenario', 'scenario'], ['scenario_url', 'scenario_link'], ['telemetry', 'telemetry'], ['content', 'public_content'], ['hypothesis', 'testable_hypothesis'], ['severity', 'prevalence_band'], ['result', 'result']]), 'text/csv', sec.querySelector('#def-reg-note'));
  });
})();
