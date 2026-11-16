/* Every computed value on the page is one of these calculations, so a reader can open its formula in Sources. */

dash.calc('item_scores', {
  title: 'Evidence item scores',
  description: 'Admiralty reliability times credibility for each reporting item (Tiepolo and Sorensen p525).',
  inputs: ['items'],
  fn: (items) => {
    const rel = { A: 1, B: 0.8, C: 0.6, D: 0.4, E: 0.2, F: 0.3 };
    const cred = { 1: 1, 2: 0.8, 3: 0.6, 4: 0.4, 5: 0.2, 6: 0.3 };
    return items.map((i) => ({ item_id: i.item_id, score: Math.round(rel[i.reliability] * cred[i.credibility] * 100) / 100 }));
  },
});

dash.calc('confidence', {
  title: 'Judgment confidence',
  description: 'HIGH: 3+ independent origins, 3+ evidence categories, mean item score 0.7+, alternative considered. MEDIUM: 2+, 2+, mean 0.4+. Else LOW. Attribution judgments cap at MEDIUM.',
  inputs: ['judgments', 'evidence', 'items'],
  fn: (judgments, evidence, items) => {
    const rel = { A: 1, B: 0.8, C: 0.6, D: 0.4, E: 0.2, F: 0.3 };
    const cred = { 1: 1, 2: 0.8, 3: 0.6, 4: 0.4, 5: 0.2, 6: 0.3 };
    const byId = new Map(items.map((i) => [i.item_id, i]));
    return judgments.map((j) => {
      const ev = evidence.filter((e) => e.judgment_id === j.judgment_id);
      const sup = ev.filter((e) => e.role === 'Supports').map((e) => byId.get(e.item_id)).filter(Boolean);
      const origins = new Set(sup.map((i) => i.origin)).size;
      const categories = new Set(sup.map((i) => i.category)).size;
      const mean = sup.length ? sup.reduce((s, i) => s + rel[i.reliability] * cred[i.credibility], 0) / sup.length : 0;
      const alt = j.alternative_considered === 'Yes';
      let level = origins >= 3 && categories >= 3 && mean >= 0.7 && alt ? 'HIGH' : origins >= 2 && categories >= 2 && mean >= 0.4 ? 'MEDIUM' : 'LOW';
      const capped = j.attribution_judgment === 'Yes' && level === 'HIGH';
      if (capped) level = 'MEDIUM';
      return {
        judgment_id: j.judgment_id,
        supporting: sup.length,
        weakening: ev.filter((e) => e.role === 'Weakens').length,
        origins,
        categories,
        mean_score: Math.round(mean * 100) / 100,
        alternative: alt ? 'Yes' : 'No',
        capped: capped ? 'Yes' : 'No',
        confidence: level,
      };
    });
  },
});

dash.calc('exec_brief', {
  title: 'Executive judgments shown',
  description: 'Judgments ranked for the executive page, keeping only MEDIUM or HIGH confidence, at most six (Thomas p212-215).',
  inputs: ['judgments', 'confidence'],
  fn: (judgments, confidence) => {
    const conf = new Map(confidence.map((c) => [c.judgment_id, c.confidence]));
    return judgments
      .filter((j) => j.exec_rank > 0 && ['HIGH', 'MEDIUM'].includes(conf.get(j.judgment_id)))
      .sort((a, b) => a.exec_rank - b.exec_rank)
      .slice(0, 6)
      .map((j, i) => ({ judgment_id: j.judgment_id, position: i + 1, confidence: conf.get(j.judgment_id) }));
  },
});

dash.calc('brief_stats', {
  title: 'Brief counts',
  description: 'Executive judgments shown and confidence mix; reporting items in the 7 days to the newest item.',
  inputs: ['exec_brief', 'confidence', 'items'],
  fn: (exec_brief, confidence, items) => {
    const newest = items.reduce((m, i) => (i.date > m ? i.date : m), '');
    const cut = new Date(Date.parse(newest + 'T00:00:00Z') - 7 * 864e5).toISOString().slice(0, 10);
    return [{
      exec_shown: exec_brief.length,
      high: confidence.filter((c) => c.confidence === 'HIGH').length,
      medium: confidence.filter((c) => c.confidence === 'MEDIUM').length,
      low: confidence.filter((c) => c.confidence === 'LOW').length,
      items_total: items.length,
      items_7d: items.filter((i) => i.date > cut).length,
      newest_item: newest,
    }];
  },
});

dash.calc('posture', {
  title: 'Theater posture',
  description: 'Count of theaters at each ThreatCon level and by trend.',
  inputs: ['theaters'],
  fn: (theaters) => [{
    theaters: theaters.length,
    critical: theaters.filter((t) => t.threatcon === 5).length,
    high: theaters.filter((t) => t.threatcon === 4).length,
    elevated: theaters.filter((t) => t.threatcon === 3).length,
    guarded: theaters.filter((t) => t.threatcon === 2).length,
    normal: theaters.filter((t) => t.threatcon === 1).length,
    escalating: theaters.filter((t) => t.trend === 'Escalating').length,
    deescalating: theaters.filter((t) => t.trend === 'De-escalating').length,
    critical_names: theaters.filter((t) => t.threatcon === 5).map((t) => t.name).join('; '),
  }],
});

dash.calc('indicator_rollup', {
  title: 'Warning indicators by theater',
  description: 'Escalation indicators observed or confirmed, emerging, and not observed, per theater.',
  inputs: ['theater_indicators'],
  fn: (theater_indicators) => {
    const by = new Map();
    for (const i of theater_indicators) {
      const r = by.get(i.theater_id) || { theater_id: i.theater_id, escalation_seen: 0, emerging: 0, not_observed: 0, deescalation_seen: 0, total: 0 };
      r.total += 1;
      const seen = i.state === 'Observed' || i.state === 'Confirmed';
      if (i.direction === 'Escalation' && seen) r.escalation_seen += 1;
      if (i.direction === 'De-escalation' && seen) r.deescalation_seen += 1;
      if (i.state === 'Emerging') r.emerging += 1;
      if (i.state === 'Not observed') r.not_observed += 1;
      by.set(i.theater_id, r);
    }
    return [...by.values()];
  },
});

dash.calc('kev_stats', {
  title: 'KEV in the last 30 days',
  description: 'KEV additions in the 30 days to the newest listing, with edge-device, ransomware and weaponization counts; median publication-to-KEV days for edge-device CVEs published and listed this year.',
  inputs: ['kev'],
  fn: (kev) => {
    const newest = kev.reduce((m, r) => (r.date_added > m ? r.date_added : m), '');
    const cut = new Date(Date.parse(newest + 'T00:00:00Z') - 30 * 864e5).toISOString().slice(0, 10);
    const recent = kev.filter((r) => r.date_added > cut);
    const year = newest.slice(0, 4);
    const lags = kev
      .filter((r) => r.edge_class !== 'Other' && r.date_added.slice(0, 4) === year && (r.published || '').slice(0, 4) === year && r.publish_to_kev_days != null && r.publish_to_kev_days >= 0)
      .map((r) => r.publish_to_kev_days)
      .sort((a, b) => a - b);
    return [{
      as_of: newest,
      total: kev.length,
      ransomware_known: kev.filter((r) => r.ransomware === 'Known').length,
      added_30d: recent.length,
      edge_30d: recent.filter((r) => r.edge_class !== 'Other').length,
      weaponized_30d: recent.filter((r) => r.weaponized === 'Yes').length,
      ransomware_30d: recent.filter((r) => r.ransomware === 'Known').length,
      edge_vendors_30d: new Set(recent.filter((r) => r.edge_class !== 'Other').map((r) => r.vendor)).size,
      edge_lag_median: lags.length ? lags[Math.floor(lags.length / 2)] : null,
      edge_lag_n: lags.length,
    }];
  },
});

dash.calc('edge_lens', {
  title: 'Edge-device lens over KEV',
  description: 'KEV entries per edge-device class: totals, last 365 days, ransomware-linked, weaponized, and median days from CVE publication to KEV.',
  inputs: ['kev'],
  fn: (kev) => {
    const newest = kev.reduce((m, r) => (r.date_added > m ? r.date_added : m), '');
    const cut = new Date(Date.parse(newest + 'T00:00:00Z') - 365 * 864e5).toISOString().slice(0, 10);
    const by = new Map();
    for (const r of kev) by.set(r.edge_class, (by.get(r.edge_class) || []).concat([r]));
    return [...by].map(([edge_class, rs]) => {
      const lags = rs.map((r) => r.publish_to_kev_days).filter((x) => x != null && x >= 0).sort((a, b) => a - b);
      return {
        edge_class,
        cves: rs.length,
        added_365d: rs.filter((r) => r.date_added > cut).length,
        ransomware_known: rs.filter((r) => r.ransomware === 'Known').length,
        weaponized: rs.filter((r) => r.weaponized === 'Yes').length,
        median_lag_days: lags.length ? lags[Math.floor(lags.length / 2)] : null,
        last_added: rs.reduce((m, r) => (r.date_added > m ? r.date_added : m), ''),
      };
    }).sort((a, b) => b.added_365d - a.added_365d);
  },
});

dash.calc('ew_stats', {
  title: 'Pre-KEV early warning counts',
  description: 'Recent CVEs outside CISA KEV by highest evidence stage.',
  inputs: ['early_warning'],
  fn: (early_warning) => [{
    total: early_warning.length,
    exploited: early_warning.filter((r) => r.stage === 'Exploited').length,
    weaponized: early_warning.filter((r) => r.stage === 'Weaponized').length,
    edge: early_warning.filter((r) => r.edge_class !== 'Other').length,
  }],
});

dash.calc('cvss_shares', {
  title: 'CVSS band shares',
  description: 'Share of each CVSS band among all CVEs published in 12 months, all KEV entries, and ransomware-linked KEV entries.',
  inputs: ['cvss_bands'],
  fn: (cvss_bands) => {
    const sum = (k) => cvss_bands.reduce((s, r) => s + r[k], 0);
    const a = sum('all_cves_12m'), k = sum('kev_all'), r = sum('kev_ransomware');
    return cvss_bands.map((b) => ({
      band: b.band,
      order: b.order,
      all_cves_share: a ? b.all_cves_12m / a : null,
      kev_share: k ? b.kev_all / k : null,
      ransomware_share: r ? b.kev_ransomware / r : null,
    }));
  },
});

dash.calc('rw_stats', {
  title: 'Leak-site claims, 90 days',
  description: 'Claims in the 90 days to the snapshot against the prior 90 days, overall and for financial services.',
  inputs: ['ransomware_groups', 'ransomware_sectors'],
  fn: (ransomware_groups, ransomware_sectors) => {
    const last = ransomware_groups.reduce((s, g) => s + g.claims_last_90d, 0);
    const prior = ransomware_groups.reduce((s, g) => s + g.claims_prior_90d, 0);
    const fin = ransomware_sectors.find((s) => s.sector === 'Financial Services') || { claims_last_90d: 0, claims_prior_90d: 0 };
    const top = ransomware_groups.slice().sort((a, b) => b.claims_last_90d - a.claims_last_90d)[0] || {};
    return [{
      claims_90d: last,
      claims_prior_90d: prior,
      change: prior ? last / prior - 1 : null,
      financial_90d: fin.claims_last_90d,
      financial_prior_90d: fin.claims_prior_90d,
      financial_change: fin.claims_prior_90d ? fin.claims_last_90d / fin.claims_prior_90d - 1 : null,
      active_groups: ransomware_groups.filter((g) => g.claims_last_90d > 0).length,
      new_groups: ransomware_groups.filter((g) => g.status === 'New in window').length,
      top_group: top.group,
      top_group_claims: top.claims_last_90d,
      snapshot: ransomware_groups.reduce((m, g) => (g.last_seen > m ? g.last_seen : m), ''),
    }];
  },
});

dash.calc('nexus_counts', {
  title: 'ATT&CK groups by stated nexus',
  description: 'Groups per country nexus as ATT&CK states it, with state attribution and release additions.',
  inputs: ['attack_groups'],
  fn: (attack_groups) => [...attack_groups.reduce((m, g) => m.set(g.nexus, (m.get(g.nexus) || []).concat([g])), new Map())].map(([nexus, gs]) => ({
    nexus,
    groups: gs.length,
    state_attributed: gs.filter((g) => g.state_link === 'State-attributed').length,
    new_relationships: gs.reduce((s, g) => s + g.new_in_release, 0),
    new_groups: gs.filter((g) => g.new_group === 'Yes').length,
  })).sort((a, b) => b.groups - a.groups),
});

dash.calc('qir', {
  title: 'Requirement quality (QIR)',
  description: 'QIR = (Specificity x Decision x Feasibility) x (Relevance + Timeliness), each 1-4, maximum 512 (Fleurat et al. ch6).',
  inputs: ['pirs'],
  fn: (pirs) => pirs.map((p) => ({ pir_id: p.pir_id, core: p.S * p.D * p.F, qir: p.S * p.D * p.F * (p.R + p.T) })),
});

dash.calc('source_usage', {
  title: 'Items cited per source',
  description: 'Number of reporting items citing each source and the newest item date.',
  inputs: ['sources', 'items'],
  fn: (sources, items) => sources.map((s) => {
    const its = items.filter((i) => i.source_id === s.source_id);
    return { source_id: s.source_id, items_cited: its.length, newest_item: its.reduce((m, i) => (i.date > m ? i.date : m), '') };
  }),
});

dash.calc('vector_items', {
  title: 'Items per vector',
  description: 'Reporting items tagged to each vector and the newest item date.',
  inputs: ['items'],
  fn: (items) => [...items.filter((i) => i.vector).reduce((m, i) => m.set(i.vector, (m.get(i.vector) || []).concat([i])), new Map())].map(([vector, its]) => ({
    vector,
    items: its.length,
    newest_item: its.reduce((m, i) => (i.date > m ? i.date : m), ''),
  })),
});

dash.calc('latest_run', {
  title: 'Latest run',
  description: 'The newest entry in the hash-chained run ledger.',
  inputs: ['ledger'],
  fn: (ledger) => ledger.slice(-1),
});

// ---- The change log and the forecast record ----
dash.calc('run_changes', {
  title: 'Changes by run',
  description: 'Every change the validator logged (theater level and trend, judgment title, likelihood, severity, status, rank and horizon, indicator state, vector level and trend), newest first, with baseline rows left out and a plain-language line for each.',
  inputs: ['history', 'ledger'],
  fn: (history, ledger) => {
    const LV = { 5: 'CRITICAL', 4: 'HIGH', 3: 'ELEVATED', 2: 'GUARDED', 1: 'NORMAL' };
    const KIND = { theater: 'Theater', judgment: 'Judgment', indicator: 'Indicator', vector: 'Vector' };
    const FIELD = { threatcon: 'ThreatCon level', trend: 'trend', title: 'title', likelihood: 'likelihood', severity: 'severity', status: 'status', exec_rank: 'executive rank', horizon: 'horizon', state: 'state', level: 'level' };
    const show = (e, x) => (e.kind === 'theater' && e.field === 'threatcon' ? `${x} ${LV[x] || ''}`.trim() : String(x));
    const last = (ledger.slice(-1)[0] || {}).run_id;
    return history.filter((e) => e.from != null).map((e) => {
      const num = e.field === 'threatcon' || e.field === 'level';
      return {
        event_id: e.event_id, run_id: e.run_id, date: e.date, kind: KIND[e.kind] || e.kind, id: e.id, name: e.name, what: FIELD[e.field] || e.field,
        from: show(e, e.from), to: show(e, e.to),
        direction: num ? (+e.to > +e.from ? 'Raised' : 'Lowered') : '',
        latest: e.run_id === last ? 'Yes' : 'No',
      };
    }).reverse();
  },
});

dash.calc('run_summary', {
  title: 'Latest run against the one before',
  description: 'The newest ledger entry beside the previous one: changes logged in the run, net change in cited items, the last ThreatCon level change on record and the date the change log begins.',
  inputs: ['ledger', 'history'],
  fn: (ledger, history) => {
    const cur = ledger.slice(-1)[0] || {};
    const prev = ledger.slice(-2, -1)[0] || {};
    const moves = history.filter((e) => e.from != null);
    const lv = moves.filter((e) => e.kind === 'theater' && e.field === 'threatcon').slice(-1)[0];
    return [{
      run_id: cur.run_id || '', at: cur.at || '', kind: cur.kind || '', prev_run: prev.run_id || '', prev_at: prev.at || '',
      changes: moves.filter((e) => e.run_id === cur.run_id).length,
      baseline_set: history.filter((e) => e.from == null && e.run_id === cur.run_id).length,
      items: cur.items ?? null, items_delta: cur.items != null && prev.items != null ? cur.items - prev.items : null,
      changes_14d: moves.filter((e) => Date.parse(cur.at) - Date.parse(e.date + 'T00:00:00Z') <= 14 * 864e5).length,
      last_level_change: lv ? `${lv.name}: ${lv.from} to ${lv.to} on ${lv.date}` : '',
      record_from: history.length ? history[0].date : '',
    }];
  },
});

dash.calc('theater_history', {
  title: 'Theater level and trend history',
  description: 'For each theater, the date its current ThreatCon level and its current trend took effect and the value each replaced, read from the change log. A value unchanged since the log began carries the log\'s first date.',
  inputs: ['theaters', 'history'],
  fn: (theaters, history) => theaters.map((t) => {
    const ev = history.filter((e) => e.kind === 'theater' && e.id === t.theater_id);
    const lastOf = (f) => ev.filter((e) => e.field === f).slice(-1)[0];
    const lv = lastOf('threatcon'), tr = lastOf('trend');
    const part = (e, label) => (!e ? '' : e.from == null ? `${label} unchanged since the record began on ${e.date}` : `${label} since ${e.date}, from ${e.from}`);
    return {
      theater_id: t.theater_id,
      level_since: lv ? lv.date : '', level_from: lv && lv.from != null ? lv.from : '',
      trend_since: tr ? tr.date : '', trend_from: tr && tr.from != null ? tr.from : '',
      level_changes: ev.filter((e) => e.field === 'threatcon' && e.from != null).length,
      summary: [part(lv, `ThreatCon ${t.threatcon}`), part(tr, t.trend)].filter(Boolean).join('; ') || 'No history recorded',
    };
  }),
});

dash.calc('forecast_record', {
  title: 'Forecast record summary',
  description: 'Judgment horizons scored so far: counts by outcome and the mean Brier score, (p - outcome) squared with p the midpoint of the stated probability range, over outcomes that held or did not hold. A score of 0 is a certain, correct forecast; always saying 50% scores 0.25.',
  inputs: ['outcomes', 'judgments'],
  fn: (outcomes, judgments) => {
    const scored = outcomes.filter((o) => o.brier != null);
    const next = judgments.filter((j) => j.horizon && j.status !== 'Retired').map((j) => j.horizon).sort()[0] || '';
    return [{
      resolved: outcomes.length, held: outcomes.filter((o) => o.outcome === 'Held').length,
      not_held: outcomes.filter((o) => o.outcome === 'Did not hold').length,
      indeterminate: outcomes.filter((o) => o.outcome === 'Indeterminate').length,
      scored: scored.length, brier_mean: scored.length ? Math.round((scored.reduce((s, o) => s + o.brier, 0) / scored.length) * 1e4) / 1e4 : null,
      open: judgments.filter((j) => j.horizon && j.status !== 'Retired').length, next_horizon: next,
    }];
  },
});

// ---- Analysis of competing hypotheses over the ranked judgments ----
dash.calc('ach_matrix', {
  title: 'Competing hypotheses',
  description: 'For each ranked judgment, the judgment (H1) and each stated alternative, with the count of evidence items rated consistent, inconsistent or not diagnostic for it. H1 is read from each evidence row\'s role (Supports, Weakens, Context); the alternatives from the row\'s ach ratings. In this method the hypothesis with the least inconsistent evidence stands, so rows are ordered by inconsistent count within a judgment; unrated counts show how much of the evidence the analyst has yet to rate.',
  inputs: ['judgments', 'evidence'],
  fn: (judgments, evidence) => {
    const out = [];
    for (const j of judgments.filter((x) => (x.exec_rank || 0) > 0 && x.status !== 'Retired').sort((a, b) => a.exec_rank - b.exec_rank)) {
      const ev = evidence.filter((e) => e.judgment_id === j.judgment_id);
      const alts = [...String(j.alternatives || '').matchAll(/\bH(\d+):\s*([\s\S]*?)(?=\s*\bH\d+:|$)/g)].map((m) => ({ h: 'H' + m[1], text: m[2].trim() }));
      const rate = (e, h) => (h === 'H1' ? { Supports: 'C', Weakens: 'I', Context: 'N' }[e.role] : (String(e.ach || '').match(new RegExp('\\b' + h + ':([CIN])')) || [])[1]) || null;
      const rows = [{ h: 'H1', text: j.title }, ...alts].map((x) => {
        const r = ev.map((e) => rate(e, x.h));
        const n = (k) => r.filter((v) => v === k).length;
        return { key: j.judgment_id + '-' + x.h, judgment_id: j.judgment_id, exec_rank: j.exec_rank, hypothesis: x.h, text: x.text, consistent: n('C'), inconsistent: n('I'), neutral: n('N'), unrated: r.filter((v) => !v).length, evidence: ev.length,
          rated_share: ev.length ? Math.round(((ev.length - r.filter((v) => !v).length) / ev.length) * 1000) / 1000 : null };
      });
      const complete = rows.every((r) => r.unrated === 0), least = Math.min(...rows.map((r) => r.inconsistent));
      for (const r of rows) out.push({ ...r, standing: !complete ? 'rating incomplete' : r.inconsistent === least ? 'least inconsistent' : 'more inconsistent' });
    }
    return out;
  },
});

// ---- Lead feedback: what the analyst run did with the machine leads it opened ----
dash.calc('lead_use', {
  title: 'Lead feedback summary',
  description: 'Machine leads the analyst run opened, by what it did with them. Precision is the share used or already held (used + duplicate) over all leads opened; the same share is given for leads the triage tier labelled relevance 3.',
  inputs: ['leads'],
  fn: (leads) => {
    const n = (f) => leads.filter(f).length, good = (l) => l.disposition === 'used' || l.disposition === 'duplicate';
    const top = leads.filter((l) => l.relevance === 3);
    const share = (a, b) => (b ? Math.round((a / b) * 1000) / 1000 : null);
    return [{ opened: leads.length, used: n((l) => l.disposition === 'used'), duplicate: n((l) => l.disposition === 'duplicate'), rejected: n((l) => l.disposition === 'rejected'),
      wrong: n((l) => l.disposition === 'wrong'), precision: share(n(good), leads.length), top_opened: top.length, top_precision: share(top.filter(good).length, top.length),
      first: leads.map((l) => l.date).sort()[0] || '', last: leads.map((l) => l.date).sort().pop() || '' }];
  },
});

// ---- Citation verification ----
dash.calc('verification_summary', {
  title: 'Citation verification by state',
  description: 'Cited items by what an independent fetch of each URL found, with the share of fetched pages that carry the claim (excerpt found or claim supported) and the share of the evidence base that could be judged at all. Blocked, thin and error states are unverifiable from the workflow, which is said plainly.',
  inputs: ['verification'],
  fn: (v) => {
    const LABEL = { excerpt_found: 'Excerpt found on the page', claim_supported: 'Figures and names found on the page', weak_match: 'Partial match', mismatch: 'Page does not carry the claim',
      thin: 'Too little page text to judge', blocked: 'Site refused the request', gone: 'Page gone (404 or 410)', error: 'Fetch failed', pending: 'Not fetched yet' };
    const ORDER = Object.keys(LABEL);
    const n = v.length || 1;
    const count = (s) => v.filter((r) => r.state === s).length;
    const judged = count('excerpt_found') + count('claim_supported') + count('weak_match') + count('mismatch') + count('gone');
    const good = count('excerpt_found') + count('claim_supported');
    return ORDER.map((s) => ({ state: s, label: LABEL[s], items: count(s), share: count(s) / n,
      judged, judged_share: judged / n, supported: good, supported_share: judged ? good / judged : null,
      newest_check: v.map((r) => r.checked_at).filter(Boolean).sort().pop() || '' }));
  },
});

// ---- Per-vertical calibration and residual risk (every vertical computed; the page shows the selected one) ----
dash.calc('theater_calibrated', {
  title: 'Theater level by vertical',
  description: 'Each theater ThreatCon recomputed for every critical-infrastructure vertical: clamp(round(base x vertical weight), 1, 5). An analyst-set lens, not a measurement.',
  inputs: ['theaters', 'verticals'],
  fn: (theaters, verticals) => {
    const out = [];
    // A vertical's weights are a record, which the dashboard hands over as its JSON text.
    const weights = (x) => { if (x && typeof x === 'object') return x; try { return JSON.parse(x) || {}; } catch { return {}; } };
    for (const v of verticals) {
      for (const t of theaters) {
        const w = +weights(v.theater_w)[t.theater_id] || 1;
        const cal = Math.max(1, Math.min(5, Math.round(t.threatcon * w)));
        out.push({ key: v.vertical_id + '|' + t.theater_id, vertical_id: v.vertical_id, theater_id: t.theater_id, base: t.threatcon, weight: w, calibrated: cal, shifted: cal - t.threatcon });
      }
    }
    return out;
  },
});

dash.calc('vector_calibrated', {
  title: 'Vector level by vertical',
  description: 'Each vector inherent level recomputed per vertical: clamp(round(base x vertical weight), 1, 5).',
  inputs: ['vectors', 'verticals'],
  fn: (vectors, verticals) => {
    const out = [];
    // A vertical's weights are a record, which the dashboard hands over as its JSON text.
    const weights = (x) => { if (x && typeof x === 'object') return x; try { return JSON.parse(x) || {}; } catch { return {}; } };
    for (const v of verticals) {
      for (const vec of vectors) {
        const w = +weights(v.vector_w)[vec.vector_id] || 1;
        const cal = Math.max(1, Math.min(5, Math.round(vec.level * w)));
        out.push({ key: v.vertical_id + '|' + vec.vector_id, vertical_id: v.vertical_id, vector_id: vec.vector_id, vector: vec.vector, base: vec.level, weight: w, calibrated: cal });
      }
    }
    return out;
  },
});

dash.calc('asset_exposure', {
  title: 'Owned assets matched to exploited CVEs',
  description: 'Each asset from the AutoRecon inventory matched by vendor/product against KEV and the pre-KEV early-warning list; internet-facing assets with a match are the residual-risk surface.',
  inputs: ['assets', 'kev', 'early_warning'],
  fn: (assets, kev, early_warning) => {
    const norm = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9 ]/g, ' ').replace(/\s+/g, ' ').trim();
    const STOP = new Set(['data', 'center', 'secure', 'multiple', 'products', 'server', 'edition', 'subscription', 'series', 'switches', 'networks', 'inc', 'ltd', 'gmbh', 'the', 'and', 'os']);
    // Distinctive product tokens: everything in product+cpe except the vendor word and generic words.
    const distinct = (a) => {
      const vend = norm(a.product).split(' ')[0];
      return norm(a.product + ' ' + a.cpe).split(' ').filter((w) => w.length > 3 && w !== vend && !STOP.has(w));
    };
    const krows = kev.map((k) => ({ cve: k.cve, vendor: norm(k.vendor), product: norm(k.product), ransomware: k.ransomware, edge: k.edge_class }));
    const erows = early_warning.map((e) => ({ cve: e.cve, vendor: norm(e.vendor), product: norm(e.product) }));
    return assets.map((a) => {
      const vend = norm(a.product).split(' ')[0];
      const toks = distinct(a);
      // Match requires the vendor AND a distinctive product token, both in the catalog row.
      const hit = (r) => (r.vendor.includes(vend) || vend.includes(r.vendor.split(' ')[0])) && toks.some((t) => r.product.includes(t) || r.vendor.includes(t));
      const kmatch = krows.filter(hit);
      const ematch = erows.filter(hit);
      const cves = [...new Set(kmatch.map((m) => m.cve).concat(ematch.map((m) => m.cve)))];
      return {
        host: a.host, ip: a.ip, product: a.product, version: a.version, exposure: a.exposure, site: a.site, sample: a.sample,
        kev_cves: kmatch.length, ew_cves: ematch.length, total_cves: cves.length,
        ransomware_linked: kmatch.some((m) => m.ransomware === 'Known') ? 'Yes' : 'No',
        example_cve: (kmatch[0] || ematch[0] || {}).cve || '',
        at_risk: a.exposure === 'Internet-facing' && cves.length > 0 ? 'Yes' : 'No',
      };
    });
  },
});

dash.calc('residual_risk', {
  title: 'Residual risk by vector and vertical',
  description: 'Residual = inherent (vertical-calibrated vector level / 5) x exposure x (1 - control coverage). Exposure comes from the owned-asset match (exploitation, ransomware), the dark-web read (identity, fraud, insider), else a stated 0.6 default. Asset and control data are what turn the inherent read into residual risk (Thomas p178-183).',
  inputs: ['vector_calibrated', 'controls', 'asset_exposure', 'exposure_darkweb'],
  fn: (vector_calibrated, controls, asset_exposure, exposure_darkweb) => {
    const cov = new Map(controls.map((c) => [c.vector_id, c]));
    const facing = asset_exposure.filter((a) => a.exposure === 'Internet-facing');
    const expExploit = facing.length ? facing.filter((a) => a.at_risk === 'Yes').length / facing.length : 0.5;
    const stealer = (exposure_darkweb.find((e) => e.kind === 'Infostealer infections') || {}).metric || 0;
    const creds = (exposure_darkweb.find((e) => e.kind === 'Leaked credentials') || {}).metric || 0;
    const expIdentity = Math.max(0.3, Math.min(1, (stealer * 0.08) + (creds > 0 ? 0.45 : 0)));
    const rwMention = (exposure_darkweb.find((e) => e.kind === 'Ransomware mention') || {}).metric || 0;
    const rwShare = facing.length ? facing.filter((a) => a.ransomware_linked === 'Yes').length / facing.length : 0;
    const r2 = (x) => Math.round(x * 100) / 100;
    const expByVector = {
      'V-EXP': [expExploit, `${facing.filter((a) => a.at_risk === 'Yes').length} of ${facing.length} internet-facing assets carry an exploited CVE`],
      'V-RAN': rwMention
        ? [1, `${rwMention} leak-site listing${rwMention === 1 ? '' : 's'} name the organization`]
        : [Math.min(1, 0.3 + 0.5 * rwShare + (creds > 0 ? 0.2 : 0)), `0.3 floor + ransomware-linked facing share ${r2(rwShare)} + leaked credentials ${creds > 0 ? 'present' : 'absent'}`],
      'V-IDN': [expIdentity, `${stealer} infostealer infections, ${creds} leaked credentials`],
      'V-FRA': [Math.min(1, expIdentity * 0.9), 'identity exposure x 0.9'],
      'V-INS': [Math.min(1, 0.4 + stealer * 0.05), `0.4 floor + ${stealer} infostealer infections x 0.05`],
    };
    const out = [];
    for (const vc of vector_calibrated) {
      const c = cov.get(vc.vector_id) || { coverage: 0.5, csf: '', basis: '' };
      const [exposure, exposure_basis] = expByVector[vc.vector_id] || [0.6, 'default: no owned-asset or dark-web signal maps to this vector'];
      const inherent = vc.calibrated / 5;
      const residual = inherent * exposure * (1 - c.coverage);
      out.push({
        key: vc.vertical_id + '|' + vc.vector_id, vertical_id: vc.vertical_id, vector_id: vc.vector_id, vector: vc.vector,
        inherent: Math.round(inherent * 100) / 100, exposure: Math.round(exposure * 100) / 100,
        exposure_basis, coverage: c.coverage, csf: c.csf, residual: Math.round(residual * 100) / 100,
        band: residual >= 0.4 ? 'High' : residual >= 0.2 ? 'Medium' : 'Low',
      });
    }
    return out;
  },
});

dash.calc('residual_summary', {
  title: 'Residual-risk summary',
  description: 'Owned internet-facing assets, how many carry an exploited CVE, and dark-web exposure counts, for the residual-risk header.',
  inputs: ['asset_exposure', 'exposure_darkweb'],
  fn: (asset_exposure, exposure_darkweb) => {
    const facing = asset_exposure.filter((a) => a.exposure === 'Internet-facing');
    return [{
      assets: asset_exposure.length,
      internet_facing: facing.length,
      at_risk: facing.filter((a) => a.at_risk === 'Yes').length,
      ransomware_linked: asset_exposure.filter((a) => a.ransomware_linked === 'Yes').length,
      stealer: (exposure_darkweb.find((e) => e.kind === 'Infostealer infections') || {}).metric || 0,
      creds: (exposure_darkweb.find((e) => e.kind === 'Leaked credentials') || {}).metric || 0,
      sample: asset_exposure.some((a) => a.sample),
    }];
  },
});

