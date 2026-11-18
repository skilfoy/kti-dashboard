/* Method: confidence workings, doctrine traceability, run ledger, STIX 2.1 export. */
(() => {
  // Deterministic, format-valid UUIDs so the same judgment exports with the same STIX id every run.
  const uuid = (s) => {
    let a = 0x811c9dc5, b = 0x01000193, out = '';
    for (let k = 0; k < 4; k++) {
      let x = a ^ k;
      for (let i = 0; i < s.length; i++) { x ^= s.charCodeAt(i); x = Math.imul(x, b) >>> 0; }
      out += x.toString(16).padStart(8, '0');
    }
    return `${out.slice(0, 8)}-${out.slice(8, 12)}-5${out.slice(13, 16)}-${((parseInt(out[16], 16) & 3) | 8).toString(16)}${out.slice(17, 20)}-${out.slice(20, 32)}`;
  };
  const TLP_GREEN = 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da'; // STIX 2.1's TLP:GREEN marking definition
  const CONF = { HIGH: 85, MEDIUM: 50, LOW: 15 };

  function stix(judgments, confidence, evidence, items, ledger) {
    const at = (ledger.slice(-1)[0] || {}).at || '2026-10-16T00:00:00Z';
    const ident = `identity--${uuid('producer')}`;
    const pap = `marking-definition--${uuid('PAP:AMBER')}`;
    const conf = new Map(confidence.map((c) => [c.judgment_id, c]));
    const byItem = new Map(items.map((i) => [i.item_id, i]));
    const objects = [
      { type: 'identity', spec_version: '2.1', id: ident, created: at, modified: at, name: 'Global threat intelligence (open-source analysis)', identity_class: 'organization' },
      { type: 'marking-definition', spec_version: '2.1', id: pap, created: at, definition_type: 'statement', name: 'PAP:AMBER', definition: { statement: 'PAP:AMBER: passive, non-attributable actions only.' } },
    ];
    for (const j of judgments) {
      const c = conf.get(j.judgment_id) || {};
      const refs = evidence.filter((e) => e.judgment_id === j.judgment_id).map((e) => byItem.get(e.item_id)).filter(Boolean);
      objects.push({
        type: 'report', spec_version: '2.1', id: `report--${uuid(j.judgment_id)}`, created_by_ref: ident, created: at, modified: at,
        name: `${j.judgment_id}: ${j.title}`, description: `${j.assessment} ${j.cta}`, report_types: ['threat-report'], published: at,
        confidence: CONF[c.confidence] ?? 15, labels: [j.likelihood, `confidence:${c.confidence || 'LOW'}`, `severity:${j.severity}`],
        object_refs: [ident], object_marking_refs: [TLP_GREEN, pap],
        external_references: refs.map((i) => ({ source_name: i.source_name, url: i.url, description: `${i.date} ${i.title} [${i.grade}, ${i.veracity}]` })),
        x_likelihood: j.likelihood, x_probability: j.probability, x_horizon: j.horizon || null, x_nist_csf: j.csf, x_pirs: j.pirs,
      });
    }
    return JSON.stringify({ type: 'bundle', id: `bundle--${uuid('bundle' + at)}`, objects }, null, 2);
  }

  TI.page('method', (sec) => {
    // Credibility and RSIT on the threat map (intel.js).
    if (TI.intel) TI.intel.methodCards(sec);
    // Forecast record and change log (changes.js).
    if (TI.changes) TI.changes.method(sec);
    const tc = sec.querySelector('#tbl-conf');
    if (TI.tableState(tc, ['confidence'])) {
      TI.table(tc, TI.rows('confidence'), [
        { field: 'judgment_id', label: 'Judgment', cls: 'ti-nowrap' },
        { field: 'supporting', label: 'Supporting', num: true },
        { field: 'origins', label: 'Origins', num: true },
        { field: 'categories', label: 'Categories', num: true },
        { field: 'mean_score', label: 'Mean score', num: true, fmt: 'dec2' },
        { field: 'alternative', label: 'Alternative' },
        { field: 'capped', label: 'Capped' },
        { field: 'confidence', label: 'Confidence' },
      ], { sort: 'judgment_id', dir: 'asc' });
    }
    const tm = sec.querySelector('#tbl-method');
    if (TI.tableState(tm, ['method'])) {
      TI.table(tm, TI.rows('method'), [
        { field: 'rule_id', label: 'Rule', cls: 'ti-nowrap' },
        { field: 'area', label: 'Area' },
        { field: 'design_choice', label: 'Design choice', cls: 'ti-wrap' },
        { field: 'source', label: 'Source in the library', cls: 'ti-wrap' },
        { field: 'where', label: 'Where on the dashboard', hideSm: true },
      ], {});
    }
    const tl = sec.querySelector('#tbl-ledger');
    if (TI.tableState(tl, ['ledger'])) {
      TI.table(tl, TI.rows('ledger'), [
        { field: 'run_id', label: 'Run', cls: 'ti-nowrap ti-mono' },
        { field: 'at', label: 'At (UTC)', cls: 'ti-nowrap' },
        { field: 'kind', label: 'Kind' },
        { field: 'validator', label: 'Validator' },
        { field: 'items', label: 'Items', num: true },
        { field: 'judgments', label: 'Judgments', num: true },
        { field: 'catalogs', label: 'Catalogs', cls: 'ti-wrap', hideSm: true },
        { field: 'prev_hash', label: 'Previous hash', cls: 'ti-mono', hideSm: true },
        { field: 'hash', label: 'Hash', cls: 'ti-mono' },
      ], { sort: 'run_id', dir: 'desc' });
    }
    const adv = sec.querySelector('#stix-adv-out');
    if (adv) {
      if (TI.failed('live_psirt')) adv.value = 'The advisory document is unavailable.';
      else if (TI.ready('live_psirt')) { const m = TI.rows('live_psirt').find((r) => r.kind === 'meta') || {}; adv.value = stixAdvisories(TI.rows('live_psirt').filter((r) => r.kind === 'advisory'), m.generated || new Date().toISOString()); }
    }
    const out = sec.querySelector('#stix-out');
    const ids = ['judgments', 'confidence', 'evidence', 'items', 'ledger'];
    if (TI.failed(...ids)) out.value = 'Failed to load';
    else if (TI.ready(...ids)) out.value = stix(TI.rows('judgments'), TI.rows('confidence'), TI.rows('evidence'), TI.rows('items'), TI.rows('ledger'));
    if (TI.catalog) TI.catalog.draw(sec);
  });
  dash.onData(() => TI.draw('method'));
  TI.root.addEventListener('focusin', (ev) => { if (ev.target.id === 'stix-out' || ev.target.id === 'stix-adv-out') ev.target.select(); });
  // Advisories as STIX 2.1: vulnerability objects by CVE and one report per advisory.
  function stixAdvisories(rows, at) {
    const ident = `identity--${uuid('producer')}`;
    const objects = [{ type: 'identity', spec_version: '2.1', id: ident, created: at, modified: at, name: 'Global threat intelligence (open-source analysis)', identity_class: 'organization' }];
    const seen = new Map();
    const vuln = (cve, kev) => {
      if (!seen.has(cve)) {
        const o = { type: 'vulnerability', spec_version: '2.1', id: `vulnerability--${uuid(cve)}`, created_by_ref: ident, created: at, modified: at, name: cve, object_marking_refs: [TLP_GREEN],
          external_references: [{ source_name: 'cve', external_id: cve }] };
        seen.set(cve, o); objects.push(o);
      }
      if (kev) seen.get(cve).labels = ['cisa-kev'];
      return seen.get(cve).id;
    };
    for (const a of rows) {
      // List cells arrive as JSON text from the runtime (app.js TI.list).
      const kev = new Set(TI.list(a.kev));
      const refs = TI.list(a.cves).map((c) => vuln(c, kev.has(c)));
      if (!refs.length) continue;
      const when = a.published || a.first_seen || at;
      objects.push({ type: 'report', spec_version: '2.1', id: `report--${uuid(a.link)}`, created_by_ref: ident, created: when, modified: when, published: when, name: a.title, report_types: ['vulnerability'],
        labels: ['vendor-advisory'].concat(kev.size ? ['names-kev-cve'] : []), object_refs: refs, object_marking_refs: [TLP_GREEN], external_references: [{ source_name: a.vendor || a.feed, url: a.link }] });
    }
    return JSON.stringify({ type: 'bundle', id: `bundle--${uuid('advisories ' + at.slice(0, 10))}`, objects }, null, 1);
  }
  TI.stixAdvisories = stixAdvisories;
})();
