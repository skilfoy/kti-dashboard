/* Collector documents on the page (threat-feeds /api/context and /api/enrich, live.js loaders): NASA FIRMS thermal
   anomalies, maritime source status, the Lanes outlet registry, SEC Form 8-K cybersecurity disclosures, the
   ThreatCluster leak-site cross-check, Ransomwhere payments, Unit 42 and Gen Threat Labs notes, the corroboration
   lists, link health, CTI blog candidates, the feed volume baseline, gated sources, the credibility method and
   on-demand enrichment. Each document arrives as one "meta" row with its own source, terms and method, then its rows;
   list and record cells are JSON text (TI.list, TI.obj). Nothing here states more than the document holds. */
(() => {
  const { h, v } = TI;
  const I = (TI.intel = {});
  const a = (href, text, title) => (href ? h('a', { href, target: '_blank', rel: 'noopener noreferrer', text, title: title || null }) : h('span', { text }));
  const kindRows = (id, kind) => (TI.ready(id) ? (TI.rows(id) || []).filter((r) => r.kind === kind) : []);
  const dataRows = (id) => (TI.ready(id) ? (TI.rows(id) || []).filter((r) => r.kind !== 'meta') : []);
  const metaOf = (id) => (TI.ready(id) ? (TI.rows(id) || []).find((r) => r.kind === 'meta') || null : null);
  const cname = (cc) => (window.TI_ISONAME && window.TI_ISONAME[cc]) || cc || '';
  const int = (x) => TI.f.int(x);
  const tnames = () => (TI.ready('theaters') ? TI.index(TI.rows('theaters'), 'theater_id') : new Map());
  const tname = (id) => { const t = tnames().get(id); return t ? t.short || t.name : id; };
  // How fresh a collector document is, in words: its collection time and whether the service marked it stale.
  const fresh = (m) => {
    if (!m) return '';
    const at = String(m.generated || '').slice(0, 16).replace('T', ' ');
    const age = m.age_min == null ? '' : m.age_min < 90 ? `${m.age_min} min ago` : m.age_min < 2880 ? `${Math.round(m.age_min / 60)} h ago` : `${Math.round(m.age_min / 1440)} days ago`;
    return (at ? `collected ${at}Z` : '') + (age ? ` (${age})` : '') + (m.stale ? ', past its refresh window' : '');
  };
  const setCount = (sec, id, text) => { const el = sec.querySelector('#' + id); if (el) el.textContent = text || ''; };
  // A card note filled from the document itself (its method or caveat), replaced on every draw.
  const note = (sec, id, ...kids) => { const el = sec.querySelector('#' + id); if (!el) return; TI.clear(el); el.append(...kids.flat().filter((k) => k != null && k !== '')); };
  const stateLine = (ids) => (TI.failed(...ids) ? 'Feed unavailable.' : null);

  // ---------------------------------------------------------------- theater detail rows (context.js calls these)
  I.theaterRows = (row, t) => {
    const w = { kind: 'aoi', id: t.theater_id };
    // NASA FIRMS thermal anomalies in the theater's area of interest.
    if (TI.failed('live_fires')) row('Thermal anomalies', 'NASA FIRMS feed unavailable.');
    else if (!TI.ready('live_fires')) row('Thermal anomalies', h('span', { class: 'dash-skeleton', text: 'Loading' }));
    else {
      const ao = kindRows('live_fires', 'aoi').find((x) => x.id === t.theater_id);
      if (ao && ao.ok === false) row('Thermal anomalies', `FIRMS did not answer for this area at the last run: ${ao.error || 'no reason given'}.`);
      else if (ao) {
        const byCc = Object.entries(TI.obj(ao.by_cc)).sort((x, y) => y[1] - x[1]).map(([cc, n]) => `${cname(cc)} ${int(n)}`).join(', ');
        const base = ao.median_daily != null
          ? h('span', {}, `; yesterday ${int(ao.yesterday)} against a ${int(ao.baseline_days)}-day median of ${int(ao.median_daily)} (ratio `, v('strong', 'live_fires', 'ratio', w, ao.ratio == null ? '—' : TI.f.dec2(ao.ratio)), ')')
          : `; daily baseline building (${int(ao.baseline_days)} days held)`;
        const novel = ao.novelty_judged ? h('span', {}, '; ', v('strong', 'live_fires', 'novel_cells', w, int(ao.novel_cells)), ' novel cells (no detection in the 30 days before)')
          : '; novel cells are judged once the collector holds 7 days of cells';
        row('Thermal anomalies', h('span', {}, v('strong', 'live_fires', 'detections', w, int(ao.detections)), ` VIIRS detections in 24 hours (${int(ao.high)} high confidence, ${int(ao.frp)} MW radiative power) in ${int(ao.cells)} 0.1-degree cells`,
          byCc ? ` (${byCc})` : '', base, novel, '. '), a('https://firms.modaps.eosdis.nasa.gov/map/', 'NASA FIRMS map'),
        h('span', { class: 'ti-ctx-note', text: ' A detection is a fire or hot spot of any cause; only corroboration ties one to a strike.' }));
      }
    }
    // Maritime security sources, for a theater with a shipping chokepoint or maritime records.
    const mt = kindRows('live_maritime', 'theater').find((x) => x.theater_id === t.theater_id);
    const seaTheater = mt || (TI.ready('chokepoints') && TI.rows('chokepoints').some((c) => c.theater_id === t.theater_id));
    if (seaTheater) {
      if (TI.failed('live_maritime')) row('Maritime security', 'Maritime feed unavailable.');
      else if (!TI.ready('live_maritime')) row('Maritime security', h('span', { class: 'dash-skeleton', text: 'Loading' }));
      else {
        const src = kindRows('live_maritime', 'source');
        const okSrc = src.filter((s) => s.ok);
        const counts = mt ? `${int(mt.advisories)} advisories in force, ${int(mt.incidents_30d)} ASAM incidents in 30 days, ${int(mt.warnings)} navigational warnings (${int(mt.warn_hostile)} hostile, ${int(mt.warn_mines)} mines, ${int(mt.warn_gnss)} GNSS, ${int(mt.warn_military)} military). ` : '';
        const down = src.filter((s) => !s.ok).map((s) => `${s.id} ${s.stale ? 'stale' : 'unavailable'}`).join(', ');
        row('Maritime security', h('span', {}, counts, okSrc.length ? '' : 'No maritime source is current: ', down ? down + '. ' : ''),
          h('span', { class: 'ti-ctx-note', text: 'The Theaters page lists what each source answered.' }));
      }
    }
    // Lanes outlet registry: which presses Lanes reads for this theater's pairs, and whose wording each lane uses.
    if (TI.ready('live_lanesreg', 'live_lanes') && TI.ctx && TI.ctx.lanesFor) {
      const pairs = TI.ctx.lanesFor(t.theater_id).map((r) => r.conflict);
      if (pairs.length) {
        const outlets = kindRows('live_lanesreg', 'outlet').filter((o) => pairs.some((c) => String(o.lanes || '').includes(c + ':')));
        const naming = kindRows('live_lanesreg', 'naming').filter((n) => pairs.includes(n.conflict) && (n.uses_a || n.uses_b));
        const top = [...new Set(naming.map((n) => n.conflict + '|' + n.refers_to))].slice(0, 2).map((k) => {
          const [c, ref] = k.split('|');
          const ls = naming.filter((n) => n.conflict === c && n.refers_to === ref);
          return `"${ref}": ` + ls.map((n) => `${n.lane_label} ${int(n.uses_a)} "${String(n.side_a).split(' / ')[0]}" to ${int(n.uses_b)} "${String(n.side_b).split(' / ')[0]}"`).join('; ');
        });
        if (outlets.length) row('Press lanes', h('span', {}, `Lanes reads ${int(outlets.length)} outlets for this theater's pairs.`, top.length ? ' Naming over 14 days, ' + top.join('. ') + '.' : ' No naming counts in the last 14 days.'),
          h('span', { class: 'ti-ctx-note', text: ' (Lanes outlet registry and naming choices, CC BY 4.0)' }));
      }
    }
  };

  // ---------------------------------------------------------------- theater page cards
  I.theaterCards = (sec) => {
    const tf = sec.querySelector('#tbl-fires');
    if (tf && TI.tableState(tf, ['live_fires'])) {
      const m = metaOf('live_fires');
      setCount(sec, 'fires-asof', fresh(m));
      note(sec, 'fires-note', m ? [m.method || '', ' ', m.credit || ''] : '');
      TI.table(tf, kindRows('live_fires', 'aoi'), [
        { field: 'name', label: 'Area of interest', get: (r) => r.name || tname(r.id), cls: 'ti-wrap' },
        { field: 'detections', label: 'Detections, 24h', num: true, fmt: 'int' },
        { field: 'high', label: 'High confidence', num: true, fmt: 'int', hideSm: true },
        { field: 'frp', label: 'FRP, MW', num: true, fmt: 'int', hideSm: true },
        { field: 'cells', label: 'Cells', num: true, fmt: 'int', hideSm: true },
        { field: 'novel_cells', label: 'Novel cells', num: true, get: (r) => (r.novelty_judged ? r.novel_cells : null), fmt: 'int' },
        { field: 'yesterday', label: 'Yesterday', num: true, fmt: 'int', hideSm: true },
        { field: 'median_daily', label: 'Daily median', num: true, fmt: 'int' },
        { field: 'ratio', label: 'Ratio', num: true, fmt: 'dec2' },
        { field: 'baseline_days', label: 'Baseline days', num: true, fmt: 'int', hideSm: true },
        { field: 'by_cc', label: 'By country', get: (r) => Object.entries(TI.obj(r.by_cc)).sort((x, y) => y[1] - x[1]).map(([cc, n]) => `${cc} ${n}`).join(', '), cls: 'ti-wrap', hideSm: true },
        { field: 'error', label: 'Note', get: (r) => (r.ok === false ? r.error || 'no answer' : ''), hideSm: true },
      ], { sort: 'detections', dir: 'desc', empty: 'FIRMS returned no areas.' });
    }
    const tm = sec.querySelector('#tbl-maritime');
    if (tm && TI.tableState(tm, ['live_maritime'])) {
      const m = metaOf('live_maritime');
      setCount(sec, 'maritime-asof', fresh(m));
      const src = kindRows('live_maritime', 'source');
      const live = src.filter((s) => s.ok).length;
      note(sec, 'maritime-note', live ? `${live} of ${src.length} maritime sources answered at the last run. ` : `None of the ${src.length} maritime sources gives current data from the collector's network: each row says what it answered. Maritime warnings and incidents stay off the map until one does. `, m ? m.method || '' : '');
      TI.table(tm, src, [
        { field: 'id', label: 'Source', link: 'url' },
        { field: 'ok', label: 'State', get: (r) => (r.ok ? 'Current' : r.stale ? 'Stale' : 'Unavailable') },
        { field: 'status', label: 'HTTP', num: true, hideSm: true },
        { field: 'n', label: 'Records', num: true, fmt: 'int', hideSm: true },
        { field: 'newest', label: 'Newest record', fmt: 'date', hideSm: true },
        { field: 'error', label: 'What it answered', cls: 'ti-wrap' },
      ], { empty: 'The maritime document lists no sources.' });
    }
    const to = sec.querySelector('#tbl-lanes-outlets');
    if (to && TI.tableState(to, ['live_lanesreg'])) {
      const m = metaOf('live_lanesreg');
      setCount(sec, 'lanesreg-asof', fresh(m));
      note(sec, 'lanesreg-note', m ? [m.method || '', ' ', m.credit || ''] : '');
      TI.table(to, kindRows('live_lanesreg', 'outlet'), [
        { field: 'name', label: 'Outlet', link: 'homepage', cls: 'ti-wrap' },
        { field: 'country_name', label: 'Country' },
        { field: 'language', label: 'Language', hideSm: true },
        { field: 'funding', label: 'Funding' },
        { field: 'ownership', label: 'Ownership', cls: 'ti-wrap', hideSm: true },
        { field: 'lanes', label: 'Lanes', cls: 'ti-wrap' },
      ], { sort: 'country_name', dir: 'asc', limit: 150, empty: 'Lanes listed no outlets.' });
    }
    const tn = sec.querySelector('#tbl-lanes-naming');
    if (tn && TI.tableState(tn, ['live_lanesreg'])) {
      TI.table(tn, kindRows('live_lanesreg', 'naming'), [
        { field: 'conflict', label: 'Pair' },
        { field: 'refers_to', label: 'Refers to', cls: 'ti-wrap' },
        { field: 'lane_label', label: 'Lane' },
        { field: 'side_a', label: 'Side A wording', cls: 'ti-wrap', hideSm: true },
        { field: 'uses_a', label: 'Uses A', num: true, fmt: 'int' },
        { field: 'side_b', label: 'Side B wording', cls: 'ti-wrap', hideSm: true },
        { field: 'uses_b', label: 'Uses B', num: true, fmt: 'int' },
        { field: 'last', label: 'Latest day', fmt: 'date', hideSm: true },
      ], { sort: 'uses_a', dir: 'desc', limit: 150, empty: 'Lanes gave no naming counts.' });
    }
  };

  // ---------------------------------------------------------------- ransomware page
  const disclosure = (r) => (r.item_105 ? (r.amendment ? 'Item 1.05 amendment' : 'Item 1.05') : r.item_801 ? 'Item 8.01 candidate' : TI.list(r.items).join(', '));
  I.ransomwareCards = (sec) => {
    const ts = sec.querySelector('#tbl-sec8k');
    if (ts && TI.tableState(ts, ['live_sec8k'])) {
      const m = metaOf('live_sec8k') || {};
      const w = { kind: 'meta' };
      setCount(sec, 'sec8k-asof', fresh(m));
      note(sec, 'sec8k-sum', v('strong', 'live_sec8k', 'item_105_90d', w, int(m.item_105_90d)), ' material cybersecurity incident disclosures under Item 1.05 in 90 days (',
        v('strong', 'live_sec8k', 'item_105_30d', w, int(m.item_105_30d)), ' in 30), ', v('strong', 'live_sec8k', 'item_801_90d', w, int(m.item_801_90d)),
        ' Item 8.01 filings whose own text names an incident, to read before treating as disclosures, and ', v('strong', 'live_sec8k', 'financial_90d', w, int(m.financial_90d)), ' filers in financial services.');
      note(sec, 'sec8k-note', m.method || '', ' ', m.terms || '');
      const kind = sec.querySelector('#sec8k-kind');
      const k = kind ? kind.value : '';
      TI.table(ts, dataRows('live_sec8k'), [
        { field: 'filed', label: 'Filed', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'company', label: 'Filer', link: 'doc_url', cls: 'ti-wrap' },
        { field: 'ticker', label: 'Ticker', hideSm: true },
        { field: 'item_105', label: 'Disclosure', get: disclosure },
        { field: 'sector', label: 'Sector', hideSm: true },
        { field: 'in_8k_text', label: 'Terms in the 8-K text', get: (r) => TI.list(r.in_8k_text).join(', '), hideSm: true },
        { field: 'score', label: 'Score', num: true, fmt: 'int', hideSm: true },
        { field: 'state', label: 'State', hideSm: true },
        { field: 'url', label: 'Filing index', link: 'url', get: (r) => (r.url ? 'EDGAR' : ''), hideSm: true },
      ], { sort: 'filed', dir: 'desc', empty: 'No filings in the window.', countEl: sec.querySelector('#sec8k-count'),
        filter: (r) => !k || (k === '105' ? r.item_105 : r.item_801) });
    }
    const tl = sec.querySelector('#tbl-leaksites');
    if (tl && TI.tableState(tl, ['live_leaksites'])) {
      const m = metaOf('live_leaksites') || {};
      const t = TI.obj(m.totals), win = TI.obj(m.window);
      setCount(sec, 'leak-asof', fresh(m));
      note(sec, 'leak-sum', `Of ransomware.live's ${int(t.rl_window)} newest claims (${String(win.from || '').slice(0, 10)} to ${String(win.to || '').slice(0, 10)}), `,
        v('strong', 'live_leaksites', null, null, int(t.both)), ` match a ThreatCluster row and ${int(t.both_first_party)} match a row ThreatCluster read off the leak site itself; `,
        `only the second count is independent corroboration. ThreatCluster holds ${int(t.tc_30d)} claims in 30 days, ${int(t.tc_first_party_30d)} first-party, ${int(t.tc_delisted_30d)} delisted.`);
      note(sec, 'leak-note', m.caveat || '', ' ', m.method || '', ' ', m.terms || '');
      TI.table(tl, dataRows('live_leaksites'), [
        { field: 'group', label: 'Group', link: 'tc_url' },
        { field: 'tc_30d', label: 'Claims, 30d', num: true, fmt: 'int' },
        { field: 'tc_first_party_30d', label: 'First-party, 30d', num: true, fmt: 'int', hideSm: true },
        { field: 'rl_window', label: 'ransomware.live, window', num: true, fmt: 'int' },
        { field: 'both', label: 'Matched', num: true, fmt: 'int', hideSm: true },
        { field: 'corroboration_first_party', label: 'First-party corroboration, %', num: true, fmt: 'int' },
        { field: 'corroboration', label: 'Any-row match, %', num: true, fmt: 'int', hideSm: true },
        { field: 'active', label: 'Site up', get: (r) => (r.active ? 'Yes' : 'No'), hideSm: true },
        { field: 'last_seen', label: 'Last seen', fmt: 'date', hideSm: true },
        { field: 'tc_delisted_30d', label: 'Delisted, 30d', num: true, fmt: 'int', hideSm: true },
      ], { sort: 'tc_30d', dir: 'desc', limit: 60, empty: 'The cross-check returned no groups.', countEl: sec.querySelector('#leak-count') });
    }
    const tp = sec.querySelector('#tbl-ransompay');
    if (tp && TI.tableState(tp, ['live_ransompay'])) {
      const m = metaOf('live_ransompay') || {};
      const t = TI.obj(m.totals);
      setCount(sec, 'pay-asof', fresh(m));
      note(sec, 'pay-sum', 'Historical: the newest transaction in the dataset is dated ', v('strong', 'live_ransompay', 'newest_tx', { kind: 'meta' }, String(m.newest_tx || '—')),
        `, so it measures past payments, not the current market. ${int(t.addresses)} addresses, ${int(t.transactions)} transactions, $${int(t.usd)} at transaction-time rates across ${int(m.families)} families.`);
      note(sec, 'pay-note', m.caveat || '', ' ', m.terms || '');
      TI.table(tp, dataRows('live_ransompay').filter((r) => r.transactions > 0), [
        { field: 'family', label: 'Family' },
        { field: 'usd', label: 'USD', num: true, fmt: 'int' },
        { field: 'transactions', label: 'Transactions', num: true, fmt: 'int' },
        { field: 'addresses', label: 'Addresses', num: true, fmt: 'int', hideSm: true },
        { field: 'first', label: 'First', fmt: 'date', hideSm: true },
        { field: 'last', label: 'Last', fmt: 'date' },
      ], { sort: 'usd', dir: 'desc', limit: 40, empty: 'Ransomwhere returned no families.' });
    }
  };

  // ---------------------------------------------------------------- actors page
  const iocText = (c) => { const o = TI.obj(c); return [['url', 'URLs'], ['domain', 'domains'], ['ip', 'IPs'], ['sha256', 'SHA-256'], ['sha1', 'SHA-1'], ['md5', 'MD5'], ['email', 'email']].filter(([k]) => o[k]).map(([k, l]) => `${o[k]} ${l}`).join(', ') || 'none counted'; };
  I.actorsCards = (sec) => {
    const tu = sec.querySelector('#tbl-unit42');
    if (tu && TI.tableState(tu, ['live_unit42'])) {
      const m = metaOf('live_unit42') || {};
      setCount(sec, 'u42-asof', fresh(m));
      note(sec, 'u42-note', `${int(m.posts_2026)} notes in 2026, newest ${m.newest || '—'}. `, m.method || '', ' ', m.terms || '');
      TI.table(tu, dataRows('live_unit42'), [
        { field: 'date', label: 'Date', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'title', label: 'Note', link: 'url', cls: 'ti-wrap' },
        { field: 'counts', label: 'Indicators counted', get: (r) => iocText(r.counts), cls: 'ti-wrap', hideSm: true },
        { field: 'references', label: 'References', num: true, fmt: 'int', hideSm: true },
      ], { sort: 'date', dir: 'desc', limit: 60, empty: 'Unit 42 listed no notes.' });
    }
    const tg = sec.querySelector('#tbl-genioc');
    if (tg && TI.tableState(tg, ['live_genioc'])) {
      const m = metaOf('live_genioc') || {};
      setCount(sec, 'gen-asof', fresh(m));
      note(sec, 'gen-note', m.attribution || '', ' Last commit ', String(m.last_commit || '—').slice(0, 10), '. ', m.method || '');
      TI.table(tg, dataRows('live_genioc'), [
        { field: 'family', label: 'Family', link: 'url' },
        { field: 'sha256', label: 'SHA-256', num: true, fmt: 'int' },
        { field: 'network', label: 'Network', num: true, fmt: 'int' },
        { field: 'yara', label: 'YARA', num: true, fmt: 'int', hideSm: true },
        { field: 'files', label: 'Files', num: true, fmt: 'int', hideSm: true },
      ], { sort: 'sha256', dir: 'desc', empty: 'Gen Threat Labs listed no families.' });
    }
  };
  // ORKL report search for the selected group, run on request (live_enrich, type actor).
  I.actorEnrich = (el, g) => {
    const box = h('div', { class: 'ti-enrich-inline', 'data-source': 'live_enrich' });
    const btn = h('button', { type: 'button', class: 'ti-more', text: 'Search ORKL reports for ' + g.name });
    btn.addEventListener('click', () => I.enrich('actor', g.name));
    box.append(btn);
    const res = I.enrichResults('actor', g.name);
    if (res) box.append(res);
    el.append(box);
  };

  // ---------------------------------------------------------------- sources page
  I.sourcesCards = (sec) => {
    const tl = sec.querySelector('#tbl-lists');
    if (tl && TI.tableState(tl, ['live_lists'])) {
      const m = metaOf('live_lists') || {};
      setCount(sec, 'lists-asof', fresh(m));
      note(sec, 'lists-sum', v('strong', 'live_lists', 'listed_hosts', { kind: 'meta' }, int(m.listed_hosts)), ` of the ${int(m.hosts)} mapped IPv4 hosts appear on at least one list. `, m.method || '');
      TI.table(tl, dataRows('live_lists'), [
        { field: 'name', label: 'List', link: 'url', cls: 'ti-wrap' },
        { field: 'operator', label: 'Operator' },
        { field: 'role', label: 'Role' },
        { field: 'entries', label: 'Entries', num: true, fmt: 'int' },
        { field: 'matched', label: 'Mapped hosts named', num: true, fmt: 'int' },
        { field: 'only_list', label: 'Only this list', num: true, fmt: 'int', hideSm: true },
        { field: 'overlap_other_operators', label: 'Overlap with other operators', num: true, fmt: 'pct', hideSm: true },
        { field: 'ok', label: 'Last fetch', get: (r) => (r.ok ? 'OK' : r.error || 'failed') },
        { field: 'terms', label: 'Terms', get: (r) => (r.noncommercial ? 'Non-commercial only. ' : '') + (r.terms || ''), cls: 'ti-wrap', hideSm: true },
      ], { empty: 'No lists were checked.' });
    }
    const tk = sec.querySelector('#tbl-links');
    if (tk && TI.tableState(tk, ['live_links'])) {
      const m = metaOf('live_links') || {};
      const bs = TI.obj(m.by_status);
      setCount(sec, 'links-asof', fresh(m));
      note(sec, 'links-sum', `${int(m.checked)} of ${int(m.listed)} links checked in the last run: ${int(bs.ok)} answered, ${int(bs.blocked)} refuse automated requests (the link stays), ${int(bs.review)} to review. `, m.method || '');
      const rank = { review: 0, blocked: 1, ok: 2 };
      TI.table(tk, dataRows('live_links').slice().sort((x, y) => (rank[x.status] ?? 3) - (rank[y.status] ?? 3)), [
        { field: 'label', label: 'Link', link: 'url', cls: 'ti-wrap' },
        { field: 'kind', label: 'Listed in', hideSm: true },
        { field: 'status', label: 'Status', attr: { 'data-status': (r) => r.status } },
        { field: 'why', label: 'Reason', get: (r) => r.why || (r.code ? 'HTTP ' + r.code : '') },
        { field: 'ok_at', label: 'Last good', fmt: 'date', hideSm: true },
      ], { empty: 'No links were checked.' });
    }
    const tb = sec.querySelector('#tbl-blog-items');
    if (tb && TI.tableState(tb, ['live_blogs'])) {
      const m = metaOf('live_blogs') || {};
      setCount(sec, 'blogs-asof', fresh(m));
      note(sec, 'blogs-sum', `${int(m.blogs_ok)} of ${int(m.blogs)} blog feeds read this cycle (of ${int(m.listed)} blogs listed). Items are candidates: the daily run fetches and confirms any item before it cites one. `, m.method || '', ' ', m.terms || '');
      TI.table(tb, kindRows('live_blogs', 'item'), [
        { field: 'published', label: 'Published', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'title', label: 'Item', link: 'link', cls: 'ti-wrap' },
        { field: 'blog', label: 'Blog' },
        { field: 'type', label: 'Type', hideSm: true },
      ], { sort: 'published', dir: 'desc', limit: 120, empty: 'No blog items in 7 days.' });
    }
    const tbf = sec.querySelector('#tbl-blog-feeds');
    if (tbf && TI.tableState(tbf, ['live_blogs'])) {
      TI.table(tbf, kindRows('live_blogs', 'blog'), [
        { field: 'name', label: 'Blog', link: 'url', cls: 'ti-wrap' },
        { field: 'type', label: 'Type' },
        { field: 'status', label: 'Feed', attr: { 'data-status': (r) => r.status } },
        { field: 'items', label: 'Items, 7d', num: true, fmt: 'int' },
        { field: 'newest', label: 'Newest', fmt: 'date', hideSm: true },
      ], { sort: 'items', dir: 'desc', limit: 80, empty: 'No blogs were read.' });
    }
    const tp = sec.querySelector('#tbl-psirt');
    if (tp && TI.tableState(tp, ['live_psirt'])) {
      const m = metaOf('live_psirt') || {};
      const feeds = m.feeds || [];
      setCount(sec, 'psirt-asof', fresh(m));
      note(sec, 'psirt-sum', `${int(m.advisories)} advisories from ${int(feeds.filter((f) => f.ok).length)} of ${int(feeds.length)} feeds; ${int(m.kev_hits)} name a CVE in CISA KEV (${int(m.kev_entries)} entries read). `, m.kev_note ? m.kev_note + '. ' : '', m.method || '', ' ', m.terms || '');
      TI.table(tp, kindRows('live_psirt', 'advisory'), [
        { field: 'published', label: 'Published', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'vendor', label: 'Publisher' },
        { field: 'title', label: 'Advisory', link: 'link', cls: 'ti-wrap' },
        { field: 'cves', label: 'CVEs', get: (r) => (r.cves || []).slice(0, 4).join(', ') + ((r.cves || []).length > 4 ? ` +${r.cves.length - 4}` : ''), hideSm: true },
        { field: 'kev', label: 'In KEV', get: (r) => ((r.kev || []).length ? (r.kev || []).join(', ') + (r.ransomware ? ' (ransomware use known)' : '') : ''), attr: { 'data-status': (r) => ((r.kev || []).length ? 'review' : '') } },
      ], { sort: 'published', dir: 'desc', limit: 150, empty: 'No advisories in 14 days.' });
      const tk = sec.querySelector('#tbl-kevrank');
      if (tk) {
        const wl = m.watchlist || {}, ev = wl.eval || {}, pc = (x) => (x == null ? 'n/a' : Math.round(x * 100) + '%');
        note(sec, 'kevrank-sum', wl.method || 'The watchlist has not been built yet.', ' ', ev.tracked
          ? `Scored so far: of ${int(ev.tracked)} CVEs first ranked a week or more ago, KEV has since listed ${int(ev.added)} (${pc(ev.base_rate)}); the top tenth by first score holds ${int(ev.top_decile_added)} of them (${pc(ev.recall_top_decile)} of the listed, ${pc(ev.top_decile_rate)} of the tenth). NDCG at ${ev.k}: ${ev.ndcg_at_k == null ? 'n/a' : ev.ndcg_at_k}.`
          : 'No CVE has been tracked for a week yet, so the ranking is unscored; the first figures appear from 22 November 2026.', wl.epss_note ? ' ' + wl.epss_note + '.' : '');
        TI.table(tk, kindRows('live_psirt', 'kevrank'), [
          { field: 'score', label: 'Score', num: true, get: (r) => d3.format('.2f')(r.score) },
          { field: 'cve', label: 'CVE', cls: 'ti-nowrap' },
          { field: 'title', label: 'Advisory', link: 'link', cls: 'ti-wrap' },
          { field: 'epss_percentile', label: 'EPSS pct.', num: true, get: (r) => (r.epss_percentile == null ? '' : Math.round(r.epss_percentile * 100)) },
          { field: 'edge', label: 'Edge', get: (r) => (r.edge ? 'yes' : ''), hideSm: true },
          { field: 'wording', label: 'Exploit wording', get: (r) => (r.wording ? 'yes' : ''), hideSm: true },
          { field: 'publishers', label: 'Publishers', num: true, fmt: 'int', hideSm: true },
        ], { sort: 'score', dir: 'desc', limit: 25, empty: 'No unlisted advisory CVEs in 14 days.' });
      }
      const tpf = sec.querySelector('#tbl-psirt-feeds');
      if (tpf) TI.table(tpf, feeds, [
        { field: 'vendor', label: 'Publisher', link: 'url' },
        { field: 'klass', label: 'Class' },
        { field: 'ok', label: 'Feed', get: (r) => (r.ok ? 'ok' : r.error || 'failed'), attr: { 'data-status': (r) => (r.ok ? 'ok' : 'review') } },
        { field: 'items', label: 'Entries', num: true, fmt: 'int' },
      ], { sort: 'vendor', empty: 'No feeds were read.' });
    }
    const tt = sec.querySelector('#tbl-triage');
    if (tt && TI.tableState(tt, ['live_triage'])) {
      const m = metaOf('live_triage') || {}, ev = m.eval, pct = (x) => (x == null ? 'n/a' : Math.round(x * 100) + '%');
      const show = !!(ev && ev.promoted);
      setCount(sec, 'triage-asof', fresh(m));
      note(sec, 'triage-sum', `${m.marking || 'Machine triage, unreviewed'}. ${int(m.labelled_24h)} titles labelled in 24 hours; ${int(m.count)} stories of relevance 1 or more shown, from ${int(m.titles)} titles. `, m.method || '');
      note(sec, 'triage-eval', ev
        ? `Agreement with the analyst's labels on ${int(ev.items)} of ${int(ev.gold_items)} evidence items (prompt ${ev.prompt_version}): theater ${pct(ev.theater_accuracy)} (macro F1 ${pct(ev.theater_macro_f1)}), vector ${pct(ev.vector_accuracy)} on ${int(ev.vector_items)} items, vector assigned where the analyst gave none ${pct(ev.vector_false_positive_rate)}. ${show ? 'The tier meets its thresholds; vector and theater labels are shown.' : `Vector and theater labels stay hidden until the full set clears the thresholds (theater ${pct(ev.thresholds.theater_accuracy)}, vector ${pct(ev.thresholds.vector_accuracy)}, false vector at most ${pct(ev.thresholds.vector_false_positive_rate)}, ${int(ev.thresholds.min_items)} items).`}`
        : 'The tier has not been scored against the analyst\'s labels yet; vector and theater labels stay hidden until it has.');
      const cols = [
        { field: 'relevance', label: 'Rel.', num: true, fmt: 'int' },
        { field: 'verify', label: 'Second model', get: (r) => (r.verify === 'confirmed' ? 'agrees' : r.verify === 'lowered' ? 'lowered from 3' : ''), hideSm: true },
        { field: 'published', label: 'Published', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'title', label: 'Title', link: 'link', cls: 'ti-wrap' },
        { field: 'source', label: 'Source', hideSm: true },
        { field: 'also', label: 'Also carried by', get: (r) => (r.also ? `${r.also} more` + ((r.also_sources || []).length ? ': ' + r.also_sources.slice(0, 3).join(', ') : '') : ''), hideSm: true },
        { field: 'cves', label: 'CVEs', get: (r) => (r.cves || []).slice(0, 3).join(', '), hideSm: true },
        { field: 'kev', label: 'In KEV', get: (r) => (r.kev || []).join(', '), attr: { 'data-status': (r) => ((r.kev || []).length ? 'review' : '') } },
      ];
      if (show) cols.push({ field: 'vector', label: 'Vector', hideSm: true }, { field: 'theater', label: 'Theater', hideSm: true });
      cols.push({ field: 'why', label: 'Model\'s reason', cls: 'ti-wrap', hideSm: true });
      TI.table(tt, kindRows('live_triage', 'lead'), cols, { sort: 'relevance', dir: 'desc', limit: 120, empty: 'No leads in 72 hours.' });
    }
    const tv = sec.querySelector('#tbl-volume');
    if (tv && TI.tableState(tv, ['live_health'])) {
      const rows = kindRows('live_health', 'volume');
      note(sec, 'volume-sum', rows.length ? `${int(rows.filter((r) => r.flag && r.flag !== 'baseline building' && r.flag !== 'normal').length)} feeds flagged against their 30-day median; ${int(rows.filter((r) => r.flag === 'baseline building').length)} still building a baseline.` : 'The collector reported no volumes.');
      TI.table(tv, rows, [
        { field: 'feed', label: 'Feed', cls: 'ti-mono' },
        { field: 'n', label: 'Latest', num: true, fmt: 'int' },
        { field: 'median_30d', label: '30-day median', num: true, fmt: 'int' },
        { field: 'ratio', label: 'Ratio', num: true, fmt: 'dec2' },
        { field: 'flag', label: 'Flag' },
        { field: 'baseline_days', label: 'Baseline days', num: true, fmt: 'int', hideSm: true },
        { field: 'at', label: 'Latest run', get: (r) => String(r.at || '').slice(0, 16).replace('T', ' '), hideSm: true },
      ], { sort: 'feed', dir: 'asc', empty: 'The collector reported no volumes.' });
    }
    // Gated and unreachable sources: what the dashboard cannot collect right now and why, from the sources' own answers.
    const tgt = sec.querySelector('#tbl-gates');
    if (tgt && TI.tableState(tgt, ['source_gaps'])) {
      TI.table(tgt, TI.rows('source_gaps'), [
        { field: 'source', label: 'Source', link: 'url', cls: 'ti-wrap' },
        { field: 'feeds', label: 'Feeds', hideSm: true },
        { field: 'status', label: 'HTTP', num: true, hideSm: true },
        { field: 'answered', label: 'What it answered', cls: 'ti-wrap' },
      ], { empty: 'Every collector source answered at its last run.' });
    }
    // The brief's indicator panel fails on its own; its loader's words say why.
    const tf = dash.data('live_threatfox');
    note(sec, 'gates-tf', TI.failed('live_threatfox') && tf.message ? 'Brief indicators panel (abuse.ch ThreatFox): ' + String(tf.message).replace(/^This source.s loader stopped: /, '').replace(/^threat-feeds: /, '').replace(/ The answer.s keys:.*$/, '') : '');
  };

  // ---------------------------------------------------------------- method page: credibility and RSIT
  I.methodCards = (sec) => {
    const el = sec.querySelector('#method-cred-body');
    if (!el) return;
    TI.clear(el);
    if (TI.failed('live_threatmap', 'live_lists')) { el.append(h('div', { class: 'ti-failed', text: 'Failed to load' })); return; }
    if (!TI.ready('live_threatmap', 'live_lists')) { el.classList.add('dash-skeleton'); return; }
    el.classList.remove('dash-skeleton');
    const tm = metaOf('live_threatmap') || {}, lm = metaOf('live_lists') || {};
    const cr = TI.obj(tm.credibility);
    el.append(h('p', {}, 'Mapped hosts by Admiralty credibility at the last collector run: ',
      v('strong', 'live_threatmap', null, null, int(cr['1'] || 0)), ' confirmed (1), ', int(cr['2'] || 0), ' probably true (2), ', int(cr['3'] || 0), ' possibly true (3).'));
    el.append(h('p', {}, lm.method || ''));
    if (tm.taxonomy) el.append(h('p', {}, 'Classification: ', tm.taxonomy, '. Each host carries its RSIT class (malicious-code/c2-server for a botnet controller, information-gathering/scanner for a scanning source) in its selection panel.'));
  };

  // ---------------------------------------------------------------- brief: disclosures and the gated indicators feed
  I.briefCards = (sec) => {
    const ts = sec.querySelector('#tbl-brief-sec');
    if (ts && TI.tableState(ts, ['live_sec8k'])) {
      const m = metaOf('live_sec8k') || {};
      setCount(sec, 'brief-sec-asof', fresh(m));
      TI.table(ts, dataRows('live_sec8k').filter((r) => r.item_105), [
        { field: 'filed', label: 'Filed', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'company', label: 'Filer', link: 'doc_url', cls: 'ti-wrap' },
        { field: 'item_105', label: 'Disclosure', get: disclosure },
        { field: 'sector', label: 'Sector', hideSm: true },
      ], { sort: 'filed', dir: 'desc', limit: 6, empty: 'No Item 1.05 disclosures in 90 days.' });
    }
    // The ThreatFox panel's own failure says why (abuse.ch's Auth-Key gate), in the loader's words.
    const card = sec.querySelector('#live-tf-card');
    if (card) {
      let g = card.querySelector('.ti-gate');
      const tf = dash.data('live_threatfox');
      if (TI.failed('live_threatfox') && tf.message) {
        if (!g) { g = h('p', { class: 'ti-card-note ti-gate' }); card.append(g); }
        g.textContent = String(tf.message).replace(/^This source.s loader stopped: /, '').replace(/^threat-feeds: /, '').replace(/ The answer.s keys:.*$/, '');
      } else if (g) g.remove();
    }
  };

  // ---------------------------------------------------------------- on-demand enrichment
  const TYPES = { asn: 'ASN', ip: 'IPv4 address', domain: 'Domain', hash: 'File hash', actor: 'Actor name' };
  I.enrich = (type, q) => {
    if (!TYPES[type] || !q) return;
    dash.setParams({ enrich_type: type, enrich_q: String(q).trim() });
    const t = document.getElementById('enrich-type'), qi = document.getElementById('enrich-q');
    if (t) t.value = type;
    if (qi) qi.value = String(q).trim();
  };
  // A one-line reading of each analyzer's answer; the full answer stays in the dataset row.
  function summarize(r) {
    const d = TI.obj(r.data);
    switch (r.analyzer) {
      case 'bgpranking': return d.description ? `${d.description}; rank ${d.rank == null ? '—' : d3.format('.2e')(d.rank)}, position ${int(d.position)} of ${int(d.of)} known networks` : 'No ranking for this network';
      case 'cl0q_asn': case 'cl0q_ip': case 'cl0q_domain': case 'cl0q_subdomains': {
        if (r.analyzer === 'cl0q_ip') return `${int(d.total)} indexed sites on this address` + (TI.list(d.sites).length ? ': ' + TI.list(d.sites).slice(0, 5).map((s) => s.domain).filter(Boolean).join(', ') : '');
        if (r.analyzer === 'cl0q_domain') return d.indexed === false ? 'Not indexed by cl0q' : 'Indexed by cl0q' + (d.title ? ': ' + d.title : '');
        if (r.analyzer === 'cl0q_subdomains') { const s = TI.list(d.subdomains || d.results || d.items); return s.length ? `${int(d.total ?? s.length)} subdomains indexed` : 'No subdomains indexed'; }
        const dims = TI.obj(d.dims), cc = TI.list(dims.country).slice(0, 3).map((x) => `${String(x[0]).toUpperCase()} ${int(x[1])}`).join(', ');
        return `${int(d.total)} sites indexed on this network` + (cc ? `; by country ${cc}` : '');
      }
      case 'map': {
        const lm = TI.list(d.listed_by_map_sources), g = TI.obj(d.geolocation), c = TI.obj(d.credibility);
        return (lm.length ? `On the map in ${[...new Set(lm.map((x) => x.layer))].join(', ')}` : 'Not on the threat map') + (g.cc ? `; ${g.as_name || ''} ${g.city || ''} ${g.cc}` : '') +
          `; lists ${TI.list(d.lists).join(', ') || 'none'}` + (d.ipsum ? `; IPsum ${d.ipsum}` : '') + (d.tor ? '; Tor exit' : '') + (c.cred ? `; credibility ${c.cred}` : '');
      }
      case 'ipasn': return d.asn ? `AS${d.asn} announces ${d.prefix || 'this address'} (as of ${String(d.as_of || '').slice(0, 10)})` : 'No routing history';
      case 'tranco': return d.best_rank_30d ? `Best rank ${int(d.best_rank_30d)} over ${int(d.days_ranked)} days. ${d.note || ''}` : d.note || 'Not ranked';
      // hashlookup's trust runs 0 to 100 (50 by default) and drops when a hash also sits in malware collections, so presence alone is no benign verdict.
      case 'hashlookup': {
        if (!d.known) return d.note || 'Not in the known-software database';
        const t = d.trust == null ? null : Number(d.trust);
        return `In the hashlookup database${d.file_name ? ': ' + d.file_name : ''}${d.product ? ' (' + d.product + ')' : ''}${d.source ? ', source ' + d.source : ''}` +
          (t == null ? '' : `; trust ${t} of 100${t < 50 ? ', too low to treat as known-good software' : ''}`);
      }
      case 'mbazaar': {
        if (d.found === false) return 'Not in MalwareBazaar';
        const yr = TI.list(d.yara_rules).length, tags = TI.list(d.tags).filter((t) => t !== d.signature).slice(0, 4);
        return `${d.signature || 'No family assigned'}${d.file_type ? ', ' + d.file_type : ''}; first seen ${String(d.first_seen || '').slice(0, 10) || '—'}` +
          (tags.length ? `; tags ${tags.join(', ')}` : '') + (yr ? `; ${yr} YARA rule${yr === 1 ? '' : 's'}` : '') + (TI.list(d.vendors).length ? `; ${TI.list(d.vendors).length} vendor reports` : '');
      }
      case 'yaraify': {
        if (d.found === false) return 'Not in YARAify';
        const rules = TI.list(d.yara_rules).map((x) => x && x.rule).filter(Boolean);
        return `${int(d.sightings)} sightings, ${int(d.tasks)} scans; ` + (rules.length ? `public YARA matches ${rules.slice(0, 5).join(', ')}${rules.length > 5 ? ` and ${rules.length - 5} more` : ''}` : 'no public YARA matches') +
          (TI.list(d.clamav).length ? `; ClamAV ${TI.list(d.clamav).slice(0, 2).join(', ')}` : '');
      }
      case 'orkl': return `${int(d.reports)} reports` + (TI.list(d.items).length ? ': ' + TI.list(d.items).slice(0, 3).map((x) => `${x.title}${x.published ? ' (' + x.published + ')' : ''}`).join('; ') : '');
      default: return Object.keys(d).slice(0, 6).join(', ');
    }
  }
  // The results block for one indicator, or null when the dataset holds another (or none).
  I.enrichResults = (type, q) => {
    const st = dash.data('live_enrich');
    const p = dash.params ? dash.params() : {};
    if (p.enrich_type !== type || String(p.enrich_q || '').toLowerCase() !== String(q).toLowerCase()) return null;
    if (st.status === 'loading' || st.refreshing) return h('p', { class: 'ti-card-note dash-skeleton', text: 'Reading the analyzers' });
    if (TI.failed('live_enrich')) return h('p', { class: 'ti-failed', text: 'Enrichment failed: ' + String(st.message || 'the service did not answer') });
    const rows = TI.rows('live_enrich') || [];
    const inv = rows.find((r) => r.kind === 'invalid');
    if (inv) return h('p', { class: 'ti-card-note', text: `Not a valid ${TYPES[type] || type}: ${inv.note}` });
    const res = rows.filter((r) => r.kind === 'result');
    if (!res.length) return null;
    const ul = h('ul', { class: 'ti-enrich-list' });
    for (const r of res) {
      ul.append(h('li', {}, r.page ? a(r.page, r.label) : h('strong', { text: r.label }), ': ',
        r.ok ? summarize(r) : 'no answer (' + (r.error || 'error') + ')',
        h('span', { class: 'ti-muted', text: ` · read ${String(r.at || '').slice(0, 16).replace('T', ' ')}Z${r.cached ? ', cached' : ''}` })));
      // ORKL lists the reports themselves: each title links to the original publication where ORKL holds one.
      if (r.analyzer === 'orkl' && r.ok) {
        const items = TI.list(TI.obj(r.data).items);
        if (items.length) ul.append(h('li', { class: 'ti-enrich-sub' }, ...items.slice(0, 8).flatMap((x, i) => [i ? ' · ' : '', a(x.url || x.orkl, x.title || 'report'), x.published ? ` (${x.published})` : ''])));
      }
    }
    return ul;
  };
  // The map page card: type, value and Run, then the analyzers' answers.
  I.enrichCard = (sec) => {
    const out = sec.querySelector('#enrich-out');
    if (!out) return;
    TI.clear(out);
    const p = dash.params ? dash.params() : {};
    if (!p.enrich_type || !p.enrich_q) { out.append(h('p', { class: 'ti-card-note', text: 'Choose a type, enter a public indicator and press Run, or press Enrich on a host selected on the map.' })); return; }
    const t = document.getElementById('enrich-type'), qi = document.getElementById('enrich-q');
    if (t && !t.matches(':focus')) t.value = p.enrich_type;
    if (qi && !qi.matches(':focus') && !qi.value) qi.value = p.enrich_q;
    out.append(h('p', { class: 'ti-card-note' }, `${TYPES[p.enrich_type] || p.enrich_type} `, h('strong', { class: 'ti-mono', text: p.enrich_q })));
    out.append(I.enrichResults(p.enrich_type, p.enrich_q) || h('p', { class: 'ti-card-note', text: 'No analyzer answered.' }));
  };
  TI.root.addEventListener('click', (ev) => {
    if (!ev.target.closest || !ev.target.closest('#enrich-run')) return;
    const t = document.getElementById('enrich-type'), qi = document.getElementById('enrich-q');
    if (t && qi && qi.value.trim()) I.enrich(t.value, qi.value.trim());
  });
  TI.root.addEventListener('keydown', (ev) => {
    if (ev.target.id !== 'enrich-q' || ev.key !== 'Enter') return;
    const t = document.getElementById('enrich-type');
    if (t && ev.target.value.trim()) I.enrich(t.value, ev.target.value.trim());
  });
})();
