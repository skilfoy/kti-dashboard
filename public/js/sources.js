/* Sources: feed catalogs, the source registry with usage, and every cited item with its score. */
(() => {
  const { h } = TI;

  TI.page('sources', (sec) => {
    if (TI.ctx) TI.ctx.sourcesCards(sec);
    const tc = sec.querySelector('#tbl-catalogs');
    if (TI.tableState(tc, ['catalogs'])) {
      TI.table(tc, TI.rows('catalogs'), [
        { field: 'catalog', label: 'Catalog' },
        { field: 'version', label: 'Version or snapshot' },
        { field: 'released', label: 'Released', fmt: 'text' },
        { field: 'count', label: 'Records', num: true, fmt: 'int' },
      ], {});
    }
    const ts = sec.querySelector('#tbl-sources');
    if (TI.tableState(ts, ['sources', 'source_usage'])) {
      const use = TI.index(TI.rows('source_usage'), 'source_id');
      const rows = TI.rows('sources');
      const sel = sec.querySelector('#src-status');
      if (sel.options.length === 1) for (const s of [...new Set(rows.map((r) => r.status))].sort()) sel.append(h('option', { text: s }));
      const q = TI.search(sec.querySelector('#src-q'));
      const st = sel.value;
      TI.table(ts, rows, [
        { field: 'name', label: 'Source', link: 'url', cls: 'ti-wrap' },
        { field: 'owner_type', label: 'Owner' },
        { field: 'tier', label: 'Tier' },
        { field: 'reliability', label: 'Rel.' },
        { field: 'default_credibility', label: 'Cred.', num: true },
        { field: 'validity', label: 'Validity', hideSm: true },
        { field: 'status', label: 'Status', cls: 'ti-wrap' },
        { field: 'cadence', label: 'Cadence', hideSm: true },
        { field: 'crit_timeliness', label: 'Time', hideSm: true },
        { field: 'crit_relevancy', label: 'Rel', hideSm: true },
        { field: 'crit_accuracy', label: 'Acc', hideSm: true },
        { field: 'crit_context', label: 'Ctx', hideSm: true },
        { field: 'crit_format', label: 'Fmt', hideSm: true },
        { field: 'crit_enrichment', label: 'Enr', hideSm: true },
        { field: 'crit_licensing', label: 'Lic', hideSm: true },
        { field: 'items_cited', label: 'Items cited', num: true, source: 'source_usage', get: (r) => (use.get(r.source_id) || {}).items_cited },
        { field: 'newest_item', label: 'Newest item', source: 'source_usage', get: (r) => (use.get(r.source_id) || {}).newest_item, fmt: 'date', hideSm: true },
        { field: 'provider_bias', label: 'Bias and limits', cls: 'ti-wrap', hideSm: true },
        { field: 'time_contract', label: 'Time field', cls: 'ti-wrap', hideSm: true },
      ], { sort: 'items_cited', dir: 'desc', countEl: sec.querySelector('#src-count'), filter: (r) => q(r, ['name', 'owner_type', 'status', 'provider_bias']) && (!st || r.status === st) });
    }
    const ti = sec.querySelector('#tbl-items');
    if (TI.tableState(ti, ['items', 'item_scores'])) {
      const sc = TI.index(TI.rows('item_scores'), 'item_id');
      const q = TI.search(sec.querySelector('#it-q'));
      TI.table(ti, TI.rows('items'), [
        { field: 'date', label: 'Date', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'theater_name', label: 'Theater', hideSm: true },
        { field: 'vector', label: 'Vector', hideSm: true },
        { field: 'lane', label: 'Lane', hideSm: true },
        { field: 'title', label: 'Item', link: 'url', cls: 'ti-wrap' },
        { field: 'source_name', label: 'Source' },
        { field: 'origin', label: 'Origin', hideSm: true },
        { field: 'category', label: 'Category', hideSm: true },
        { field: 'grade', label: 'Grade' },
        { field: 'score', label: 'Score', num: true, fmt: 'dec2', source: 'item_scores', get: (r) => (sc.get(r.item_id) || {}).score },
        { field: 'veracity', label: 'Veracity', attr: { 'data-v': (r) => r.veracity }, cls: 'ti-ver' },
      ], { sort: 'date', dir: 'desc', countEl: sec.querySelector('#it-count'), filter: (r) => q(r, ['title', 'source_name', 'theater_name', 'vector', 'origin']) });
    }
  });
  dash.onData(() => TI.draw('sources'));
  TI.root.addEventListener('input', (ev) => { if (['src-q', 'src-status', 'it-q'].includes(ev.target.id)) TI.draw('sources'); });
})();
