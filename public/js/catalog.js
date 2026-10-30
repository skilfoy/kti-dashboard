/* The site's dataset catalog on the Method page: every dataset the page reads, whether it is a built file or a live
   query, when it was last built, its status in this browser, and a link to download each built file as JSON. */
(() => {
  const KIND = { file: 'Built file', query: 'Live query' };
  const STATUS = { ok: 'Loaded', loading: 'Loading', error: 'Failed', missing: 'Not in this build' };
  TI.catalog = {
    draw(sec) {
      const t = sec.querySelector('#tbl-datasets');
      if (!t || !dash.datasets) return;
      const s = dash.site && dash.site();
      const note = sec.querySelector('#data-build');
      if (note && s) note.textContent = `Site built ${String(s.built || '').replace('T', ' ').replace('Z', ' UTC')}` + (s.commit ? ` from commit ${s.commit}` : '') + '.';
      const rows = dash.datasets().map((d) => ({ ...d, kind_label: KIND[d.kind] || d.kind, updated_at: d.updated && d.updated.at ? d.updated.at : '',
        status_label: (STATUS[d.status] || d.status) + (d.stale ? ', stale' : ''), href: d.kind === 'file' ? d.url : null, link_text: d.kind === 'file' ? 'JSON' : '' }));
      const q = TI.search(sec.querySelector('#data-q'));
      TI.table(t, rows, [
        { field: 'title', label: 'Dataset', cls: 'ti-wrap' },
        { field: 'id', label: 'Id', cls: 'ti-mono ti-nowrap', hideSm: true },
        { field: 'kind_label', label: 'Kind', cls: 'ti-nowrap' },
        { field: 'rows', label: 'Rows', num: true, fmt: 'int' },
        { field: 'updated_at', label: 'Updated (UTC)', cls: 'ti-nowrap', hideSm: true },
        { field: 'status_label', label: 'In this browser', cls: 'ti-nowrap' },
        { field: 'link_text', label: 'Download', link: 'href' },
        { field: 'description', label: 'What it holds', cls: 'ti-wrap', hideSm: true },
      ], { sort: 'kind_label', dir: 'asc', countEl: sec.querySelector('#data-count'), filter: (r) => q(r, ['title', 'id', 'description']) });
    },
  };
  TI.root.addEventListener('input', (ev) => { if (ev.target.id === 'data-q') TI.draw('method'); });
})();
