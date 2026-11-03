/* Data sources page: renders /data-sources.json (the checked registry) grouped by category, with filters, a live
   badge from /api/health and one attribution block built from the registry rows. No libraries; text set with
   textContent only. */
(() => {
  const $ = (id) => document.getElementById(id);
  const el = (tag, attrs, ...kids) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) if (v != null) (k === 'text' ? (e.textContent = v) : e.setAttribute(k, v));
    for (const c of kids) if (c != null) e.append(c);
    return e;
  };
  const STATUS_LABEL = { live: 'Live', known_gap: 'Known gap', held: 'Held', candidate: 'Candidate', declined: 'Declined', not_implemented: 'Not implemented' };
  const ACCESS_LABEL = { open: 'Open', registration: 'Registration', key: 'Key' };
  const WHERE = { neon_function_variable: 'collector (Neon) variable', github_secret: 'GitHub secret', github_environment_secret: 'GitHub environment secret', none: 'not stored' };
  const safeUrl = (u) => (/^https?:\/\//.test(String(u || '')) ? u : null);
  let REG = null, LIVE = {};

  // Live state per collector feed id: Up, Down or Known gap (a collector before 2026-11-02.1 has no state: ok decides).
  function liveOf(r) {
    const f = r.health_feed && LIVE[r.health_feed];
    if (!f) return null;
    if (f.state === 'known_gap' || (!f.state && f.ok === false && r.status === 'known_gap')) return 'Known gap';
    return f.ok === true ? 'Up' : f.ok === false ? 'Down' : null;
  }
  function feedsText(r) {
    const ds = (r.feeds || []).filter((f) => !f.startsWith('page:'));
    const pages = (r.feeds || []).filter((f) => f.startsWith('page:')).map((f) => f.slice(5));
    return [ds.length ? ds.join(', ') : '', pages.length ? 'pages: ' + pages.join(', ') : ''].filter(Boolean).join('; ');
  }
  function render() {
    const st = $('f-status').value, ac = $('f-access').value, q = $('f-q').value.trim().toLowerCase();
    const rows = REG.rows.filter((r) => (!st || r.status === st) && (!ac || r.access === ac)
      && (!q || [r.name, r.owner, r.licence, r.category, r.id].join(' ').toLowerCase().includes(q)));
    const body = $('rows');
    body.textContent = '';
    const cats = [...new Set(rows.map((r) => r.category))];
    for (const c of cats) {
      body.append(el('tr', { class: 'ds-group' }, el('th', { colspan: '7', scope: 'colgroup', text: c })));
      for (const r of rows.filter((x) => x.category === c)) {
        const url = safeUrl(r.url);
        const name = el('td', { class: 'ds-name' }, url ? el('a', { href: url, rel: 'noopener', text: r.name }) : r.name, el('span', { class: 'ds-sub', text: r.owner }));
        if (r.gap_note) name.append(el('span', { class: 'ds-sub', text: r.gap_note }));
        const live = liveOf(r);
        const access = el('td', null, ACCESS_LABEL[r.access] || r.access);
        if (r.secret && r.secret.name) access.append(el('span', { class: 'ds-sub' }, el('code', { text: r.secret.name }), ' ' + (WHERE[r.secret.where] || '')));
        body.append(el('tr', null, name,
          el('td', null, el('span', { class: 'ds-badge', 'data-s': r.status, text: STATUS_LABEL[r.status] || r.status })),
          el('td', null, live ? el('span', { class: 'ds-badge', 'data-s': live, text: live }) : el('span', { class: 'ds-note', text: r.health_feed ? 'n/a' : '' })),
          el('td', { class: 'ds-hide-sm', text: feedsText(r) }),
          access,
          el('td', { class: 'ds-hide-sm', text: r.licence + (r.terms_verified === false ? ' (terms unverified)' : '') }),
          el('td', { class: 'ds-hide-sm', text: r.cadence || '' })));
      }
    }
    $('count').textContent = `${rows.length} of ${REG.rows.length} sources`;
  }
  function attribution() {
    const list = $('attr-list');
    list.textContent = '';
    const seen = new Set();
    for (const r of REG.rows) {
      if (!r.attribution || seen.has(r.attribution)) continue;
      seen.add(r.attribution);
      list.append(el('li', null, el('strong', { text: r.name + ': ' }), r.attribution));
    }
    if (!seen.size) list.append(el('li', { class: 'ds-note', text: 'No source requires attribution.' }));
  }
  function fill(sel, values, labels) { for (const v of values) sel.append(el('option', { value: v, text: labels[v] || v })); }
  async function main() {
    try {
      const r = await fetch('/data-sources.json', { headers: { accept: 'application/json' } });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      REG = await r.json();
    } catch (e) { $('count').textContent = 'The registry could not be read (' + e.message + ').'; return; }
    fill($('f-status'), (REG.statuses || Object.keys(STATUS_LABEL)).filter((s) => REG.rows.some((x) => x.status === s)), STATUS_LABEL);
    fill($('f-access'), Object.keys(ACCESS_LABEL).filter((a) => REG.rows.some((x) => x.access === a)), ACCESS_LABEL);
    for (const id of ['f-status', 'f-access']) $(id).addEventListener('change', render);
    $('f-q').addEventListener('input', render);
    render(); attribution();
    try {
      const h = await (await fetch('/api/health', { headers: { accept: 'application/json' } })).json();
      for (const f of (h.collector && h.collector.feeds) || []) LIVE[f.feed] = f;
      render();
    } catch { /* live badges stay empty; the registry still shows */ }
  }
  main();
})();
