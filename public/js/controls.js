/* Header controls: critical-infrastructure vertical, theme (auto/light/dark), manual refresh, and a typed
   auto-refresh interval. Live datasets refresh in the browser from the threat-feeds service on this site. */
(() => {
  const { h } = TI;
  const LIVE = ['live_ransomware', 'live_epss', 'live_threatfox', 'live_health', 'live_gdelt', 'live_threatmap', 'live_outages', 'live_actors', 'live_cyberattacks', 'live_lanes', 'live_ofac',
    // Collector documents (threat-feeds /api/context); enrichment runs on demand only and is left out.
    'live_fires', 'live_maritime', 'live_leaksites', 'live_lists', 'live_blogs', 'live_psirt', 'live_triage', 'live_news', 'live_sources', 'live_links', 'live_unit42', 'live_genioc', 'live_lanesreg', 'live_ransompay', 'live_sec8k', 'live_graph'];
  TI.LIVE = LIVE;
  const store = {
    get(k, d) { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
  };

  // ---- Theme: auto (follows the system setting), light, dark ----
  // The choice is set on the document root too, so the page background around the dashboard follows it.
  function applyTheme(mode) {
    if (mode === 'auto') { TI.root.removeAttribute('data-theme'); document.documentElement.removeAttribute('data-theme'); }
    else { TI.root.setAttribute('data-theme', mode); document.documentElement.setAttribute('data-theme', mode); }
    const btn = document.getElementById('ti-theme');
    if (btn) { btn.textContent = mode === 'auto' ? 'Theme: auto' : mode === 'dark' ? 'Theme: dark' : 'Theme: light'; btn.setAttribute('aria-label', 'Theme ' + mode); }
  }
  let theme = store.get('ti-theme', 'auto');
  applyTheme(theme);
  TI.root.addEventListener('click', (ev) => {
    if (!ev.target.closest || !ev.target.closest('#ti-theme')) return;
    theme = theme === 'auto' ? 'dark' : theme === 'dark' ? 'light' : 'auto';
    store.set('ti-theme', theme); applyTheme(theme);
    TI.draw(currentPage()); // re-resolve token-derived colors in charts
  });

  function currentPage() {
    const s = TI.root.querySelector('.ti-page:not([hidden])');
    return s ? s.id : 'brief';
  }

  // ---- Vertical selector ----
  function fillVerticals() {
    const sel = document.getElementById('ti-vertical');
    if (!sel || sel.dataset.filled || !TI.ready('verticals')) return;
    const vs = TI.rows('verticals');
    for (const vrt of vs) sel.append(h('option', { value: vrt.vertical_id, text: vrt.name }));
    let def = store.get('ti-vertical', (vs.find((x) => x.default === 'Yes') || vs[0]).vertical_id);
    if (!vs.some((x) => x.vertical_id === def)) def = (vs.find((x) => x.default === 'Yes') || vs[0]).vertical_id;
    sel.value = def;
    if ((dash.params().vertical || '') !== def) dash.setParams({ vertical: def });
    sel.dataset.filled = '1';
    verticalNote(def);
  }
  function verticalNote(id) {
    const vrt = TI.ready('verticals') ? TI.rows('verticals').find((x) => x.vertical_id === id) : null;
    const note = document.getElementById('ti-vertical-note');
    if (note && vrt) note.textContent = vrt.summary;
    const scope = document.getElementById('marking-scope');
    if (scope && vrt) scope.textContent = 'Inherent threat calibrated for ' + vrt.name.toLowerCase();
  }
  TI.root.addEventListener('change', (ev) => {
    if (ev.target.id !== 'ti-vertical') return;
    store.set('ti-vertical', ev.target.value);
    dash.setParams({ vertical: ev.target.value });
    verticalNote(ev.target.value);
    // vertical is read only by the page, so setParams redraws without a query; redraw the open page too.
    TI.draw(currentPage());
  });

  // ---- Manual refresh ----
  // The first read happens on page load (pending from the start), so its note settles the same way a refresh does.
  let pending = true;
  TI.refreshLive = () => {
    pending = true;
    for (const id of LIVE) { try { dash.refresh(id); } catch { /* not loaded yet */ } }
    refreshNote();
  };
  function refreshNote() {
    const note = document.getElementById('ti-refresh-note');
    if (!note) return;
    const st = LIVE.map((id) => dash.data(id));
    if (st.some((d) => d.refreshing || d.status === 'loading')) { note.textContent = 'Refreshing…'; return; }
    if (pending && st.every((d) => d.status !== 'loading')) {
      pending = false;
      const ok = st.filter((d) => d.status === 'ok').length;
      note.textContent = `Updated ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}` + (ok < LIVE.length ? ` (${LIVE.length - ok} unavailable)` : '');
    }
  }
  TI.root.addEventListener('click', (ev) => {
    if (!ev.target.closest || !ev.target.closest('#ti-refresh')) return;
    TI.refreshLive();
  });

  // ---- Typed auto-refresh interval ----
  let timer = null;
  function parseInterval(s) {
    s = String(s || '').trim().toLowerCase();
    if (!s || /^(off|manual|none|stop|never|0)$/.test(s)) return 0;
    const m = s.match(/([\d.]+)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours)?/);
    if (!m) return 0;
    const n = parseFloat(m[1]); const u = m[2] || 'm';
    const mult = /^s/.test(u) ? 1e3 : /^h/.test(u) ? 36e5 : 6e4;
    return Math.round(n * mult);
  }
  function setInterval_(raw) {
    const ms = parseInterval(raw);
    if (timer) { clearInterval(timer); timer = null; }
    const note = document.getElementById('ti-interval-note');
    if (!ms) { if (note) note.textContent = 'Auto-refresh off'; return; }
    const clamped = Math.max(15000, ms);
    timer = setInterval(() => TI.refreshLive(), clamped);
    if (note) note.textContent = 'Every ' + fmtMs(clamped) + (clamped !== ms ? ' (min 15s)' : '');
  }
  function fmtMs(ms) { const s = ms / 1000; return s < 60 ? s + 's' : s < 3600 ? (s / 60) + ' min' : (s / 3600) + ' h'; }
  TI.root.addEventListener('change', (ev) => {
    if (ev.target.id !== 'ti-interval') return;
    store.set('ti-interval', ev.target.value);
    setInterval_(ev.target.value);
  });

  // ---- Feed status chip from live_health ----
  function feedStatus() {
    const el = document.getElementById('ti-feedstatus');
    if (!el) return;
    const st = dash.data('live_health');
    if (st.status === 'ok') {
      const rows = (TI.rows('live_health') || []).filter((r) => r.kind === 'upstream' || !r.kind);
      const up = rows.filter((r) => r.ok === 'Up').length;
      el.textContent = `Feeds ${up}/${rows.length} up`;
      el.setAttribute('data-ok', up === rows.length ? 'all' : up ? 'some' : 'none');
    } else if (st.status === 'loading') { el.textContent = 'Feeds…'; }
    else if (['connect', 'declined', 'missing', 'error'].includes(st.status)) { el.textContent = 'Feeds unavailable'; el.setAttribute('data-ok', 'none'); }
  }

  // Init once the page is live, and keep header bits current.
  function init() {
    const iv = document.getElementById('ti-interval');
    if (iv && !iv.dataset.init) { iv.value = store.get('ti-interval', ''); iv.dataset.init = '1'; setInterval_(iv.value); }
  }
  init();
  dash.onData(() => { fillVerticals(); feedStatus(); refreshNote(); });
})();
