/* Site runtime: the `dash` interface the page scripts are written against, served from this site alone.
   Datasets are listed in site.json. A file dataset is a JSON table built by the pipeline and served under /data; a
   query dataset is a same-origin call to the threat-feeds service under /api, whose HTTP answer reaches the page's
   loader as an envelope {success, status, statusText, text}. Calcs are derived tables recomputed in dependency order
   whenever an input changes. Params are per-viewer filters held in memory; a query whose URL names a param re-runs
   when that param changes. Nothing here stores data outside the page, and nothing calls another origin. */
(() => {
  'use strict';
  const MANIFEST = '/site.json';
  const QUERY_TIMEOUT_MS = 65000;
  const BAD = new Set(['error', 'connect', 'declined', 'missing']);

  const defs = new Map();      // dataset id -> manifest entry
  const state = new Map();     // id -> public state object
  const calcs = new Map();     // id -> {inputs, fn, title, description}
  const loaders = new Map();   // id -> {fn, description}
  const answers = new Map();   // query id -> {answer, args} awaiting a loader
  const listeners = [];
  let params = {};
  let defaults = {};
  let site = null;
  let booted = false;

  // ---------------------------------------------------------------- table normalizer
  // A table is the union of its rows' keys; a missing cell is null, a non-finite number null, and a list or record
  // cell its JSON text (a record with a primitive `value` gives that value). Files, loader rows and calc rows all
  // pass through it, so page code reads one shape whatever produced the rows.
  const cell = (v) => {
    if (v === null || v === undefined) return null;
    if (typeof v === 'number') return isFinite(v) ? v : null;
    if (typeof v === 'string' || typeof v === 'boolean') return v;
    if (typeof v !== 'object') return null;
    if (!Array.isArray(v) && Object.prototype.hasOwnProperty.call(v, 'value') && (v.value === null || typeof v.value !== 'object')) return cell(v.value);
    try { return JSON.stringify(v); } catch { return null; }
  };
  const isRow = (r) => r && typeof r === 'object' && !Array.isArray(r);
  function table(rows) {
    const objs = rows.filter(isRow);
    const cols = [];
    const seen = new Set();
    for (const r of objs) for (const k of Object.keys(r)) if (!seen.has(k)) { seen.add(k); cols.push(k); }
    return { columns: cols, rows: objs.map((r) => { const o = {}; for (const c of cols) o[c] = Object.prototype.hasOwnProperty.call(r, c) ? cell(r[c]) : null; return o; }) };
  }

  // ---------------------------------------------------------------- state
  const blank = (status, message) => ({ status, data: null, rows: [], columns: [], message: message || '', refreshing: false, meta: [], updated: null, stale: false });
  function put(id, patch) {
    const prev = state.get(id) || blank('loading');
    const next = Object.assign({}, prev, patch);
    state.set(id, next);
    return next;
  }
  function settle(id, out, meta) {
    // Rows (a list, or {data|rows: list}) become a normalized table; any other value is kept as is.
    const list = Array.isArray(out) ? out : out && Array.isArray(out.data) ? out.data : out && Array.isArray(out.rows) ? out.rows : null;
    if (list) {
      const t = table(list);
      return put(id, { status: 'ok', data: t.rows, rows: t.rows, columns: t.columns, message: '', refreshing: false, meta: meta || [] });
    }
    const value = out && typeof out === 'object' && 'data' in out ? out.data : out;
    return put(id, { status: 'ok', data: value, rows: [], columns: [], message: '', refreshing: false, meta: meta || [] });
  }

  // ---------------------------------------------------------------- change notification
  let flushQueued = false;
  function notify() {
    if (flushQueued) return;
    flushQueued = true;
    requestAnimationFrame(() => {
      flushQueued = false;
      for (const cb of listeners.slice()) { try { cb(); } catch (e) { report('a dash.onData callback', e); } }
    });
  }
  function report(where, e) {
    // Page faults go to the console only; the page shows its own failure states.
    console.error('[site runtime] ' + where + ': ' + (e && e.stack ? e.stack : e));
  }

  // ---------------------------------------------------------------- calcs
  // Calcs whose inputs include `id`, directly or through other calcs, in dependency order.
  function dependents(ids) {
    const dirty = new Set();
    const queue = [...ids];
    while (queue.length) {
      const x = queue.shift();
      for (const [cid, c] of calcs) if (!dirty.has(cid) && c.inputs.includes(x)) { dirty.add(cid); queue.push(cid); }
    }
    return order([...dirty]);
  }
  function order(ids) {
    const want = new Set(ids), done = new Set(), out = [], visiting = new Set();
    const visit = (id) => {
      if (done.has(id) || !want.has(id)) return;
      if (visiting.has(id)) { report('calc ' + id, 'circular inputs'); return; }
      visiting.add(id);
      for (const i of calcs.get(id).inputs) if (calcs.has(i)) visit(i);
      visiting.delete(id); done.add(id); out.push(id);
    };
    for (const id of ids) visit(id);
    return out;
  }
  // A name the site does not know: still loading until the manifest is read, then missing (or failed, when the
  // manifest itself did not load).
  function unknown(id) {
    if (!site || defs.has(id) || calcs.has(id)) return blank('loading');
    return site.failed ? blank('error', 'The site manifest did not load.') : blank('missing', 'No dataset named ' + id);
  }
  function runCalc(id) {
    const c = calcs.get(id);
    const ins = c.inputs.map((i) => state.get(i) || unknown(i));
    const bad = ins.find((s) => BAD.has(s.status));
    if (bad) { put(id, Object.assign(blank(bad.status === 'missing' ? 'missing' : 'error', bad.message), { refreshing: false })); return; }
    if (ins.some((s) => s.status !== 'ok')) { put(id, { status: 'loading', refreshing: false }); return; }
    try {
      const out = c.fn(...ins.map((s) => s.data));
      if (Array.isArray(out) && out.every(isRow)) settle(id, out);
      else put(id, { status: 'ok', data: out, rows: [], columns: [], message: '', refreshing: false, meta: [] });
    } catch (e) {
      report('calc ' + id, e);
      put(id, Object.assign(blank('error', 'This calculation stopped: ' + (e && e.message ? e.message : e))));
    }
  }
  function recompute(changed) {
    if (!booted) return;
    for (const id of dependents(changed)) runCalc(id);
    notify();
  }

  // ---------------------------------------------------------------- files
  async function loadFile(id) {
    const d = defs.get(id);
    let rows = null, err = null;
    try {
      const r = await fetch(d.url, { credentials: 'same-origin' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const body = await r.json();
      rows = Array.isArray(body) ? body : body && Array.isArray(body.rows) ? body.rows : null;
      if (!rows) throw new Error('not a table');
    } catch (e) {
      err = e;
    }
    await booting;
    if (err) put(id, Object.assign(blank('error', 'This dataset did not load (' + (err && err.message ? err.message : err) + ').'), { updated: d.updated || null }));
    else { const st = settle(id, rows); st.updated = d.updated || null; st.stale = isStale(d); }
    recompute([id]);
  }
  function isStale(d) {
    if (!d.staleAfterHours || !d.updated || !d.updated.at) return false;
    const t = Date.parse(d.updated.at);
    return isFinite(t) && Date.now() - t > d.staleAfterHours * 3600000;
  }

  // ---------------------------------------------------------------- queries
  const TEMPLATE = /\{\{\s*([A-Za-z0-9_]+)\s*\}\}/g;
  const templateKeys = (url) => [...String(url).matchAll(TEMPLATE)].map((m) => m[1]);
  // A query whose URL names filters stays idle while every one of them is unset; once any is set it runs, with the
  // unset ones sent empty (the exposure monitor takes domains, suppliers and egress IPs in any combination).
  function fill(url) {
    let named = 0, set = 0;
    const out = String(url).replace(TEMPLATE, (_, k) => {
      const v = params[k];
      const s = v == null ? '' : Array.isArray(v) ? v.join(',') : String(v);
      named++;
      if (s) set++;
      return encodeURIComponent(s);
    });
    return { url: out, empty: named > 0 && set === 0 };
  }
  const seq = new Map(); // id -> run counter, so a slow answer never overwrites a newer one
  async function runQuery(id, mode) {
    const d = defs.get(id);
    const n = (seq.get(id) || 0) + 1;
    seq.set(id, n);
    const { url, empty } = fill(d.url);
    if (empty) {
      // Idle: no rows, no request.
      settle(id, []);
      recompute([id]);
      return;
    }
    if (mode === 'refresh' && state.get(id) && state.get(id).status === 'ok') put(id, { refreshing: true });
    else put(id, Object.assign(blank('loading'), { refreshing: false }));
    notify();
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), QUERY_TIMEOUT_MS);
    let answer;
    try {
      const r = await fetch(url, { credentials: 'same-origin', signal: ctrl.signal, headers: { accept: 'application/json' } });
      answer = { success: true, status: r.status, statusText: r.statusText, text: await r.text() };
    } catch (e) {
      answer = { success: false, status: 0, statusText: ctrl.signal.aborted ? 'timed out' : 'network error', text: '' };
    } finally {
      clearTimeout(timer);
    }
    if (seq.get(id) !== n) return;
    answers.set(id, { answer, args: { url } });
    if (booted) applyAnswer(id);
  }
  function applyAnswer(id) {
    const got = answers.get(id);
    if (!got) return;
    answers.delete(id);
    const { answer, args } = got;
    if (!answer.success) {
      put(id, Object.assign(blank('error', 'The threat-feeds service did not answer (' + answer.statusText + ').'), { refreshing: false }));
      recompute([id]);
      return;
    }
    const l = loaders.get(id);
    try {
      if (l) {
        const out = l.fn({ answer, args });
        settle(id, out, out && Array.isArray(out.meta) ? out.meta : []);
      } else {
        if (answer.status < 200 || answer.status > 299) throw new Error('HTTP ' + answer.status);
        const body = JSON.parse(answer.text);
        settle(id, Array.isArray(body) ? body : body && Array.isArray(body.rows) ? body.rows : [body]);
      }
    } catch (e) {
      if (!/^threat-feeds: /.test(e && e.message)) report('loader ' + id, e);
      put(id, Object.assign(blank('error', "This source's loader stopped: " + (e && e.message ? e.message : e)), { refreshing: false }));
    }
    recompute([id]);
  }

  // ---------------------------------------------------------------- boot
  // Downloads start as soon as the manifest is read; their results wait until the page scripts (loaded after this
  // file) have registered every calc and loader, which DOMContentLoaded marks.
  const domReady = new Promise((resolve) => {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', resolve, { once: true });
    else resolve();
  });
  const booting = domReady.then(() => {
    booted = true;
    for (const id of order([...calcs.keys()])) runCalc(id);
    for (const id of [...answers.keys()]) applyAnswer(id);
    notify();
  });
  async function start() {
    try {
      const r = await fetch(MANIFEST, { credentials: 'same-origin', cache: 'no-cache' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      site = await r.json();
    } catch (e) {
      report('site manifest', e);
      site = { datasets: {}, params: {}, failed: true };
    }
    defaults = Object.assign({}, site.params || {});
    params = Object.assign({}, defaults, params);
    for (const [id, d] of Object.entries(site.datasets || {})) {
      defs.set(id, Object.assign({ id }, d));
      if (!state.has(id)) state.set(id, Object.assign(blank('loading'), { updated: d.updated || null }));
    }
    if (booted || site.failed) { await booting; for (const id of order([...calcs.keys()])) runCalc(id); notify(); }
    for (const [id, d] of defs) { if (d.kind === 'query') runQuery(id, 'load'); else loadFile(id); }
  }

  // ---------------------------------------------------------------- the interface
  const dash = {
    colors: ['var(--h-c1)', 'var(--h-c2)', 'var(--h-c3)', 'var(--h-c4)', 'var(--h-c5)', 'var(--h-c6)'],
    calc(id, def) {
      if (typeof id !== 'string' || !def || typeof def.fn !== 'function') return;
      calcs.set(id, { inputs: Array.isArray(def.inputs) ? def.inputs.slice() : [], fn: def.fn, title: def.title || id, description: def.description || '' });
      if (!state.has(id)) state.set(id, blank('loading'));
      if (booted) { runCalc(id); recompute([id]); }
    },
    loader(id, def) {
      if (typeof id !== 'string' || !def || typeof def.fn !== 'function') return;
      loaders.set(id, { fn: def.fn, description: def.description || '' });
      if (booted && answers.has(id)) applyAnswer(id);
    },
    data(id) {
      const s = state.get(id);
      if (s) return s;
      return unknown(id);
    },
    onData(cb) {
      if (typeof cb !== 'function') return;
      listeners.push(cb);
      try { cb(); } catch (e) { report('a dash.onData callback', e); }
    },
    params: () => Object.assign({}, params),
    setParams(p) {
      if (!p || typeof p !== 'object') return;
      const changed = Object.keys(p).filter((k) => params[k] !== p[k]);
      params = Object.assign({}, params, p);
      if (!changed.length) return;
      for (const [id, d] of defs) if (d.kind === 'query' && templateKeys(d.url).some((k) => changed.includes(k))) runQuery(id, 'param');
      notify();
    },
    resetParams() { dash.setParams(Object.assign({}, defaults)); },
    refresh(id) {
      const d = defs.get(id);
      if (d && d.kind === 'query') return void runQuery(id, 'refresh');
      if (d) { put(id, { refreshing: true }); notify(); return void loadFile(id); }
      if (calcs.has(id) && booted) { runCalc(id); recompute([id]); }
    },
    setLink(fragment) {
      if (typeof fragment !== 'string') return;
      try { history.replaceState(history.state, '', '#' + fragment); } catch { /* sandboxed */ }
    },
    // Site extension: the dataset catalog with each dataset's current status, for the page's data list.
    datasets() {
      return [...defs.values()].map((d) => {
        const s = state.get(d.id) || blank('loading');
        return { id: d.id, title: d.title, description: d.description, kind: d.kind, url: d.kind === 'file' ? d.url : d.url.replace(TEMPLATE, '{$1}'),
          schedule: d.schedule || '', updated: d.updated || null, staleAfterHours: d.staleAfterHours || null, status: s.status, stale: !!s.stale, rows: s.rows ? s.rows.length : 0, message: s.message };
      });
    },
    site: () => (site ? { title: site.title, built: site.built, commit: site.commit } : null),
  };
  window.dash = dash;
  start();
})();
