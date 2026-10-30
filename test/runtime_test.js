// Unit test of the site runtime (public/runtime/dash.js) in node, with a fake browser: manifest and dataset loading,
// the table normalizer, calcs in dependency order, query templates and idle queries, params, refresh, loader
// failures and a missing manifest.  node test/runtime_test.js <repository root>
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert/strict');
const ROOT = path.resolve(process.argv[2] || '.');
const SRC = fs.readFileSync(path.join(ROOT, 'public', 'runtime', 'dash.js'), 'utf8');
let pass = 0;
const ok = (c, m) => { assert.ok(c, m); pass++; };
const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

function boot(routes, { manifestStatus = 200 } = {}) {
  const calls = [];
  let domReady = null;
  const listeners = {};
  const document = {
    readyState: 'loading',
    addEventListener(ev, fn) { if (ev === 'DOMContentLoaded') domReady = fn; listeners[ev] = fn; },
  };
  const ctx = {
    console: { error: () => {} }, setTimeout, clearTimeout, AbortController, URLSearchParams, encodeURIComponent, Promise, JSON, Date, Math,
    requestAnimationFrame: (fn) => setTimeout(fn, 0),
    history: { state: null, replaceState(_s, _t, u) { ctx.__link = u; } },
    document,
    fetch: async (url) => {
      calls.push(url);
      if (url === '/site.json') {
        if (manifestStatus !== 200) return { ok: false, status: manifestStatus, json: async () => ({}) };
        return { ok: true, status: 200, json: async () => routes.manifest };
      }
      const key = String(url).split('?')[0];
      const r = routes[key] || routes[url];
      if (r === 'neterr') throw new Error('network');
      if (!r) return { ok: false, status: 404, statusText: 'Not Found', json: async () => ({}), text: async () => '{"error":"missing"}' };
      const body = typeof r.body === 'function' ? r.body(url) : r.body;
      return { ok: (r.status || 200) < 300, status: r.status || 200, statusText: 'OK', json: async () => body, text: async () => JSON.stringify(body) };
    },
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  vm.runInContext(SRC, ctx);
  return { dash: ctx.dash, calls, ready: () => { document.readyState = 'interactive'; domReady && domReady(); }, ctx };
}

const manifest = {
  title: 't', built: '2026-10-24T00:00:00Z', commit: 'abc', params: { vertical: 'financial', enrich_type: '', enrich_q: '' },
  datasets: {
    rows: { kind: 'file', url: '/data/rows.json?v=1', title: 'Rows', updated: { at: '2026-10-24T00:00:00Z' }, staleAfterHours: 1 },
    broken: { kind: 'file', url: '/data/broken.json?v=1', title: 'Broken' },
    live_a: { kind: 'query', url: '/api/a?limit=2', title: 'A' },
    live_q: { kind: 'query', url: '/api/q?type={{enrich_type}}&q={{enrich_q}}', title: 'Q' },
    live_x: { kind: 'query', url: '/api/x?domains={{exp_domains}}&ips={{exp_ips}}', title: 'X' },
    live_bad: { kind: 'query', url: '/api/bad', title: 'Bad' },
    live_down: { kind: 'query', url: '/api/down', title: 'Down' },
  },
};
let qHits = 0;
const routes = {
  manifest,
  '/data/rows.json': { body: [{ a: 1, list: [1, 2] }, { b: 'x', obj: { value: 3 }, rec: { k: 1 }, n: Infinity }] },
  '/api/a': { body: { source: 's', rows: [{ id: 1, v: 2 }, { id: 2, v: 5 }] } },
  '/api/q': { body: (u) => { qHits++; return { echo: u }; } },
  '/api/x': { body: (u) => ({ rows: [{ url: u }] }) },
  '/api/bad': { status: 500, body: { error: 'boom' } },
  '/api/down': 'neterr',
};

(async () => {
  const { dash, calls, ready, ctx } = boot(routes);
  // Page scripts register before DOMContentLoaded.
  dash.loader('live_a', { fn: ({ answer }) => { const b = JSON.parse(answer.text); return { data: b.rows, meta: [{ label: 'Source', value: b.source }] }; } });
  dash.loader('live_q', { fn: ({ answer, args }) => [{ url: args.url, body: answer.text }] });
  dash.loader('live_bad', { fn: ({ answer }) => { const b = JSON.parse(answer.text); if (b.error) throw new Error('threat-feeds: ' + b.error); return []; } });
  dash.calc('sum_a', { inputs: ['live_a'], fn: (a) => [{ total: a.reduce((s, r) => s + r.v, 0) }] });
  dash.calc('sum_twice', { inputs: ['sum_a'], fn: (s) => [{ twice: s[0].total * 2 }] });
  dash.calc('uses_broken', { inputs: ['broken'], fn: () => [{ x: 1 }] });
  dash.calc('uses_unknown', { inputs: ['nope'], fn: () => [{ x: 1 }] });
  dash.calc('throws', { inputs: ['rows'], fn: () => { throw new Error('bad calc'); } });
  let draws = 0;
  dash.onData(() => { draws++; });
  ok(draws === 1, 'onData runs its callback at once');
  ok(dash.data('rows').status === 'loading' && dash.data('anything').status === 'loading', 'everything is loading before the manifest');
  await tick(5);
  ok(calls.filter((u) => u.startsWith('/data/') || u.startsWith('/api/')).length >= 4, 'downloads start before the page has finished loading');
  ok(dash.data('rows').status === 'loading', 'results wait for DOMContentLoaded');
  ready();
  await tick(30);

  const rows = dash.data('rows');
  ok(rows.status === 'ok' && rows.data.length === 2 && rows.columns.join() === 'a,list,b,obj,rec,n', 'file table: union of keys in first-seen order');
  ok(rows.data[0].b === null && rows.data[0].list === '[1,2]' && rows.data[1].obj === 3 && rows.data[1].rec === '{"k":1}' && rows.data[1].n === null, 'cells normalized: missing null, list and record as JSON text, primitive value unwrapped, non-finite null');
  ok(rows.stale === true && rows.updated.at === '2026-10-24T00:00:00Z', 'a file past its staleAfterHours is marked stale');
  ok(dash.data('broken').status === 'error' && /did not load/.test(dash.data('broken').message), 'a missing file is an error with a message');
  ok(dash.data('uses_broken').status === 'error', 'a calc on a failed input fails');
  ok(dash.data('uses_unknown').status === 'missing', 'a calc on an unknown dataset is missing');
  ok(dash.data('throws').status === 'error' && /bad calc/.test(dash.data('throws').message), 'a throwing calc is an error');
  ok(dash.data('live_a').status === 'ok' && dash.data('live_a').meta[0].value === 's', 'query through its loader, with meta');
  ok(dash.data('sum_a').data[0].total === 7 && dash.data('sum_twice').data[0].twice === 14, 'calcs computed in dependency order');
  ok(dash.data('live_q').status === 'ok' && dash.data('live_q').data.length === 0 && qHits === 0, 'a query with an unset filter stays idle without a request');
  ok(dash.data('live_bad').status === 'error' && /boom/.test(dash.data('live_bad').message), 'loader failure carries its message');
  ok(dash.data('live_down').status === 'error' && /did not answer/.test(dash.data('live_down').message), 'network failure is an error');
  ok(dash.data('zzz').status === 'missing', 'an unknown name is missing once the manifest is read');

  // Params re-run the queries that name them.
  dash.setParams({ enrich_type: 'ip', enrich_q: '8.8.8.8 x' });
  ok(dash.params().enrich_q === '8.8.8.8 x' && dash.params().vertical === 'financial', 'params merge');
  ok(dash.data('live_q').status === 'loading', 'a re-parametrized query is loading again');
  await tick(20);
  ok(qHits === 1 && dash.data('live_q').data[0].url === '/api/q?type=ip&q=8.8.8.8%20x', 'template filled and URL-encoded');
  ok(dash.data('live_x').status === 'ok' && dash.data('live_x').data.length === 0, 'a query whose filters are all unset is idle');
  dash.setParams({ exp_domains: 'example.org' });
  await tick(20);
  ok(dash.data('live_x').data[0].url === '/api/x?domains=example.org&ips=', 'one filter set runs the query, the others sent empty');
  const before = calls.length;
  dash.setParams({ vertical: 'energy' });
  await tick(10);
  ok(calls.length === before, 'a param no query names triggers no request');

  // Refresh keeps the data while the query re-runs.
  routes['/api/a'].body = { source: 's2', rows: [{ id: 1, v: 10 }] };
  dash.refresh('live_a');
  ok(dash.data('live_a').refreshing === true && dash.data('live_a').status === 'ok', 'refresh keeps rows and marks refreshing');
  await tick(20);
  ok(dash.data('live_a').refreshing === false && dash.data('sum_twice').data[0].twice === 20, 'refresh lands and dependent calcs follow');
  dash.setLink('defense');
  ok(ctx.__link === '#defense', 'setLink sets the fragment');
  const cat = dash.datasets();
  ok(cat.length === 7 && cat.find((d) => d.id === 'live_q').url.includes('{enrich_q}') && cat.find((d) => d.id === 'rows').rows === 2, 'dataset catalog for the page');
  ok(dash.site().commit === 'abc', 'site build info');
  ok(draws > 3, 'listeners notified on changes');

  // A manifest that does not load fails every dataset.
  const b2 = boot(routes, { manifestStatus: 500 });
  b2.dash.calc('c', { inputs: ['rows'], fn: () => [] });
  b2.ready();
  await tick(20);
  ok(b2.dash.data('rows').status === 'error' && b2.dash.data('c').status === 'error', 'no manifest: datasets and calcs fail');
  console.log(`PASS ${pass} checks`);
})().catch((e) => { console.error(e); process.exit(1); });
