// Offline checks of the intraday lead watch (pipeline/lead_watch.mjs): which leads it raises and what it does with the issue.
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { watchLeads, plan, issueBody, fingerprint, TITLE } from '../pipeline/lead_watch.mjs';
let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const root = process.argv[2] || '.';
const J = [{ judgment_id: 'KJ-02', exec_rank: 1, status: 'Active', theater_id: 'T-HRM', title: 'Hormuz stays closed', situation: 'Extortion Group pressure and North Korean hackers are mentioned here.', assessment: '', attribution_judgment: '' },
  { judgment_id: 'KJ-05', exec_rank: 5, status: 'Active', title: 'North Korean revenue operations', situation: 'Lazarus Group and TraderTraitor target exchanges.', assessment: '', attribution_judgment: '' },
  { judgment_id: 'KJ-08', exec_rank: 0, status: 'Active', title: 'PRC coercion', situation: 'Volt Typhoon prepositioning.', assessment: '', attribution_judgment: '' }];
const row = (o) => ({ relevance: 3, title: 't', link: 'https://x.example/' + Math.random(), actors: [], cves: [], kev: [], published: '2026-11-15T10:00:00Z', ...o });
const doc = { rows: [row({ title: 'Edge flaw exploited', link: 'https://a.example/1', kev: ['CVE-2026-11111'] }), row({ title: 'Lazarus Group hits exchange', link: 'https://a.example/2', actors: ['Lazarus Group'] }),
  row({ title: 'Volt Typhoon report', actors: ['Volt Typhoon'] }), row({ title: 'KEV but background', relevance: 2, kev: ['CVE-2026-22222'] }), row({ title: 'APT in title', actors: ['APT'] }), row({ title: 'Unrelated breach' }),
  row({ title: 'Extortion Group claims theft', actors: ['Extortion Group'] }), row({ title: 'North Korean hackers', actors: ['North Korean'] }), row({ title: 'Tanker seized', link: 'https://a.example/3', theater: 'T-HRM' }), row({ title: 'Global story', theater: 'T-GLB' })] };
const hits = watchLeads(doc, J);
ok(hits.length === 3 && hits.some((h) => /CISA KEV/.test(h.why[0])) && hits.some((h) => /KJ-05 names/.test(h.why[0])) && hits.some((h) => /labelled T-HRM, the theater of KJ-02/.test(h.why[0])), 'raises KEV, named-actor and theater leads; generic actor phrases raise nothing: ' + JSON.stringify(hits.map((h) => h.why)));
ok(watchLeads({ rows: [] }, J).length === 0 && watchLeads(null, J).length === 0, 'empty and missing documents raise nothing');
const body = issueBody(hits, '2026-11-15T12:00Z');
ok(body.includes('fp:' + fingerprint(hits)) && body.includes('https://a.example/1') && /unreviewed model tier/.test(body), 'issue body lists the leads and carries the fingerprint');
ok(plan(hits, null, 'now').op === 'create' && plan(hits, null, 'now').title === TITLE, 'creates the issue when none is open');
ok(plan(hits, { number: 5, body }, 'now').op === 'none', 'same leads: nothing to do');
ok(plan(hits.slice(0, 1), { number: 5, body }, 'now').op === 'update', 'changed leads update the issue');
ok(plan([], { number: 5, body }, 'now').op === 'close' && plan([], null, 'now').op === 'none', 'no leads closes the issue, or does nothing');
const real = JSON.parse(fs.readFileSync(path.join(root, 'data', 'authored', 'judgments.json'), 'utf8'));
ok(Array.isArray(watchLeads({ rows: [row({ actors: ['Lazarus'] })] }, real)), 'runs against the authored judgments');
console.log(`PASS ${n} checks (lead watch)`);
