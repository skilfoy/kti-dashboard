// Every offline test, in the order a change is checked: authored data, the collector build and its jobs, the Vercel
// service, the page calculations against the built site data, and the runtime. The browser check (test/e2e.mjs) runs
// separately because it needs Chromium.   node test/run_all.mjs      (from the repository root, after site_build.py)
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const py = process.env.PYTHON || 'python3';
const has = (m) => fs.existsSync(path.join(ROOT, 'node_modules', m));
const steps = [
  ['authored data validator', py, ['-I', 'pipeline/authored_build.py', 'data/authored', '--check']],
  ['collector build', py, ['pipeline/collector_build.py', '.']],
  ...(has('@electric-sql/pglite') ? [['collector jobs (PGlite)', process.execPath, ['test/collector_test.mjs', '.']]] : []),
  ['collector loader and deploy plan', process.execPath, ['test/loader_test.mjs', '.']],
  ['collector alert workflow', process.execPath, ['test/alert_test.mjs', '.']],
  ['reassessment watch', py, ['-I', 'pipeline/reassessment_watch.py', '--self-test']],
  ...(has('@electric-sql/pglite') ? [['submarine cables job and route (PGlite)', process.execPath, ['test/cables_test.mjs', '.']]] : []),
  ['data sources registry', process.execPath, ['test/data_sources_test.mjs', '.']],
  ['intel, lists and enrichment parts', process.execPath, ['test/intel_test.mjs', '.']],
  ['press-reported attacks part', process.execPath, ['test/cyber_test.mjs', '.']],
  ['context feeds part', process.execPath, ['test/context_test.mjs', '.']],
  ['Vercel service routes', process.execPath, ['test/vercel_store_test.js', '.']],
  ...(fs.existsSync(path.join(ROOT, 'public', 'site.json')) ? [['page calculations on the built data', process.execPath, ['test/defense_test.js', '.']]] : []),
  ['site runtime', process.execPath, ['test/runtime_test.js', '.']],
];
let failed = 0;
for (const [name, cmd, args] of steps) {
  const t0 = Date.now();
  const r = spawnSync(cmd, args, { cwd: ROOT, encoding: 'utf8', timeout: 600000 });
  const out = ((r.stdout || '') + (r.stderr || '')).trim().split('\n');
  const ok = r.status === 0;
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name} (${((Date.now() - t0) / 1000).toFixed(1)} s): ${out.filter((l) => /PASS|passed|checks|validator|sha256/.test(l)).slice(-1)[0] || out.slice(-1)[0] || ''}`);
  if (!ok) console.log(out.slice(-25).map((l) => '     ' + l).join('\n'));
}
if (!has('@electric-sql/pglite')) console.log('skip collector jobs (PGlite): npm i --no-save @electric-sql/pglite@0.5.8 to run it');
process.exit(failed ? 1 : 0);
