// ---------------------------------------------------------------- Sigma detection drafts (3.8.0)
// Draft Sigma rules for the threats the collection is reporting now, written by a free hosted model from the
// publishers' own pages and accepted only through deterministic checks. Each hour at most one subject is drafted:
// a malware family, tool, actor, campaign, extortion brand or CVE named by MIN_PUBLISHERS or more publishers in
// LOOKBACK_DAYS, with at least one research entry, and not drafted within its cooldown. The job reads up to PAGES of
// those entries' pages (the report agent's fetcher), asks the model for rules as JSON, and checks every rule:
//   logsource      a Sigma taxonomy category (or the Windows security and system channels) with its product
//   fields         the taxonomy's field names for that log source, with contains, startswith, endswith, all, windash
//   condition      parsed; names only defined selections, uses every one, and is false when nothing matches
//   grounding      every detection value appears in the fetched pages (refanged, case-insensitive, by wildcard
//                  fragment); Windows event ids are exempt
//   specificity    at least one grounded value of 8 characters or more that is not a common system binary or path
//   tags           ATT&CK technique ids that exist in ATT&CK v20 (the Defense page's technique table), tactic names
//   evidence       the numbered sources the rule rests on, which become its references
// A rule that fails goes back to the model once with the failures; what still fails is kept as rejected, with the
// reasons. The YAML is written here, never by the model: status experimental, an unreviewed-draft author line and a
// deterministic id. Drafts are leads for a detection engineer to test, never deployable content.
export const SIGMA = { LOOKBACK_DAYS: 14, MIN_PUBLISHERS: 3, COOLDOWN_DAYS: 21, RETRY_DAYS: 3, DAILY: 6, PAGES: 5, TRIES: 9, PAGE_CHARS: 12000, SOURCE_CHARS: 48000,
  BUDGET_MS: 270000, CALL_MS: 150000, MAX_RULES: 3, KEEP_DAYS: 365, DOC_DAYS: 180, TYPES: ['malware', 'tool', 'actor', 'campaign', 'extortion', 'cve'],
  TECH_URL: 'https://intel.kilfoycyber.com/data/defense_techniques.json', PROMPT_V: 1 };

// Sigma's log source taxonomy (sigma-specification appendix), the categories a draft may use and their fields.
const WIN = ['windows'], HOST = ['windows', 'linux', 'macos'];
const PROC = ['Image', 'OriginalFileName', 'CommandLine', 'ParentImage', 'ParentCommandLine', 'CurrentDirectory', 'User', 'IntegrityLevel', 'Hashes', 'Product', 'Company', 'Description'];
export const SIGMA_TAXONOMY = {
  process_creation: { products: HOST, fields: PROC },
  file_event: { products: HOST, fields: ['TargetFilename', 'Image', 'User'] },
  file_delete: { products: WIN, fields: ['TargetFilename', 'Image', 'User'] },
  file_rename: { products: WIN, fields: ['SourceFilename', 'TargetFilename', 'Image'] },
  registry_set: { products: WIN, fields: ['TargetObject', 'Details', 'Image', 'EventType'] },
  registry_add: { products: WIN, fields: ['TargetObject', 'Image', 'EventType'] },
  registry_event: { products: WIN, fields: ['TargetObject', 'Details', 'Image', 'EventType'] },
  network_connection: { products: HOST, fields: ['DestinationHostname', 'DestinationIp', 'DestinationPort', 'SourceIp', 'SourcePort', 'Initiated', 'Image', 'User', 'Protocol'] },
  dns_query: { products: HOST, fields: ['QueryName', 'QueryResults', 'Image'] },
  image_load: { products: HOST, fields: ['ImageLoaded', 'Image', 'Signed', 'Signature', 'Hashes', 'OriginalFileName'] },
  driver_load: { products: WIN, fields: ['ImageLoaded', 'Hashes', 'Signed', 'Signature'] },
  pipe_created: { products: WIN, fields: ['PipeName', 'Image'] },
  create_remote_thread: { products: WIN, fields: ['SourceImage', 'TargetImage', 'StartModule', 'StartFunction'] },
  process_access: { products: WIN, fields: ['SourceImage', 'TargetImage', 'GrantedAccess', 'CallTrace'] },
  ps_script: { products: WIN, fields: ['ScriptBlockText', 'Path'] },
  ps_module: { products: WIN, fields: ['ContextInfo', 'Payload'] },
  wmi_event: { products: WIN, fields: ['EventType', 'Destination', 'Consumer', 'Filter', 'Query'] },
  proxy: { products: [null], fields: ['c-uri', 'c-uri-query', 'c-uri-stem', 'c-uri-extension', 'c-useragent', 'cs-host', 'cs-method', 'cs-referrer', 'r-dns', 'sc-status'] },
  webserver: { products: [null], fields: ['cs-method', 'cs-uri-query', 'cs-uri-stem', 'cs-user-agent', 'cs-referer', 'cs-host', 'sc-status', 'cs-username'] },
  dns: { products: [null], fields: ['query', 'answer', 'record_type'] },
};
export const SIGMA_SERVICES = {
  'windows/security': ['EventID', 'TaskName', 'TaskContent', 'ServiceName', 'ServiceFileName', 'ObjectName', 'ProcessName', 'NewProcessName', 'CommandLine', 'TargetUserName', 'SubjectUserName', 'ShareName', 'RelativeTargetName'],
  'windows/system': ['EventID', 'Provider_Name', 'ServiceName', 'ImagePath', 'StartType', 'AccountName'],
};
const MODS = new Set(['contains', 'startswith', 'endswith', 'all', 'windash']);
const NUMERIC = new Set(['EventID', 'DestinationPort', 'SourcePort', 'sc-status']);
// Values a rule cannot rest on alone: system binaries, interpreters and common paths every environment runs.
const SIGMA_GENERIC = new Set(['cmd.exe', 'powershell.exe', 'pwsh.exe', 'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe', 'certutil.exe', 'bitsadmin.exe',
  'schtasks.exe', 'reg.exe', 'msiexec.exe', 'explorer.exe', 'svchost.exe', 'curl.exe', 'wmic.exe', 'net.exe', 'net1.exe', 'whoami.exe', 'conhost.exe', 'taskkill.exe', 'vssadmin.exe',
  'bcdedit.exe', 'wevtutil.exe', 'nltest.exe', 'mstsc.exe', 'ntdsutil.exe', 'lsass.exe', 'winword.exe', 'excel.exe', 'outlook.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe',
  '/bin/bash', '/bin/sh', '/usr/bin/curl', '/usr/bin/wget', 'python', 'python3', 'bash', 'curl', 'wget', 'powershell', '\\appdata\\', '\\appdata\\roaming\\', '\\appdata\\local\\temp\\',
  '\\temp\\', '\\programdata\\', '\\users\\public\\', '\\windows\\temp\\', '\\windows\\system32\\', 'c:\\windows\\system32\\', 'http://', 'https://', '-encodedcommand', '-enc',
  '-noprofile', '-windowstyle hidden', 'invoke-expression', 'downloadstring', 'frombase64string', 'hkcu\\software\\microsoft\\windows\\currentversion\\run',
  'hklm\\software\\microsoft\\windows\\currentversion\\run', '\\currentversion\\run', '/tmp/', '/dev/shm/', 'get', 'post', '.php', '.jsp', '.aspx', '/api/',
  // runtimes, servers and their ordinary artefacts: a crash log or a worker process names the platform, never the threat
  'hs_err_pid', 'java.exe', 'javaw.exe', 'w3wp.exe', 'httpd.exe', 'nginx.exe', 'tomcat9.exe', 'node.exe', 'python.exe', 'pythonw.exe', 'php-cgi.exe', 'sqlservr.exe',
  'nginx', 'httpd', 'apache2', 'tomcat', 'catalina', 'java', 'node', 'perl', 'ruby', '/usr/bin/python', '/usr/bin/perl', '/bin/zsh', 'mozilla/5.0', 'user-agent',
  'c:\\windows', 'c:\\windows\\', 'c:\\program files', 'c:\\programdata', 'c:\\users', 'system32', 'syswow64', 'windows\\temp', 'appdata\\local', 'appdata\\roaming',
  'base64', 'whoami', 'ipconfig', 'systeminfo', 'tasklist', 'net user', 'net group', 'nslookup', 'ping', 'cmd /c', 'powershell -', '/bin/sh -c', 'chmod +x']);

// Filter selections (named filter*, Sigma's convention for exclusions) may also rest on standard install locations,
// which no report prints but every exclusion of a signed system binary needs.
const SIGMA_BENIGN = ['c:\\windows\\system32\\', 'c:\\windows\\syswow64\\', 'c:\\windows\\winsxs\\', 'c:\\program files\\', 'c:\\program files (x86)\\', '/usr/bin/', '/usr/sbin/', '/usr/lib/', '/applications/'];
const benign = (v) => SIGMA_BENIGN.some((b) => { const g = groundText(v).replace(/\*+$/, ''); return g === b || g.startsWith(b) && !/[*?]/.test(g.slice(b.length)) && g.length - b.length <= 40; });

// --- condition: tokens, parse, evaluation ---------------------------------------------------------------------------------
export function parseCondition(src) {
  const toks = String(src || '').match(/\(|\)|[A-Za-z_][A-Za-z0-9_]*\*?|\d+|\S/g) || [];
  let i = 0;
  const peek = () => toks[i], eat = (t) => { if (toks[i] !== t) throw new Error(`expected "${t}" at "${toks[i] || 'end'}"`); i++; };
  const expr = () => { let n = term(); while (peek() === 'or') { i++; n = { op: 'or', a: n, b: term() }; } return n; };
  const term = () => { let n = factor(); while (peek() === 'and') { i++; n = { op: 'and', a: n, b: factor() }; } return n; };
  const factor = () => {
    const t = peek();
    if (t === 'not') { i++; return { op: 'not', a: factor() }; }
    if (t === '(') { i++; const n = expr(); eat(')'); return n; }
    if (t === '1' || t === 'all' || t === 'any') {
      i++; eat('of');
      const what = toks[i++];
      if (!what || !/^[A-Za-z_][A-Za-z0-9_]*\*?$/.test(what) || ['and', 'or', 'not', 'of'].includes(what)) throw new Error('"of" needs a selection pattern or "them"');
      return { op: t === 'all' ? 'all' : 'one', of: what };
    }
    if (t && /^[A-Za-z_][A-Za-z0-9_]*$/.test(t) && !['and', 'or', 'of'].includes(t)) { i++; return { op: 'id', id: t }; }
    throw new Error(`unexpected "${t || 'end'}"`);
  };
  if (!toks.length) throw new Error('empty condition');
  const ast = expr();
  if (i < toks.length) throw new Error(`unexpected "${toks[i]}"`);
  return ast;
}
const ofNames = (pat, names) => (pat === 'them' ? names : pat.endsWith('*') ? names.filter((n) => n.startsWith(pat.slice(0, -1))) : names.filter((n) => n === pat));
export function condNames(ast, names, out = new Set()) {
  if (!ast) return out;
  if (ast.op === 'id') out.add(ast.id);
  else if (ast.op === 'one' || ast.op === 'all') ofNames(ast.of, names).forEach((n) => out.add(n));
  else { condNames(ast.a, names, out); condNames(ast.b, names, out); }
  return out;
}
export function condEval(ast, truth, names) {
  switch (ast.op) {
    case 'id': return !!truth[ast.id];
    case 'not': return !condEval(ast.a, truth, names);
    case 'and': return condEval(ast.a, truth, names) && condEval(ast.b, truth, names);
    case 'or': return condEval(ast.a, truth, names) || condEval(ast.b, truth, names);
    case 'one': return ofNames(ast.of, names).some((n) => truth[n]);
    case 'all': { const s = ofNames(ast.of, names); return s.length > 0 && s.every((n) => truth[n]); }
    default: return false;
  }
}

// --- grounding --------------------------------------------------------------------------------------------------------------
// Source text as the checks read it: lower case, refanged, HTML entities decoded by pageText already, doubled
// backslashes (JSON-escaped paths in a page) single, quotes and whitespace normalised.
export function groundText(s) {
  return String(s || '').toLowerCase().replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/g, '.').replace(/\[:\]/g, ':').replace(/\bhxxp/g, 'http').replace(/\[\/\/\]/g, '//')
    .replace(/\\\\/g, '\\').replace(/[\u2018\u2019]/g, "'").replace(/[\u201c\u201d]/g, '"').replace(/[\u2010-\u2015]/g, '-').replace(/\s+/g, ' ');
}
// The pieces of a value that must appear: split on Sigma wildcards, path separators kept inside, the ends trimmed.
export function fragments(v) {
  return groundText(v).split(/[*?]/).map((f) => f.replace(/^[\\/ ]+|[\\/ ]+$/g, '').trim()).filter((f) => f.length >= 3);
}
// A path fragment may join two printed pieces at one separator: a registry key and its value name, a folder and a
// file name, reported apart ("a Run key value named X under HKCU\...\Run").
const joined = (f, text) => {
  for (let i = 0; i < f.length; i++) {
    if (f[i] !== '\\' && f[i] !== '/') continue;
    const a = f.slice(0, i).replace(/[\\/ ]+$/, ''), b = f.slice(i + 1).replace(/^[\\/ ]+/, '');
    if (a.length >= 3 && b.length >= 3 && text.includes(a) && text.includes(b)) return true;
  }
  return false;
};
export function grounded(v, text, windash = false) {
  const fr = fragments(v);
  if (!fr.length) return false;
  return fr.every((f) => text.includes(f) || (windash && (text.includes(f.replace(/(^| )-/g, '$1/')) || text.includes(f.replace(/(^| )\//g, '$1-')))) || text.includes(f.replace(/ /g, '')) || joined(f, text));
}
const specificValue = (v) => {
  const f = fragments(v);
  return f.some((x) => x.length >= 8 && !SIGMA_GENERIC.has(x) && !SIGMA_GENERIC.has(x.split(/[\\/]/).pop()));
};

// Models often double every backslash in a Windows path (JSON escaping applied twice). Pairs are folded to one,
// keeping Sigma's own escapes before a wildcard.
export function unescapeValue(v) {
  // Doubling is systematic: when any backslash pair follows the start, every pair is folded once (a doubled UNC
  // prefix of four becomes two). A pair only at the start is a UNC prefix and stays.
  if (!/\\\\(?![*?])/.test(v.slice(2))) return v;
  return v.replace(/\\\\(?![*?])/g, '\\');
}

// --- one rule ---------------------------------------------------------------------------------------------------------------
// ctx: { text (groundText of the sources), sources: n, techniques: Set of ATT&CK ids, tactics: Set of tactic slugs }.
// Returns { ok, failures: [..], rule (normalised) }.
export function checkRule(r, ctx) {
  const fail = [], warn = [];
  if (!r || typeof r !== 'object') return { ok: false, failures: ['the rule is not an object'] };
  const title = String(r.title || '').trim(), description = String(r.description || '').trim();
  if (title.length < 10 || title.length > 110) fail.push('title must be 10 to 110 characters');
  if (description.length < 30) fail.push('description must say what the rule detects (30 characters or more)');
  const ls = r.logsource || {};
  const cat = ls.category ? String(ls.category).toLowerCase() : null, prod = ls.product ? String(ls.product).toLowerCase() : null, svc = ls.service ? String(ls.service).toLowerCase() : null;
  let fields = null;
  if (cat) {
    const t = SIGMA_TAXONOMY[cat];
    if (!t) fail.push(`logsource category "${cat}" is not in the Sigma taxonomy this checker accepts (${Object.keys(SIGMA_TAXONOMY).join(', ')})`);
    else if (!t.products.includes(prod)) fail.push(`category ${cat} takes product ${t.products.map((p) => p || '(none)').join(' or ')}, not ${prod || '(none)'}`);
    else fields = t.fields;
    if (svc) fail.push('a category log source takes no service');
  } else if (svc) {
    fields = SIGMA_SERVICES[`${prod}/${svc}`] || null;
    if (!fields) fail.push(`service log source ${prod}/${svc} is not accepted (${Object.keys(SIGMA_SERVICES).join(', ')})`);
  } else fail.push('logsource needs a category, or product windows with service security or system');
  const det = r.detection && typeof r.detection === 'object' && !Array.isArray(r.detection) ? r.detection : null;
  if (!det) return { ok: false, failures: [...fail, 'detection must be an object of selections and a condition'] };
  const names = Object.keys(det).filter((k) => k !== 'condition');
  if (!names.length) fail.push('detection has no selection');
  if (names.length > 8) fail.push('detection has more than 8 selections');
  const clean = {}, values = [];
  for (const name of names) {
    if (!/^[a-z][a-z0-9_]{1,39}$/.test(name)) { fail.push(`selection name "${name}" must be lower case letters, digits and underscores`); continue; }
    const sel = det[name], maps = Array.isArray(sel) ? sel : [sel];
    if (!maps.length || maps.some((m) => !m || typeof m !== 'object' || Array.isArray(m))) { fail.push(`selection ${name} must be a field map or a list of field maps (keyword lists are not accepted)`); continue; }
    const outMaps = [];
    for (const m of maps) {
      const om = {};
      for (const [key, raw] of Object.entries(m)) {
        const [field, ...mods] = key.split('|');
        if (fields && !fields.includes(field)) fail.push(`field ${field} is not a ${cat || prod + '/' + svc} field (${fields.join(', ')})`);
        const bad = mods.filter((x) => !MODS.has(x));
        if (bad.length) fail.push(`modifier ${bad.join(', ')} on ${field} is not accepted (contains, startswith, endswith, all, windash)`);
        const list = (Array.isArray(raw) ? raw : [raw]).filter((x) => x !== null && x !== undefined && String(x).trim() !== '');
        if (!list.length) { fail.push(`field ${key} in ${name} has no value`); continue; }
        if (list.length > 25) fail.push(`field ${key} in ${name} has more than 25 values`);
        if (mods.includes('all') && list.length < 2) fail.push(`the all modifier on ${field} needs two or more values`);
        const vals = list.map((x) => (NUMERIC.has(field) && /^\d+$/.test(String(x).trim()) ? +String(x).trim() : unescapeValue(String(x))));
        for (const v of vals) {
          if (typeof v === 'number') continue;
          if (v.length > 300) fail.push(`a value of ${field} is longer than 300 characters`);
          values.push({ field, v, windash: mods.includes('windash'), sel: name });
        }
        om[key] = Array.isArray(raw) || vals.length > 1 ? vals : vals[0];
      }
      outMaps.push(om);
    }
    clean[name] = Array.isArray(sel) ? outMaps : outMaps[0];
  }
  let ast = null;
  try { ast = parseCondition(det.condition); } catch (e) { fail.push('condition: ' + e.message); }
  if (ast) {
    const used = condNames(ast, names);
    const unknown = [...used].filter((n) => !names.includes(n));
    if (unknown.length) fail.push(`condition names undefined selections: ${unknown.join(', ')}`);
    const unused = names.filter((n) => !used.has(n));
    if (unused.length) fail.push(`selections not used by the condition: ${unused.join(', ')}`);
    if (condEval(ast, {}, names)) fail.push('the condition is true when no selection matches (a rule must need a positive match)');
  }
  const ungrounded = values.filter((x) => !grounded(x.v, ctx.text, x.windash) && !(/^filter/.test(x.sel) && benign(x.v)));
  if (ungrounded.length) fail.push(`values not found in the sources: ${ungrounded.slice(0, 8).map((x) => `${x.field}=${JSON.stringify(x.v)}`).join('; ')}${ungrounded.length > 8 ? ` and ${ungrounded.length - 8} more` : ''}`);
  if (!values.some((x) => specificValue(x.v) && grounded(x.v, ctx.text, x.windash))) fail.push('no grounded value specific to this threat (8 characters or more, not a common system binary or path)');
  const tags = [...new Set((Array.isArray(r.tags) ? r.tags : []).map((t) => String(t).toLowerCase().trim()))];
  const tech = [], tac = [];
  for (const t of tags) {
    const m = t.match(/^attack\.(t\d{4}(?:\.\d{3})?)$/);
    if (m) { if (ctx.techniques && !ctx.techniques.has(m[1].toUpperCase())) fail.push(`ATT&CK technique ${m[1].toUpperCase()} does not exist in ATT&CK v20`); else tech.push(t); continue; }
    const s = t.match(/^attack\.([a-z-]+)$/);
    if (s && (!ctx.tactics || ctx.tactics.has(s[1]))) { tac.push(t); continue; }
    warn.push(`tag ${t} dropped`);
  }
  if (!tech.length) fail.push('tags need at least one ATT&CK technique id (attack.t1234 or attack.t1234.001)');
  const level = String(r.level || '').toLowerCase();
  if (!['low', 'medium', 'high'].includes(level)) fail.push('level must be low, medium or high (critical is not given to an unreviewed draft)');
  const ev = [...new Set((Array.isArray(r.evidence) ? r.evidence : []).map((n) => +n).filter((n) => Number.isInteger(n) && n >= 1 && n <= ctx.sources))];
  if (!ev.length) fail.push(`evidence must list the source numbers (1 to ${ctx.sources}) the rule rests on`);
  const fps = (Array.isArray(r.falsepositives) ? r.falsepositives : r.falsepositives ? [r.falsepositives] : []).map((x) => String(x).trim()).filter(Boolean).slice(0, 6);
  const rule = { title, description, logsource: Object.fromEntries(Object.entries({ category: cat, product: prod, service: svc }).filter(([, v]) => v)),
    detection: { ...clean, condition: String(det.condition || '').trim() }, falsepositives: fps.length ? fps : ['Unknown'], level, tags: [...tac, ...tech], evidence: ev };
  return { ok: !fail.length, failures: fail, warnings: warn, rule, values: values.length };
}

// --- YAML -------------------------------------------------------------------------------------------------------------------
const q = (s) => `'${String(s).replace(/'/g, "''").replace(/[\r\n]+/g, ' ')}'`;
const yv = (v) => (typeof v === 'number' ? String(v) : q(v));
export function sigmaId(subject, rule) {
  const h = createHash('sha256').update(subject + '\n' + JSON.stringify(rule.logsource) + JSON.stringify(rule.detection)).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${((parseInt(h[16], 16) & 3) | 8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}
export function toYaml(rule, meta) {
  const L = [];
  L.push(`title: ${q(rule.title)}`, `id: ${meta.id}`, 'status: experimental', `description: ${q(rule.description)}`);
  L.push('references:', ...meta.references.map((u) => `    - ${q(u)}`));
  L.push(`author: ${q(meta.author)}`, `date: ${meta.date}`, 'tags:', ...rule.tags.map((t) => `    - ${t}`), 'logsource:');
  for (const k of ['category', 'product', 'service']) if (rule.logsource[k]) L.push(`    ${k}: ${rule.logsource[k]}`);
  L.push('detection:');
  const map = (m, ind, first = '') => {
    let lead = first;
    for (const [k, v] of Object.entries(m)) {
      if (Array.isArray(v)) { L.push(`${ind}${lead}${k}:`, ...v.map((x) => `${ind}${lead ? '  ' : ''}    - ${yv(x)}`)); }
      else L.push(`${ind}${lead}${k}: ${yv(v)}`);
      if (lead) { ind += '  '; lead = ''; }
    }
  };
  for (const [name, sel] of Object.entries(rule.detection)) {
    if (name === 'condition') continue;
    L.push(`    ${name}:`);
    if (Array.isArray(sel)) for (const m of sel) map(m, '        ', '- ');
    else map(sel, '        ');
  }
  L.push(`    condition: ${rule.detection.condition}`, 'falsepositives:', ...rule.falsepositives.map((f) => `    - ${q(f)}`), `level: ${rule.level}`);
  return L.join('\n') + '\n';
}

// --- the model's answer -----------------------------------------------------------------------------------------------------
export function parseAnswer(content) {
  const s = String(content || '').replace(/^```(?:json)?\s*|\s*```\s*$/g, '');
  const a = s.indexOf('{'), b = s.lastIndexOf('}');
  if (a < 0 || b <= a) throw new Error('no JSON object in the answer');
  const j = JSON.parse(s.slice(a, b + 1));
  return { rules: Array.isArray(j.rules) ? j.rules.slice(0, SIGMA.MAX_RULES) : [], reason: j.reason ? String(j.reason).slice(0, 500) : null };
}
const SIGMA_SYS = `You are a detection engineer writing Sigma rule drafts from published threat reporting. Answer with one JSON object only, no prose:
{"rules": [{"title": "...", "description": "...", "logsource": {"category": "process_creation", "product": "windows"}, "detection": {"selection_x": {"Field|modifier": ["value", "value"]}, "condition": "selection_x"}, "falsepositives": ["..."], "level": "medium", "tags": ["attack.execution", "attack.t1059.001"], "evidence": [1, 3]}], "reason": "..."}
Rules:
- Use only behaviour and artefacts the SOURCES state: file names, paths, command-line strings, registry keys, named pipes, domains, URI paths, user agents. Copy each value exactly as the sources print it (refang domains). Never invent, generalise or complete a value.
- Log sources: a Sigma taxonomy category (process_creation, file_event, registry_set, network_connection, dns_query, image_load, pipe_created, ps_script, proxy, webserver and the like) with product windows, linux or macos (none for proxy, webserver and dns), or product windows with service security or system.
- Fields are the Sigma taxonomy field names (Image, CommandLine, ParentImage, TargetFilename, TargetObject, Details, QueryName, DestinationHostname, PipeName, ScriptBlockText, cs-uri-stem, c-useragent, EventID ...). Modifiers: contains, startswith, endswith, all, windash. No regular expressions, no keyword lists.
- Each rule rests on at least one value specific to this threat, not only on common tools such as cmd.exe or powershell.exe. Filters (condition "selection and not filter") are welcome where the sources name benign look-alikes.
- tags: ATT&CK technique ids the behaviour maps to, and tactic names. evidence: the numbers of the sources the rule rests on. level: low, medium or high.
- At most ${SIGMA.MAX_RULES} rules, each on a different behaviour. If the sources give no concrete host or network artefact, answer {"rules": [], "reason": "why"}.`;

// --- candidates, sources, the ATT&CK reference ------------------------------------------------------------------------------
let ATTACK = null;
async function attackRef() {
  if (ATTACK && Date.now() - ATTACK.at < 6 * 3600e3) return ATTACK;
  let rows = null;
  const r = await get(ENV().TI_TECHNIQUES_URL || SIGMA.TECH_URL, { as: 'json', timeout: 20000 });
  if (r.ok && Array.isArray(r.json) && r.json.length > 300) {
    rows = r.json.map((t) => ({ id: t.technique_id, name: t.name, tactics: t.tactics, sigma: +t.sigma || 0 }));
    await s3Put('ref/attack_techniques.json.gz', gzipSync(Buffer.from(JSON.stringify(rows)), { level: 9 }), 'application/gzip').catch(() => null);
  } else {
    const o = await refGet('ref/attack_techniques.json');
    if (!o) throw new Error('the ATT&CK technique table is unreachable: site ' + (r.status || r.error) + ', and ref/attack_techniques.json is missing from the bucket');
    rows = JSON.parse(o.buf.toString('utf8'));
  }
  const tactics = new Set(rows.flatMap((t) => String(t.tactics || '').split(',').map((x) => x.trim().toLowerCase().replace(/\s+/g, '-')).filter(Boolean)));
  ATTACK = { at: Date.now(), techniques: new Set(rows.map((t) => t.id)), byId: new Map(rows.map((t) => [t.id, t])), tactics };
  return ATTACK;
}
export function resetSigma() { ATTACK = null; }

export async function sigmaCandidates(limit = 10) {
  return sql(`WITH c AS (
      SELECT m.eid, count(DISTINCT m.host)::int AS p, count(DISTINCT m.link)::int AS n,
        count(DISTINCT m.link) FILTER (WHERE x.category = 'research')::int AS research, max(m.published) AS last_at
      FROM ti.mention m JOIN ti.item x ON x.link = m.link
      WHERE m.published > now() - make_interval(days => $1::int) AND split_part(m.eid, ':', 1) = ANY(ARRAY(SELECT jsonb_array_elements_text($2::jsonb)))
      GROUP BY 1 HAVING count(DISTINCT m.host) >= $3::int)
    SELECT c.*, e.n AS name, e.t AS type, e.names,
      EXISTS (SELECT 1 FROM ti.alert a WHERE a.subject = c.eid AND a.last_at > now() - interval '7 days') AS alerted
    FROM c JOIN ti.entity e ON e.id = c.eid
    WHERE c.research > 0 AND NOT EXISTS (SELECT 1 FROM ti.sigma s WHERE s.subject = c.eid
      AND s.created_at > now() - make_interval(days => CASE WHEN s.outcome IN ('error', 'no_source') THEN $4::int ELSE $5::int END))
    ORDER BY alerted DESC, c.research DESC, c.p DESC, c.last_at DESC LIMIT $6::int`,
  [SIGMA.LOOKBACK_DAYS, SIGMA.TYPES, SIGMA.MIN_PUBLISHERS, SIGMA.RETRY_DAYS, SIGMA.COOLDOWN_DAYS, limit]);
}
async function sigmaEntries(eid) {
  return sql(`SELECT DISTINCT ON (x.link) x.link, x.title, x.summary, x.host, x.published, x.category FROM ti.mention m JOIN ti.item x ON x.link = m.link
    WHERE m.eid = $1 AND m.published > now() - make_interval(days => $2::int) ORDER BY x.link, x.published DESC`, [eid, SIGMA.LOOKBACK_DAYS]);
}
// The entries' pages, research first, one per publisher, until PAGES have readable text that names the subject.
export async function sigmaSources(cand, entries, fetcher = fetchPage) {
  const names = [cand.name, ...String(cand.names || '').split(' | ')].map((s) => String(s).trim().toLowerCase()).filter((s) => s.length >= 3);
  const order = entries.slice().sort((a, b) => (b.category === 'research') - (a.category === 'research') || Date.parse(b.published) - Date.parse(a.published));
  const out = [], hosts = new Set();
  let tries = 0;
  for (const e of order) {
    if (out.length >= SIGMA.PAGES || tries >= SIGMA.TRIES) break;
    if (hosts.has(e.host)) continue;
    tries++;
    const p = await fetcher(e.link, e.title, SIGMA.PAGE_CHARS).catch((x) => ({ ok: false, error: x.message }));
    if (!p.ok) continue;
    const lt = p.text.toLowerCase();
    if (!names.some((n) => lt.includes(n))) continue;
    hosts.add(e.host);
    out.push({ n: out.length + 1, url: p.url || e.link, entry: e.link, title: e.title, host: e.host, published: e.published, text: p.text });
  }
  return out;
}
const sourcePack = (src) => {
  let left = SIGMA.SOURCE_CHARS;
  return src.map((s) => { const t = s.text.slice(0, Math.max(800, Math.floor(left / Math.max(1, src.length - s.n + 1)))); left -= t.length; return `[${s.n}] ${s.title} | ${s.host} | ${String(s.published || '').slice(0, 10)} | ${s.url}\n${t}`; }).join('\n\n');
};

// --- the job ----------------------------------------------------------------------------------------------------------------
async function sigmaBudget() {
  const day = new Date().toISOString().slice(0, 10), b = (await kvGet('sigma:budget')) || {};
  const used = b.day === day ? b.used || 0 : 0;
  if (used >= SIGMA.DAILY) return false;
  await kvPut('sigma:budget', { day, used: used + 1, cap: SIGMA.DAILY });
  return true;
}
// The record after a repair round: every rule of the second answer, plus the first answer's accepted rules the second
// dropped (an accepted rule stays accepted), plus its rejected rules the second neither kept nor corrected, so a
// rejection's reasons survive a model that answers the repair with nothing.
const ruleKey = (c) => (c.rule ? c.rule.title.toLowerCase() : '');
export function mergeRounds(first, second) {
  const out = second.slice(), titles = new Set(second.map(ruleKey));
  const ids = new Set(second.filter((c) => c.ok && c.rule).map((c) => JSON.stringify([c.rule.logsource, c.rule.detection])));
  for (const c of first) {
    if (c.ok && c.rule && !ids.has(JSON.stringify([c.rule.logsource, c.rule.detection]))) out.push(c);
    else if (!c.ok && !titles.has(ruleKey(c))) out.push({ ...c, failures: [...c.failures, 'dropped by the model in the repair round'] });
  }
  return out.slice(0, SIGMA.MAX_RULES * 2);
}
export async function draftSubject(cand, opts = {}) {
  const t0 = Date.now(), ref = opts.ref || (await attackRef());
  const entries = opts.entries || (await sigmaEntries(cand.eid));
  const src = await sigmaSources(cand, entries, opts.fetcher);
  const base = { subject: cand.eid, name: cand.name, type: cand.type, publishers: cand.p, entries: cand.n };
  if (!src.length) return { ...base, outcome: 'no_source', reason: `none of ${Math.min(entries.length, SIGMA.TRIES)} entry pages could be read with the subject named in it`, rules: [], sources: [], calls: [] };
  const ctx = { text: groundText(src.map((s) => s.title + '\n' + s.text).join('\n')), sources: src.length, techniques: ref.techniques, tactics: ref.tactics };
  const chat = opts.chat || orChat, models = opts.models || (await reportModels());
  const messages = [{ role: 'system', content: SIGMA_SYS },
    { role: 'user', content: `SUBJECT: ${cand.name} (${cand.type}), named by ${cand.p} publishers in ${SIGMA.LOOKBACK_DAYS} days.\n\nSOURCES:\n${sourcePack(src)}\n\nWrite the Sigma rule drafts for ${cand.name} as JSON.` }];
  const calls = [];
  let answer = null, model = null, mi = 0;
  const ask = async () => {
    while (mi < models.length && Date.now() - t0 < SIGMA.BUDGET_MS) {
      if (!opts.chat && !(await reportBudget())) throw new Error('the daily model request allowance is spent');
      const a = await chat(models[mi], messages, null, Math.max(30000, Math.min(SIGMA.CALL_MS, SIGMA.BUDGET_MS - (Date.now() - t0))));
      calls.push({ model: models[mi], ok: a.ok, status: a.status || null, error: a.ok ? null : String(a.error || '').slice(0, 160), tokens: a.usage ? { in: a.usage.prompt_tokens, out: a.usage.completion_tokens } : null });
      if (a.ok) {
        try { const p = parseAnswer(a.msg.content); model = models[mi]; messages.push({ role: 'assistant', content: String(a.msg.content).slice(0, 20000) }); return p; }
        catch (e) { calls[calls.length - 1].error = 'unreadable answer: ' + e.message; }
      }
      mi++;
    }
    return null;
  };
  answer = await ask();
  if (!answer) return { ...base, outcome: 'error', reason: 'no model answered with readable JSON', rules: [], sources: src.map(({ text, ...s }) => s), calls };
  const first = answer.rules.map((r) => checkRule(r, ctx));
  let checked = first, repaired = false;
  if (first.some((c) => !c.ok)) {
    const why = first.map((c, i) => (c.ok ? `rule ${i + 1}: accepted` : `rule ${i + 1}: ${c.failures.join(' | ')}`)).join('\n');
    messages.push({ role: 'user', content: `The checker rejected some rules:\n${why}\nAnswer again with the full JSON: keep the accepted rules unchanged, correct the others using only values printed in the sources, or drop them.` });
    const again = await ask();
    if (again) { checked = mergeRounds(first, again.rules.map((r) => checkRule(r, ctx))); repaired = true; }
  }
  const date = new Date().toISOString().slice(0, 10);
  const rules = checked.map((c) => {
    if (!c.rule) return { ok: false, failures: c.failures };
    const refs = c.rule.evidence.map((n) => src[n - 1] && src[n - 1].url).filter(Boolean);
    const id = sigmaId(cand.eid, c.rule);
    const techniques = c.rule.tags.filter((t) => /^attack\.t\d/.test(t)).map((t) => t.slice(7).toUpperCase());
    const out = { ok: c.ok, id, title: c.rule.title, level: c.rule.level, logsource: c.rule.logsource, techniques, failures: c.failures, warnings: c.warnings || [], evidence: c.rule.evidence,
      public_sigma: Object.fromEntries(techniques.map((t) => [t, ref.byId.get(t) ? ref.byId.get(t).sigma : null])), rule: c.rule };
    if (c.ok) out.yaml = toYaml({ ...c.rule, tags: [...c.rule.tags, 'detection.emerging-threats'] }, { id, references: refs, date,
      author: `KTI draft by ${model} from public reporting, unreviewed (${new Date().toISOString().slice(0, 10)})` });
    return out;
  });
  const okN = rules.filter((r) => r.ok).length;
  return { ...base, outcome: okN ? 'draft' : rules.length ? 'rejected' : 'none', reason: answer.reason || (okN ? null : rules.length ? 'every rule failed the checks' : null), model,
    repaired, rules, sources: src.map(({ text, ...s }) => s), calls, ms: Date.now() - t0 };
}

export async function jobSigma(opts = {}) {
  const t0 = Date.now();
  await sql(`DELETE FROM ti.sigma WHERE created_at < now() - make_interval(days => $1::int)`, [SIGMA.KEEP_DAYS]);
  let attempt = null, skipped = null;
  if (!(ENV().OPENROUTER_API_KEY || ENV().TI_TRIAGE_KEY) && !opts.chat) skipped = 'the model key is not configured';
  else {
    const cands = await sigmaCandidates(5);
    if (!cands.length) skipped = 'no subject is due';
    else if (!opts.chat && !(await sigmaBudget())) skipped = `the daily allowance of ${SIGMA.DAILY} drafts is spent`;
    else {
      const c = cands[0];
      try { attempt = await draftSubject(c, opts); }
      catch (e) { attempt = { subject: c.eid, name: c.name, type: c.type, publishers: c.p, entries: c.n, outcome: 'error', reason: String(e.message).slice(0, 300), rules: [], sources: [], calls: [] }; }
      await sql(`INSERT INTO ti.sigma (subject, name, etype, outcome, reason, model, rules, sources, calls, prompt_v) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [attempt.subject, attempt.name, attempt.type, attempt.outcome, attempt.reason || null, attempt.model || null, JSON.stringify(attempt.rules), JSON.stringify(attempt.sources), JSON.stringify(attempt.calls), SIGMA.PROMPT_V]);
    }
  }
  return { attempt: attempt && { subject: attempt.subject, outcome: attempt.outcome, rules: attempt.rules.length, accepted: attempt.rules.filter((r) => r.ok).length, model: attempt.model || null, reason: attempt.reason || null },
    skipped, published: await putDoc('sigma', await sigmaDoc()), ms: Date.now() - t0 };
}

export async function sigmaDoc() {
  const rows = await sql(`SELECT id, subject, name, etype, outcome, reason, model, rules, sources, created_at FROM ti.sigma WHERE created_at > now() - make_interval(days => $1::int) ORDER BY created_at DESC`, [SIGMA.DOC_DAYS]);
  const out = [];
  for (const a of rows) {
    const rules = a.rules || [];
    out.push({ kind: 'attempt', attempt: +a.id, subject: a.subject, name: a.name, type: a.etype, outcome: a.outcome, reason: a.reason, model: a.model, created_at: a.created_at,
      accepted: rules.filter((r) => r.ok).length, rejected: rules.filter((r) => !r.ok).length, sources: (a.sources || []).map((s) => ({ n: s.n, url: s.url, title: s.title, host: s.host })) });
    for (const r of rules) {
      if (!r.title) continue;
      out.push({ kind: 'rule', attempt: +a.id, id: r.id, ok: r.ok, subject: a.subject, name: a.name, type: a.etype, title: r.title, level: r.level, logsource: r.logsource,
        techniques: r.techniques, public_sigma: r.public_sigma, gap: r.techniques.some((t) => r.public_sigma && r.public_sigma[t] === 0), failures: r.ok ? [] : r.failures,
        yaml: r.ok ? r.yaml : null, references: (r.evidence || []).map((n) => ((a.sources || [])[n - 1] || {}).url).filter(Boolean), model: a.model, created_at: a.created_at });
    }
  }
  const rules = out.filter((r) => r.kind === 'rule');
  return { source: 'KTI Sigma drafts: written by a free hosted model from publishers\' pages, accepted by deterministic checks, unreviewed', generated: new Date().toISOString(), served_from: 'store',
    window_days: SIGMA.DOC_DAYS, attempts: rows.length, drafts: rules.filter((r) => r.ok).length, rejected: rules.filter((r) => !r.ok).length,
    method: `Each hour at most one subject (a malware family, tool, actor, campaign, extortion brand or CVE named by ${SIGMA.MIN_PUBLISHERS} or more publishers in ${SIGMA.LOOKBACK_DAYS} days, with a research entry, not drafted in ${SIGMA.COOLDOWN_DAYS} days) is drafted from up to ${SIGMA.PAGES} of its entries' pages, at most ${SIGMA.DAILY} a day. A rule is accepted only when its log source and fields are in the Sigma taxonomy, its condition parses, uses every selection and needs a positive match, every detection value appears in the sources, one grounded value is specific to the threat, its ATT&CK techniques exist in ATT&CK v20 and it cites its sources. A failing rule goes back to the model once with the failures. The YAML is written by the collector: status experimental, an unreviewed-draft author line, a deterministic id. Drafts are leads to test in a lab, never rules to deploy.`,
    count: out.length, rows: out };
}
