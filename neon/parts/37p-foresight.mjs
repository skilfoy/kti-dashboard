// ---------------------------------------------------------------- Threatcasting: futures and signposts (3.9.0)
// Three alternative futures over a fixed horizon for each CRITICAL and HIGH theater, drafted by a free hosted model
// from the theater's authored assessment, its warning indicators and its recent items, and accepted only through
// deterministic checks. The futures follow Suryavanshi's accelerating, gradual and constrained paths (Corporate
// Intelligence for Risk Management ch10) and Vanatta and Johnson's threatcasting frame (a person in a place doing an
// activity, the adversary's view, enabling conditions, effects), each backcast to the present as milestones and
// preparedness actions. Every future names signposts: existing indicator ids of its theater with the state the future
// expects (present or absent), and up to three proposed indicators the analyst may adopt. The reading, which future
// the current indicator states lean toward, is computed from the authored states and is never a forecast: futures
// carry no probability, and a match never confirms one (KCS advancement plan B69). The watch W-4B opens a change alert
// when a signpost indicator's state moves.
//
// One theater per run in the :04 slot, at most FORE.DAILY a day: the theater with no set, else the one whose
// threatcon, trend or indicator states changed since its set was drafted (at most once a day), else the oldest set
// past FORE.REFRESH_DAYS. A failing set goes back to the model once with the checker's failures; what still fails is
// stored as rejected with the reasons, and the theater keeps its last accepted set.
export const FORE = { HORIZON_MONTHS: 6, MIN_THREATCON: 4, DAILY: 8, REFRESH_DAYS: 7, CHANGED_MIN_H: 24, RETRY_H: 6, ITEMS: 25, BUDGET_MS: 270000, CALL_MS: 150000,
  KEEP_DAYS: 365, DOC_DAYS: 60, PROMPT_V: 1, SITE: 'https://intel.kilfoycyber.com/data/' };
export const FORE_KINDS = ['escalation', 'continuation', 'de-escalation'];
const PRESENT = new Set(['Observed', 'Confirmed']);

// Site datasets the job reads, with the bucket copy as the fallback when the site does not answer.
const SITEREF = new Map();
export async function siteRef(name, check) {
  const hit = SITEREF.get(name);
  if (hit && Date.now() - hit.at < 1800e3) return hit.rows;
  const r = await get((ENV().TI_SITE_DATA_URL || FORE.SITE) + name + '.json', { as: 'json', timeout: 30000 });
  let rows = r.ok && Array.isArray(r.json) && check(r.json) ? r.json : null;
  if (rows) await s3Put(`ref/${name}.json.gz`, gzipSync(Buffer.from(JSON.stringify(rows)), { level: 9 }), 'application/gzip').catch(() => null);
  else {
    const o = await refGet(`ref/${name}.json`);
    if (!o) throw new Error(`${name} is unreachable: site ${r.status || r.error}, and ref/${name}.json is missing from the bucket`);
    rows = JSON.parse(o.buf.toString('utf8'));
  }
  SITEREF.set(name, { at: Date.now(), rows });
  return rows;
}
export function resetForesight() { SITEREF.clear(); }
async function foreInputs() {
  const theaters = await siteRef('theaters', (a) => a.length >= 5 && a.every((t) => t.theater_id && t.name));
  const indicators = await siteRef('theater_indicators', (a) => a.length >= 10 && a.every((i) => i.ind_id && i.theater_id));
  const items = await siteRef('items', (a) => a.length >= 100 && a.every((i) => i.item_id));
  return { theaters, indicators, items };
}
// What a set rests on: a change here makes the theater due for a new set.
export const stateHash = (t, inds) => createHash('sha256').update(JSON.stringify([t.threatcon, t.label, t.trend, inds.map((i) => [i.ind_id, i.state]).sort()])).digest('hex').slice(0, 16);

// --- checks -----------------------------------------------------------------------------------------------------------------
const FIRST_PERSON = /\b(our|ours|we|us|your (company|organi[sz]ation|firm|business|bank|team))\b|\bthe client\b/i;
const PERCENT = /\b\d{1,3}(\.\d+)?\s?(%|per ?cent)|\bprobabilit(y|ies)\b|\b(likelihood|odds) of\b/i;
const txt = (x, n) => String(x == null ? '' : x).trim().slice(0, n);
// ctx: { theater, indicators (of this theater), items: Set of item ids supplied }. Returns { ok, failures, set }.
export function checkSet(ans, ctx) {
  const fail = [];
  const raw = ans && Array.isArray(ans.futures) ? ans.futures : null;
  if (!raw) return { ok: false, failures: ['the answer must be {"futures": [three futures]}'] };
  if (raw.length !== 3) fail.push(`three futures are needed (escalation, continuation, de-escalation), not ${raw.length}`);
  const byId = new Map(ctx.indicators.map((i) => [i.ind_id, i]));
  const futures = [];
  for (const [n, f] of raw.slice(0, 3).entries()) {
    const at = `future ${n + 1}`;
    if (!f || typeof f !== 'object') { fail.push(`${at} is not an object`); continue; }
    const kind = String(f.kind || '').toLowerCase();
    if (!FORE_KINDS.includes(kind)) fail.push(`${at}: kind must be escalation, continuation or de-escalation`);
    const name = txt(f.name, 90), narrative = txt(f.narrative, 1400);
    if (name.length < 6) fail.push(`${at}: a name of 6 to 90 characters is needed`);
    if (narrative.length < 120) fail.push(`${at}: the narrative must tell the future in 120 characters or more`);
    const tc = f.threatcast && typeof f.threatcast === 'object' ? f.threatcast : {};
    const cast = Object.fromEntries(['person', 'place', 'activity', 'adversary', 'enablers', 'effects'].map((k) => [k, txt(tc[k], 400)]));
    const missing = Object.entries(cast).filter(([, v]) => v.length < 3).map(([k]) => k);
    if (missing.length) fail.push(`${at}: threatcast needs ${missing.join(', ')}`);
    const sp = Array.isArray(f.signposts) ? f.signposts : [];
    const signposts = [];
    for (const s of sp) {
      const id = String((s && s.ind_id) || '').trim(), expect = String((s && s.expect) || '').toLowerCase();
      const ind = byId.get(id);
      if (!ind) { fail.push(`${at}: signpost ${id || '(no id)'} is not an indicator of ${ctx.theater.theater_id} (${[...byId.keys()].join(', ')})`); continue; }
      if (!['present', 'absent'].includes(expect)) { fail.push(`${at}: signpost ${id} needs expect present or absent`); continue; }
      const esc = ind.direction !== 'De-escalation';
      if (kind === 'escalation' && (esc ? expect !== 'present' : expect !== 'absent')) fail.push(`${at}: an escalation future expects escalation indicators present and de-escalation indicators absent (${id} is ${ind.direction})`);
      if (kind === 'de-escalation' && (esc ? expect !== 'absent' : expect !== 'present')) fail.push(`${at}: a de-escalation future expects escalation indicators absent and de-escalation indicators present (${id} is ${ind.direction})`);
      if (!signposts.some((x) => x.ind_id === id)) signposts.push({ ind_id: id, expect, why: txt(s.why, 240) });
    }
    const proposed = (Array.isArray(f.proposed_indicators) ? f.proposed_indicators : []).slice(0, 3).map((p) => ({ indicator: txt(p && p.indicator, 200), expect: String((p && p.expect) || 'present').toLowerCase() === 'absent' ? 'absent' : 'present', why: txt(p && p.why, 240) })).filter((p) => p.indicator.length >= 10);
    if (signposts.length + proposed.length < 3) fail.push(`${at}: three or more signposts are needed (existing indicators plus proposed ones)`);
    if (signposts.length < 1) fail.push(`${at}: at least one signpost must be an existing indicator of the theater`);
    const backcast = (Array.isArray(f.backcast) ? f.backcast : []).map((b) => ({ when: txt(b && b.when, 40), step: txt(b && b.step, 300) })).filter((b) => b.when && b.step.length >= 10);
    if (backcast.length < 3 || backcast.length > 6) fail.push(`${at}: the backcast needs three to six milestones from the horizon back to now`);
    const actions = (Array.isArray(f.actions) ? f.actions : []).map((a) => txt(a, 300)).filter((a) => a.length >= 15).slice(0, 5);
    if (actions.length < 2) fail.push(`${at}: two or more preparedness actions are needed`);
    const evidence = [...new Set((Array.isArray(f.evidence) ? f.evidence : []).map((e) => String(e).trim()))];
    const badEv = evidence.filter((e) => !ctx.items.has(e));
    if (badEv.length) fail.push(`${at}: evidence ${badEv.join(', ')} is not among the supplied items`);
    if (!evidence.filter((e) => ctx.items.has(e)).length) fail.push(`${at}: cite one or more supplied items as evidence`);
    const all = [name, narrative, ...Object.values(cast), ...backcast.map((b) => b.step), ...actions, ...proposed.map((p) => p.indicator)].join(' ');
    if (FIRST_PERSON.test(all)) fail.push(`${at}: write for any reader in the sector; no first person and no named client or organisation of the reader ("${all.match(FIRST_PERSON)[0]}")`);
    if (PERCENT.test(all)) fail.push(`${at}: a future carries no probability or percentage (it is not a forecast)`);
    futures.push({ kind, name, narrative, threatcast: cast, signposts, proposed, backcast, actions, evidence: evidence.filter((e) => ctx.items.has(e)) });
  }
  const kinds = futures.map((f) => f.kind);
  if (futures.length === 3 && FORE_KINDS.some((k) => !kinds.includes(k))) fail.push('one future of each kind is needed: escalation, continuation and de-escalation');
  const esc = futures.find((f) => f.kind === 'escalation'), de = futures.find((f) => f.kind === 'de-escalation');
  if (esc && de) {
    const same = esc.signposts.filter((s) => de.signposts.some((d) => d.ind_id === s.ind_id && d.expect === s.expect));
    if (same.length) fail.push(`the escalation and de-escalation futures expect the same thing of ${same.map((s) => s.ind_id).join(', ')}; signposts must separate the futures`);
  }
  const names = futures.map((f) => f.name.toLowerCase());
  if (new Set(names).size !== names.length) fail.push('the futures need distinct names');
  return { ok: !fail.length, failures: fail, set: { horizon_months: FORE.HORIZON_MONTHS, futures: FORE_KINDS.map((k) => futures.find((f) => f.kind === k)).filter(Boolean) } };
}

// The reading: for each future, the share of its existing-indicator signposts the current states meet (an Emerging
// indicator meets half of a "present" expectation). A future leads only with two or more met and a margin of 0.2 over
// the next; otherwise the indicators do not separate the futures. Proposed indicators are not measured and not counted.
export function readSet(set, indicators) {
  const st = new Map(indicators.map((i) => [i.ind_id, i]));
  const futures = set.futures.map((f) => {
    const sps = f.signposts.map((s) => {
      const i = st.get(s.ind_id), state = i ? i.state : null;
      const met = !i ? null : s.expect === 'present' ? (PRESENT.has(state) ? 1 : state === 'Emerging' ? 0.5 : 0) : state === 'Not observed' ? 1 : state === 'Emerging' ? 0.5 : 0;
      return { ...s, state, indicator: i ? i.indicator : null, last_seen: i ? i.last_seen || null : null, item_id: i ? i.item_id || null : null, met };
    });
    const known = sps.filter((s) => s.met != null);
    const score = known.length ? Math.round((known.reduce((a, s) => a + s.met, 0) / known.length) * 100) / 100 : null;
    return { kind: f.kind, name: f.name, score, met: known.filter((s) => s.met === 1).length, of: known.length, signposts: sps };
  });
  const ranked = futures.filter((f) => f.score != null).sort((a, b) => b.score - a.score);
  const lead = ranked[0] && ranked[0].met >= 2 && (!ranked[1] || ranked[0].score - ranked[1].score >= 0.2) ? ranked[0] : null;
  return { futures, leans: lead ? lead.kind : null, leans_name: lead ? lead.name : null,
    text: lead ? `Indicator states lean toward "${lead.name}" (${lead.met} of ${lead.of} signposts met); a reading of the analyst's indicator states, never a forecast.`
      : 'The indicator states do not separate the futures.' };
}

const FORE_SYS = `You are a strategic-warning analyst running a threatcasting exercise for a public threat-intelligence site read by people in financial services and their suppliers. Answer with one JSON object only, no prose:
{"futures": [{"kind": "escalation", "name": "...", "narrative": "...", "threatcast": {"person": "...", "place": "...", "activity": "...", "adversary": "...", "enablers": "...", "effects": "..."}, "signposts": [{"ind_id": "W-XXX-1", "expect": "present", "why": "..."}], "proposed_indicators": [{"indicator": "...", "expect": "present", "why": "..."}], "backcast": [{"when": "month 6", "step": "..."}, {"when": "month 3", "step": "..."}, {"when": "now", "step": "..."}], "actions": ["...", "..."], "evidence": ["I-123"]}, {"kind": "continuation", ...}, {"kind": "de-escalation", ...}]}
Rules:
- Exactly three futures over the stated horizon: escalation (the accelerating path), continuation (the gradual path) and de-escalation (the constrained path). Each is plausible from the material given; none is a prediction.
- threatcast: a person affected (a role, never a named private individual), the place, the activity they are doing when the threat lands, the adversary's view (what they want and why now), the enabling conditions, and the effects on operations, staff, connectivity, payments or energy.
- signposts: indicator ids from the INDICATORS list only, each with the state the future expects (present or absent). An escalation future expects escalation indicators present and de-escalation indicators absent; a de-escalation future the reverse; the escalation and de-escalation futures must not expect the same state of the same indicator. Add up to three proposed_indicators where the list lacks a signpost the future needs; every future has three or more signposts in all.
- backcast: three to six milestones from the horizon back to now. actions: two to five preparedness actions a reader in the sector could take now; generic, never addressed to one organisation, no first person.
- evidence: item ids from the ITEMS list that the future builds on. No probabilities or percentages anywhere: these are futures to prepare for, not forecasts.`;

export function parseFutures(content) {
  const s = String(content || '').replace(/^```(?:json)?\s*|\s*```\s*$/g, '');
  const a = s.indexOf('{'), b = s.lastIndexOf('}');
  if (a < 0 || b <= a) throw new Error('no JSON object in the answer');
  return JSON.parse(s.slice(a, b + 1));
}
function forePrompt(t, inds, items) {
  const L = [`THEATER: ${t.theater_id} ${t.name} (${t.region}); ThreatCon ${t.threatcon} ${t.label}, trend ${t.trend}. HORIZON: ${FORE.HORIZON_MONTHS} months from ${new Date().toISOString().slice(0, 10)}.`,
    `KEY JUDGMENT: ${txt(t.key_judgment, 900)}`, `SPONSOR POSTURE: ${txt(t.sponsor_posture, 700)}`, `CYBER NEXUS: ${txt(t.cyber_nexus, 700)}`, `OUTLOOK: ${txt(t.outlook, 900)}`,
    `ANALYST'S SCENARIO: ${txt(t.scenario, 400)}`, `SO WHAT: ${txt(t.so_what, 400)}`, `RECENT BASIS: ${txt(t.basis, 1800)}`, '', 'INDICATORS (id | direction | current state | indicator | note):',
    ...inds.map((i) => `${i.ind_id} | ${i.direction} | ${i.state} | ${txt(i.indicator, 200)} | ${txt(i.note, 220)}`), '', 'ITEMS (id | date | title):',
    ...items.map((i) => `${i.item_id} | ${String(i.date || '').slice(0, 10)} | ${txt(i.title, 260)}`)];
  return L.join('\n');
}

// --- choosing the theater ---------------------------------------------------------------------------------------------------
export async function foreDue(inp, now = Date.now()) {
  const last = await sql(`SELECT DISTINCT ON (theater_id) theater_id, state_hash, outcome, created_at FROM ti.foresight ORDER BY theater_id, created_at DESC`);
  const acc = await sql(`SELECT DISTINCT ON (theater_id) theater_id, state_hash, created_at FROM ti.foresight WHERE outcome = 'accepted' ORDER BY theater_id, created_at DESC`);
  const L = new Map(last.map((r) => [r.theater_id, r])), A = new Map(acc.map((r) => [r.theater_id, r]));
  const out = [];
  for (const t of inp.theaters.filter((x) => +x.threatcon >= FORE.MIN_THREATCON)) {
    const inds = inp.indicators.filter((i) => i.theater_id === t.theater_id);
    if (!inds.length) continue;
    const hash = stateHash(t, inds), l = L.get(t.theater_id), a = A.get(t.theater_id);
    const ageH = (r) => (now - Date.parse(r.created_at)) / 3600e3;
    if (l && l.outcome !== 'accepted' && ageH(l) < FORE.RETRY_H) continue;
    let why = null, rank = 0;
    if (!a) { why = 'no accepted set'; rank = 3; }
    else if (a.state_hash !== hash && ageH(a) >= FORE.CHANGED_MIN_H) { why = 'threatcon, trend or indicator states changed'; rank = 2; }
    else if (ageH(a) >= FORE.REFRESH_DAYS * 24) { why = `set older than ${FORE.REFRESH_DAYS} days`; rank = 1; }
    if (why) out.push({ t, inds, hash, why, rank, age: a ? ageH(a) : 1e9 });
  }
  return out.sort((x, y) => y.rank - x.rank || +y.t.threatcon - +x.t.threatcon || y.age - x.age);
}

// --- one theater ------------------------------------------------------------------------------------------------------------
export async function draftTheater(due, inp, opts = {}) {
  const t0 = Date.now(), t = due.t, inds = due.inds;
  const items = inp.items.filter((i) => i.theater_id === t.theater_id).sort((a, b) => String(b.date).localeCompare(String(a.date))).slice(0, FORE.ITEMS);
  const ctx = { theater: t, indicators: inds, items: new Set(items.map((i) => i.item_id)) };
  const chat = opts.chat || orChat, models = opts.models || (await reportModels());
  const messages = [{ role: 'system', content: FORE_SYS }, { role: 'user', content: forePrompt(t, inds, items) + '\n\nWrite the three futures as JSON.' }];
  const calls = [];
  let mi = 0, model = null;
  const ask = async () => {
    while (mi < models.length && Date.now() - t0 < FORE.BUDGET_MS) {
      if (!opts.chat && !(await reportBudget())) throw new Error('the daily model request allowance is spent');
      const a = await chat(models[mi], messages, null, Math.max(30000, Math.min(FORE.CALL_MS, FORE.BUDGET_MS - (Date.now() - t0))));
      calls.push({ model: models[mi], ok: a.ok, status: a.status || null, error: a.ok ? null : String(a.error || '').slice(0, 160), tokens: a.usage ? { in: a.usage.prompt_tokens, out: a.usage.completion_tokens } : null });
      if (a.ok) {
        try { const p = parseFutures(a.msg.content); model = models[mi]; messages.push({ role: 'assistant', content: String(a.msg.content).slice(0, 24000) }); return p; }
        catch (e) { calls[calls.length - 1].error = 'unreadable answer: ' + e.message; }
      }
      mi++;
    }
    return null;
  };
  const base = { theater_id: t.theater_id, name: t.name, threatcon: +t.threatcon, state_hash: due.hash, why: due.why };
  let ans = await ask();
  if (!ans) return { ...base, outcome: 'error', reason: 'no model answered with readable JSON', set: null, failures: [], calls, model: null };
  let c = checkSet(ans, ctx), repaired = false;
  if (!c.ok) {
    messages.push({ role: 'user', content: `The checker rejected the set:\n- ${c.failures.join('\n- ')}\nAnswer again with the full JSON, corrected; keep what was not rejected.` });
    const again = await ask();
    if (again) { c = checkSet(again, ctx); repaired = true; }
  }
  return { ...base, outcome: c.ok ? 'accepted' : 'rejected', reason: c.ok ? null : 'the set failed the checks', set: c.set, failures: c.failures, calls, model, repaired, ms: Date.now() - t0 };
}

async function foreBudget() {
  const day = new Date().toISOString().slice(0, 10), b = (await kvGet('foresight:budget')) || {};
  const used = b.day === day ? b.used || 0 : 0;
  if (used >= FORE.DAILY) return false;
  await kvPut('foresight:budget', { day, used: used + 1, cap: FORE.DAILY });
  return true;
}
export async function jobForesight(opts = {}) {
  const t0 = Date.now();
  await sql(`DELETE FROM ti.foresight WHERE created_at < now() - make_interval(days => $1::int) AND outcome <> 'accepted'`, [FORE.KEEP_DAYS]);
  const inp = opts.inputs || (await foreInputs());
  let attempt = null, skipped = null;
  if (!(ENV().OPENROUTER_API_KEY || ENV().TI_TRIAGE_KEY) && !opts.chat) skipped = 'the model key is not configured';
  else {
    const due = await foreDue(inp);
    if (!due.length) skipped = 'no theater is due';
    else if (!opts.chat && !(await foreBudget())) skipped = `the daily allowance of ${FORE.DAILY} sets is spent`;
    else {
      try { attempt = await draftTheater(due[0], inp, opts); }
      catch (e) { attempt = { theater_id: due[0].t.theater_id, name: due[0].t.name, threatcon: +due[0].t.threatcon, state_hash: due[0].hash, why: due[0].why, outcome: 'error', reason: String(e.message).slice(0, 300), set: null, failures: [], calls: [], model: null }; }
      await sql(`INSERT INTO ti.foresight (theater_id, name, state_hash, why, outcome, reason, model, futures, failures, calls, prompt_v) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [attempt.theater_id, attempt.name, attempt.state_hash, attempt.why, attempt.outcome, attempt.reason || null, attempt.model || null, JSON.stringify(attempt.set), JSON.stringify(attempt.failures || []), JSON.stringify(attempt.calls || []), FORE.PROMPT_V]);
    }
  }
  const doc = await foresightDoc(inp);
  await kvPut('foresight:signposts', doc.signposts);
  return { attempt: attempt && { theater_id: attempt.theater_id, outcome: attempt.outcome, why: attempt.why, model: attempt.model, failures: (attempt.failures || []).length },
    skipped, published: await putDoc('foresight', doc), ms: Date.now() - t0 };
}

// The document: the latest accepted set per theater with its reading against the current indicator states, the
// attempts of the last DOC_DAYS (rejected ones with the checker's reasons), and the signpost index the watch reads.
export async function foresightDoc(inp) {
  const sets = await sql(`SELECT DISTINCT ON (theater_id) id, theater_id, name, state_hash, model, futures, created_at FROM ti.foresight WHERE outcome = 'accepted' ORDER BY theater_id, created_at DESC`);
  const atts = await sql(`SELECT id, theater_id, name, why, outcome, reason, model, failures, created_at FROM ti.foresight WHERE created_at > now() - make_interval(days => $1::int) ORDER BY created_at DESC`, [FORE.DOC_DAYS]);
  const itemsById = new Map(inp.items.map((i) => [i.item_id, i]));
  const rows = [], signposts = {};
  for (const s of sets) {
    const t = inp.theaters.find((x) => x.theater_id === s.theater_id) || {};
    const inds = inp.indicators.filter((i) => i.theater_id === s.theater_id);
    const reading = readSet(s.futures, inds);
    const current = stateHash(t, inds) === s.state_hash;
    for (const [n, f] of s.futures.futures.entries()) {
      const r = reading.futures[n];
      rows.push({ kind: 'future', set: +s.id, theater_id: s.theater_id, theater: s.name, threatcon: +t.threatcon || null, future: f.kind, name: f.name, narrative: f.narrative, threatcast: f.threatcast,
        signposts: r.signposts.map((sp) => ({ ...sp, url: sp.item_id && itemsById.get(sp.item_id) ? itemsById.get(sp.item_id).url : null })), proposed: f.proposed, backcast: f.backcast, actions: f.actions,
        evidence: f.evidence.map((e) => ({ item_id: e, title: itemsById.has(e) ? itemsById.get(e).title : null, url: itemsById.has(e) ? itemsById.get(e).url : null, date: itemsById.has(e) ? itemsById.get(e).date : null })),
        score: r.score, met: r.met, of: r.of, leans: reading.leans === f.kind, horizon_months: s.futures.horizon_months, drafted_at: s.created_at, model: s.model, current });
      for (const sp of f.signposts) (signposts[sp.ind_id] = signposts[sp.ind_id] || []).push({ theater_id: s.theater_id, future: f.kind, name: f.name, expect: sp.expect });
    }
    rows.push({ kind: 'reading', set: +s.id, theater_id: s.theater_id, theater: s.name, leans: reading.leans, leans_name: reading.leans_name, text: reading.text, drafted_at: s.created_at, current,
      model: s.model, horizon_months: s.futures.horizon_months });
  }
  for (const a of atts) rows.push({ kind: 'attempt', id: +a.id, theater_id: a.theater_id, theater: a.name, why: a.why, outcome: a.outcome, reason: a.reason, model: a.model, failures: a.failures || [], created_at: a.created_at });
  return { source: 'KTI threatcasting: futures drafted by a free hosted model from the authored theater assessments, accepted by deterministic checks, read against the analyst\'s indicator states', generated: new Date().toISOString(),
    served_from: 'store', horizon_months: FORE.HORIZON_MONTHS, theaters: sets.length,
    method: `For each theater at ThreatCon ${FORE.MIN_THREATCON} or above, three futures over ${FORE.HORIZON_MONTHS} months (escalation, continuation, de-escalation), each a threatcast (person, place, activity, adversary's view, enabling conditions, effects) backcast to present milestones and preparedness actions. A set is accepted only when every signpost is an indicator of that theater with the state its future expects, escalation and de-escalation futures expect different states of shared indicators, every future has three or more signposts and cites the theater's items, and no future carries a probability or first-person text. The reading counts the signposts the current indicator states meet; it is never a forecast and never confirms a future. Sets are redrafted when the theater's threatcon, trend or indicator states change (at most daily) or after ${FORE.REFRESH_DAYS} days.`,
    signposts, count: rows.length, rows };
}
