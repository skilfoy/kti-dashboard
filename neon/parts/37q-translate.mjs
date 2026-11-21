// ---------------------------------------------------------------- Non-English collection (3.10.0)
// 1. Language identification. Every entry the source network stores carries the language of its own title and summary,
//    identified here from the script and, for Latin-script text, from function words and letters particular to each
//    language. The feed's tag is the fallback when the text is too short or ambiguous. Until 3.10.0 the tag was the
//    feed's, from five scripts only: Japanese was stored as zh, Ukrainian as ru, Urdu as ar, and German, French,
//    Spanish, Hebrew or Hindi Google News queries as en. pipeline/feeds_build.py ports the same rules for feed tags,
//    and test/fixtures/lang_samples.json holds the cases both must agree on.
// 2. Title translation. The translate job runs in every slot between sources and entities. It sends non-English
//    titles of the last TR.WINDOW_H hours, cyber categories first, to the reports' free hosted models in batches of
//    TR.BATCH. Every translation is checked before it is stored in ti.item.title_en:
//    - each line answered once;
//    - mostly Latin letters;
//    - a plausible length;
//    - every CVE id and every number of four or more digits kept;
//    - for a non-Latin source, text that differs from the source.
//    A title that fails twice is left untranslated. The entities job reads translated titles as a third source (by
//    tr_at), triage labels the English title, and search matches it.
export const TR = { WINDOW_H: 48, BATCH: 40, PARALLEL: 3, ROUNDS: 3, DAILY: 420, MIN_THREATCON: 4, MAX_FAILS: 2, BUDGET_MS: 120000, CALL_MS: 75000, MIN_CALL_MS: 20000, MAX_TOKENS: 12000, PROMPT_V: 1,
  // Model order (3.12.1): each model's record of readable answers, decayed by DECAY a run so the order follows the last day.
  DECAY: 0.97 };

// --- language identification -----------------------------------------------------------------------------------------------
const LATIN_LANGS = {
  en: ['the', 'of', 'and', 'to', 'in', 'for', 'on', 'with', 'is', 'as', 'by', 'from', 'after', 'over', 'at', 'says', 'are', 'its', 'new', 'how', 'what', 'was', 'has', 'have', 'be', 'that', 'this', 'into', 'amid', 'against'],
  es: ['el', 'la', 'los', 'las', 'del', 'que', 'por', 'para', 'con', 'una', 'un', 'se', 'al', 'tras', 'sobre', 'es', 'su', 'sus', 'contra', 'como', 'más', 'según', 'ante'],
  pt: ['o', 'os', 'do', 'da', 'dos', 'das', 'que', 'em', 'no', 'na', 'nos', 'nas', 'para', 'com', 'um', 'uma', 'por', 'ao', 'após', 'é', 'são', 'contra', 'mais', 'pela', 'pelo'],
  fr: ['le', 'la', 'les', 'des', 'du', 'et', 'un', 'une', 'pour', 'sur', 'dans', 'par', 'au', 'aux', 'est', 'après', 'avec', 'contre', 'qui', 'ce', 'cette', 'son', 'ses', 'pas'],
  de: ['der', 'die', 'das', 'und', 'ist', 'mit', 'für', 'von', 'den', 'dem', 'im', 'auf', 'bei', 'nach', 'ein', 'eine', 'zu', 'nicht', 'gegen', 'wie', 'auch', 'sich', 'über', 'vor'],
  it: ['il', 'lo', 'gli', 'di', 'del', 'della', 'che', 'per', 'con', 'un', 'una', 'nel', 'nella', 'dopo', 'sono', 'è', 'alla', 'dei', 'delle', 'contro', 'sul', 'sulla'],
  nl: ['het', 'een', 'en', 'van', 'op', 'met', 'voor', 'bij', 'door', 'naar', 'aan', 'niet', 'dat', 'zijn', 'wordt', 'tegen', 'ook', 'nog', 'uit'],
  pl: ['w', 'z', 'i', 'na', 'do', 'się', 'nie', 'że', 'dla', 'po', 'od', 'przez', 'jest', 'oraz', 'ze', 'jak', 'atak', 'są'],
  tr: ['ve', 'bir', 'bu', 'ile', 'için', 'olarak', 'sonra', 'çok', 'yeni', 'gibi', 'daha', 'saldırı', 'saldırısı', 'oldu', 'değil', 'kadar'],
  id: ['dan', 'yang', 'di', 'ke', 'dari', 'untuk', 'dengan', 'ini', 'itu', 'pada', 'akan', 'oleh', 'dalam', 'tidak', 'serangan', 'siber', 'adalah'],
  sv: ['och', 'att', 'det', 'som', 'en', 'på', 'är', 'för', 'med', 'av', 'till', 'den', 'har', 'om', 'efter', 'mot', 'inte'],
};
const LATIN_SETS = Object.fromEntries(Object.entries(LATIN_LANGS).map(([k, v]) => [k, new Set(v)]));
// Letters that only some Latin-script languages use; each distinct one counts twice.
const LATIN_HINTS = { pl: 'ąćęłńśźż', tr: 'ığş', de: 'ßäöü', es: 'ñ¿¡', pt: 'ãõ', fr: 'œèêëîïûù', sv: 'å', vi: 'ăđơưạảấầẩẫậắằẳẵặẹẻẽếềểễệỉịọỏốồổỗộớờởỡợụủứừửữựỳỵỷỹ' };
const count = (s, re) => (s.match(re) || []).length;
export function detectLang(text) {
  const s = String(text || '').slice(0, 2000);
  const n = count(s, /\p{L}/gu);
  if (n < 4) return null;
  const share = (re) => count(s, re) / n;
  if (share(/[぀-ヿ]/g) > 0.08) return 'ja';
  if (share(/[가-힯ᄀ-ᇿ]/g) > 0.2) return 'ko';
  if (share(/[一-鿿㐀-䶿]/g) > 0.2) return 'zh';
  if (share(/[Ѐ-ӿ]/g) > 0.3) {
    if (/[іїєґІЇЄҐ]/.test(s)) return 'uk';
    if (/[ыэЫЭ]/.test(s)) return 'ru';
    if (/[јљњћђџЈЉЊЋЂЏ]/.test(s)) return 'sr';
    if (count(s, /[ъЪ]/g) >= 2) return 'bg';
    return 'ru';
  }
  if (share(/[؀-ۿݐ-ݿﭐ-﷿ﹰ-﻿]/g) > 0.3) {
    if (count(s, /[ٹڈڑںےھ]/g) >= 2) return 'ur';
    if (count(s, /[پچژگکی]/g) >= 2) return 'fa';
    return 'ar';
  }
  if (share(/[֐-׿]/g) > 0.3) return 'he';
  if (share(/[ऀ-ॿ]/g) > 0.3) return 'hi';
  if (share(/[฀-๿]/g) > 0.3) return 'th';
  if (share(/[Ͱ-Ͽ]/g) > 0.3) return 'el';
  if (share(/[a-zA-ZÀ-ɏḀ-ỿ]/g) < 0.6) return null;
  const low = s.toLowerCase();
  const vi = new Set(low.match(new RegExp(`[${LATIN_HINTS.vi}]`, 'g')) || []).size;
  if (vi >= 2) return 'vi';
  const words = low.match(/\p{L}+/gu) || [];
  const score = {};
  for (const [lang, set] of Object.entries(LATIN_SETS)) score[lang] = words.filter((w) => set.has(w)).length;
  for (const [lang, chars] of Object.entries(LATIN_HINTS)) if (lang !== 'vi' && score[lang] != null) score[lang] += 2 * new Set(low.match(new RegExp(`[${chars}]`, 'g')) || []).size;
  const ranked = Object.entries(score).sort((a, b) => b[1] - a[1]);
  const [top, second] = ranked;
  if (!top[1]) return null;
  if (top[1] === second[1]) return score.en === top[1] ? 'en' : null;
  if (top[0] === 'en') return 'en';
  return top[1] >= 2 || score.en === 0 ? top[0] : null;
}
// An entry's language: its own text first, the feed's tag when the text does not settle it.
export const entryLang = (title, summary, feedLang) => detectLang(`${title || ''} ${String(summary || '').slice(0, 600)}`) || feedLang || 'en';

// --- translation checks -----------------------------------------------------------------------------------------------------
const NON_LATIN = new Set(['zh', 'ja', 'ko', 'ru', 'uk', 'bg', 'sr', 'ar', 'fa', 'ur', 'he', 'hi', 'th', 'el']);
const ascii = (s) => String(s).replace(/[٠-٩]/g, (d) => d.charCodeAt(0) - 0x660).replace(/[۰-۹]/g, (d) => d.charCodeAt(0) - 0x6f0).replace(/[０-９]/g, (d) => d.charCodeAt(0) - 0xff10);
export function checkTranslation(src, lang, en) {
  const fail = [];
  const t = String(en || '').replace(/\s+/g, ' ').trim();
  if (!t) return ['empty'];
  if (t.length > 400) fail.push('longer than 400 characters');
  const letters = count(t, /\p{L}/gu), latin = count(t, /[a-zA-ZÀ-ɏ]/g);
  if (letters && latin / letters < 0.6) fail.push('not mostly Latin letters');
  const sl = String(src).length;
  if (t.length < Math.min(8, sl) || t.length > 8 * sl + 20) fail.push('implausible length');
  const a = ascii(src), b = ascii(t);
  for (const c of new Set((a.match(/CVE-\d{4}-\d{4,7}/gi) || []).map((x) => x.toUpperCase()))) if (!b.toUpperCase().includes(c)) fail.push(`${c} not kept`);
  for (const d of new Set(a.replace(/CVE-\d{4}-\d{4,7}/gi, '').match(/\d{4,}/g) || [])) if (!b.replace(/[,.\s ]/g, '').includes(d)) fail.push(`number ${d} not kept`);
  if (NON_LATIN.has(lang) && t.toLowerCase() === String(src).trim().toLowerCase()) fail.push('same as the source');
  return fail;
}
// Models answer in three shapes: the JSON object asked for, a bare JSON array of the same entries, or numbered lines in
// the request's own layout ("1<tab>[ru]<tab>Hackers attacked a bank"). On 21 November 2026, 21:37 UTC, six of twelve
// requests came back as "no JSON object" from four models. An answer cut off before its closing brace keeps the entries
// it completed.
const TR_ENTRY = /"i"\s*:\s*"?(\d+)"?\s*,\s*"en"\s*:\s*"((?:[^"\\]|\\.)*)"/g;
const TR_LINE = /^\s*(\d{1,3})\s*(?:[\t.):|-]+\s*|\s+)(?:\[[a-z]{2,3}\]\s*)?(.+?)\s*$/;
export function parseTranslations(content, n) {
  const s = String(content || '').replace(/^```(?:json)?\s*|\s*```\s*$/g, '').trim();
  const out = new Map();
  const put = (i, en) => { i = +i; if (Number.isInteger(i) && i >= 1 && i <= n && !out.has(i)) out.set(i, String(en == null ? '' : en)); };
  const a = s.indexOf('{'), b = s.lastIndexOf('}');
  if (a >= 0 && b > a) {
    try {
      const j = JSON.parse(s.slice(s[0] === '[' ? 0 : a, s[0] === '[' ? s.lastIndexOf(']') + 1 : b + 1));
      for (const r of Array.isArray(j) ? j : Array.isArray(j.t) ? j.t : []) if (r && typeof r === 'object') put(r.i, r.en);
      if (out.size) return out;
    } catch { /* an answer cut short: the entries it completed */ }
    for (const m of s.matchAll(TR_ENTRY)) { try { put(m[1], JSON.parse(`"${m[2]}"`)); } catch { /* a broken escape */ } }
    if (out.size) return out;
  }
  for (const line of s.split('\n')) { const m = line.match(TR_LINE); if (m && !/^[\[{"]/.test(m[2])) put(m[1], m[2].replace(/^["']|["']$/g, '')); }
  if (!out.size) throw new Error(s ? 'no numbered translations in the answer' : 'empty answer');
  return out;
}
// Readable answers per model, decayed each run. Models never tried rank at the prior of one half; a 429, or a timeout on a
// request the run's own deadline cut short, says nothing about the model and counts nothing.
export function rankModels(ids, stats = {}) {
  const score = (id) => { const x = stats[id] || {}; return ((x.ok || 0) + 1) / ((x.ok || 0) + (x.bad || 0) + 2); };
  return ids.map((id, k) => ({ id, k, s: score(id) })).sort((p, q) => q.s - p.s || p.k - q.k).map((x) => x.id);
}
export function updateModelStats(stats = {}, calls = []) {
  const out = {};
  for (const [id, x] of Object.entries(stats)) {
    const ok = (x.ok || 0) * TR.DECAY, bad = (x.bad || 0) * TR.DECAY;
    if (ok + bad >= 0.05) out[id] = { ok: +ok.toFixed(3), bad: +bad.toFixed(3) };
  }
  for (const c of calls) {
    if (!c.model || c.status === 429 || (c.short && c.error === 'deadline passed')) continue;
    const x = out[c.model] || (out[c.model] = { ok: 0, bad: 0 });
    if (c.ok && !c.error) x.ok += 1; else x.bad += 1;
  }
  return out;
}
const TR_SYS = `Translate each numbered news headline into English. Answer with one JSON object only: {"t": [{"i": 1, "en": "..."}, ...]}, one entry per headline, same numbers.
Keep names of people, organisations, products, malware and threat groups, CVE ids, numbers and dates exactly; transliterate names written in another script. Translate only: no notes, no explanations, no added context.`;

// --- the job ----------------------------------------------------------------------------------------------------------------
// The daily allowance, taken one request at a time in one statement, so batches sent in parallel cannot both read the
// same count and overspend it.
async function trBudget() {
  const day = new Date().toISOString().slice(0, 10);
  await sql(`INSERT INTO ti.kv (k, v, at) VALUES ('translate:budget', jsonb_build_object('day', $1::text, 'used', 0, 'cap', $2::int), now()) ON CONFLICT (k) DO NOTHING`, [day, TR.DAILY]);
  const r = await sql(`UPDATE ti.kv SET v = jsonb_build_object('day', $1::text, 'cap', $2::int, 'used', CASE WHEN v->>'day' = $1 THEN (v->>'used')::int ELSE 0 END + 1), at = now()
    WHERE k = 'translate:budget' AND (v->>'day' IS DISTINCT FROM $1 OR (v->>'used')::int < $2::int) RETURNING (v->>'used')::int AS used`, [day, TR.DAILY]);
  return r.length > 0;
}
// The queue's order: cyber categories, then theater and geopolitical press from theaters at ThreatCon MIN_THREATCON
// or above (the site's theaters, by the feed's region), then the rest of that press, then everything else; newest first.
export async function pendingTitles(limit, skip = [], hot = []) {
  return sql(`SELECT link, title, lang FROM ti.item WHERE lang <> 'en' AND title_en IS NULL AND tr_fail < $1 AND seen_at > now() - make_interval(hours => $2::int)
      AND NOT (link = ANY(ARRAY(SELECT jsonb_array_elements_text($4::jsonb))))
    ORDER BY CASE WHEN category IN ('vulnerability', 'government', 'research', 'cyber-news', 'topic-cyber', 'community') THEN 0
      WHEN category IN ('topic-theater', 'geopolitics', 'defense', 'maritime', 'think-tank') AND region = ANY(ARRAY(SELECT jsonb_array_elements_text($5::jsonb))) THEN 1
      WHEN category IN ('topic-theater', 'geopolitics', 'defense', 'maritime', 'think-tank') THEN 2 ELSE 3 END,
      seen_at DESC LIMIT $3::int`, [TR.MAX_FAILS, TR.WINDOW_H, limit, JSON.stringify(skip), JSON.stringify(hot)]);
}
async function hotTheaters() {
  try { return (await siteRef('theaters', (a) => a.length >= 5 && a.every((t) => t.theater_id))).filter((t) => +t.threatcon >= TR.MIN_THREATCON).map((t) => t.theater_id); }
  catch { return []; }
}
// A batch stops at the run's deadline: each request gets what is left of it (at most CALL_MS), and no request starts with
// less than MIN_CALL_MS left. Translation needs little reasoning, so requests ask for low effort and a short answer.
export async function translateBatch(rows, opts = {}, deadline = Date.now() + TR.BUDGET_MS, offset = 0) {
  const chat = opts.chat || orChat, all = opts.models || (await reportModels());
  const rmeta = opts.reasoning || (opts.chat ? {} : await modelReasoning());
  // Parallel batches start on different models, so one upstream provider's rate limit meets one batch, not all.
  const models = all.length ? [...all.slice(offset % all.length), ...all.slice(0, offset % all.length)] : all;
  const user = rows.map((r, n) => `${n + 1}\t[${r.lang}]\t${String(r.title).replace(/\s+/g, ' ').slice(0, 300)}`).join('\n');
  const calls = [];
  for (const model of models.slice(0, 4)) {
    const left = deadline - Date.now();
    if (left < TR.MIN_CALL_MS) return { done: null, calls, stop: 'run time spent', answered: calls.some((c) => c.ok) };
    if (!opts.chat && !(await trBudget())) return { done: null, calls, stop: 'daily allowance spent' };
    const ms = Math.min(TR.CALL_MS, left - 5000);
    // The least reasoning the model allows (3.12.2). With low effort, reasoning models spent 3,500 to 12,000 output
    // tokens on 40 headlines whose answer needs about 1,200 (21 November 2026, 22:57 UTC), and two answered nothing.
    const reasoning = leastReasoning(rmeta[model]);
    let a = await chat(model, [{ role: 'system', content: TR_SYS }, { role: 'user', content: user }], null, ms,
      { reasoning, max_tokens: TR.MAX_TOKENS, temperature: 0.1 });
    // A model that refuses the reasoning setting is asked once more with the catalogue's default.
    if (a.status === 400 && reasoning.effort !== 'low' && Date.now() + TR.MIN_CALL_MS < deadline && (opts.chat || (await trBudget())))
      a = await chat(model, [{ role: 'system', content: TR_SYS }, { role: 'user', content: user }], null, Math.min(TR.CALL_MS, deadline - Date.now() - 5000),
        { reasoning: { exclude: true }, max_tokens: TR.MAX_TOKENS, temperature: 0.1 });
    const call = { model, reasoning: reasoning.effort || (reasoning.max_tokens ? 'capped' : 'default'), ok: a.ok, status: a.status || null, error: a.ok ? null : String(a.error || '').slice(0, 120),
      ...(ms < TR.CALL_MS ? { short: true } : {}),
      ...(a.ok ? { finish: a.finish || null, chars: String((a.msg && a.msg.content) || '').length, out_tokens: (a.usage && a.usage.completion_tokens) || null } : {}) };
    calls.push(call);
    // A refused key or balance stops the run. A 429 is often one upstream provider's limit on one free model
    // (20 November 2026: two of three runs met one on the first model), so the next model is tried.
    if ([401, 402].includes(a.status)) return { done: null, calls, stop: `endpoint answered HTTP ${a.status}` };
    if (a.status === 429) continue;
    if (!a.ok) continue;
    let got;
    try { got = parseTranslations(a.msg.content, rows.length); } catch (e) { call.error = 'unreadable answer: ' + e.message + (a.finish && a.finish !== 'stop' ? ` (finish_reason ${a.finish})` : ''); continue; }
    if (got.size < rows.length / 2) { call.error = `answered ${got.size} of ${rows.length} lines`; continue; }
    const done = rows.map((r, n) => {
      const en = got.get(n + 1);
      // A line the answer left out (often an answer cut short) waits for the next run and counts nothing against it.
      if (en == null) return { link: r.link, ok: false, skip: true, en: null, why: ['not answered'], model };
      const f = checkTranslation(r.title, r.lang, en);
      return { link: r.link, ok: !f.length, en: f.length ? null : en.replace(/\s+/g, ' ').trim(), why: f, model };
    });
    return { done, calls, model };
  }
  if (calls.length && calls.every((c) => c.status === 429)) return { done: null, calls, stop: 'every model answered HTTP 429' };
  return { done: null, calls, stop: 'no model answered with readable JSON', answered: calls.some((c) => c.ok) };
}
export async function jobTranslate(opts = {}) {
  const t0 = Date.now();
  if (!(ENV().OPENROUTER_API_KEY || ENV().TI_TRIAGE_KEY) && !opts.chat) return { skipped: 'the model key is not configured', ms: Date.now() - t0 };
  const out = { batches: 0, sent: 0, translated: 0, failed: 0, reasons: {}, calls: [], stop: null };
  // A title tried in this run waits for the next one (and, as models fail over, perhaps another model). Each round
  // sends up to PARALLEL batches at once; a round whose batches all stop early ends the run.
  const tried = [], hot = await hotTheaters();
  const mstats = (await kvGet('translate:models')) || {};
  const models = rankModels(opts.models || (await reportModels()), mstats.stats || {});
  const bopts = { ...opts, models };
  const store = async (rows, r) => {
    out.calls.push(...r.calls);
    out.batches++; out.sent += rows.length;
    if (!r.done) {
      // When a model answered but nothing readable came back, the lines count a failure, so one poison title cannot
      // hold the queue. Timeouts, refusals and the run's own deadline say nothing about the titles and count nothing.
      if (r.answered) await sql(`UPDATE ti.item SET tr_fail = tr_fail + 1 WHERE link = ANY(ARRAY(SELECT jsonb_array_elements_text($1::jsonb)))`, [rows.map((x) => x.link)]);
      return r.stop;
    }
    const ok = r.done.filter((d) => d.ok), bad = r.done.filter((d) => !d.ok && !d.skip);
    out.unanswered = (out.unanswered || 0) + r.done.filter((d) => d.skip).length;
    await sqlTx([
      ...(ok.length ? [[`UPDATE ti.item i SET title_en = x.en, tr_model = x.model, tr_at = now() FROM jsonb_to_recordset($1::jsonb) AS x(link text, en text, model text) WHERE i.link = x.link`, [ok.map(({ link, en, model }) => ({ link, en, model }))]]] : []),
      ...(bad.length ? [[`UPDATE ti.item SET tr_fail = tr_fail + 1 WHERE link = ANY(ARRAY(SELECT jsonb_array_elements_text($1::jsonb)))`, [bad.map((d) => d.link)]]] : []),
    ]);
    out.translated += ok.length; out.failed += bad.length;
    for (const d of bad) for (const w of d.why) { const k = w.replace(/CVE-\S+|\d{4,}/g, '#'); out.reasons[k] = (out.reasons[k] || 0) + 1; }
    return null;
  };
  for (let round = 0; round < TR.ROUNDS && Date.now() - t0 < TR.BUDGET_MS - TR.MIN_CALL_MS; round++) {
    const rows = await pendingTitles(TR.BATCH * TR.PARALLEL, tried, hot);
    tried.push(...rows.map((r) => r.link));
    if (!rows.length) break;
    const chunks = [];
    for (let k = 0; k < rows.length; k += TR.BATCH) chunks.push(rows.slice(k, k + TR.BATCH));
    const res = await Promise.all(chunks.map((c, k) => translateBatch(c, bopts, t0 + TR.BUDGET_MS, round * TR.PARALLEL + k)));
    const stops = [];
    for (const [k, r] of res.entries()) stops.push(await store(chunks[k], r));
    if (stops.every(Boolean)) { out.stop = stops[0]; break; }
    out.stop = stops.find(Boolean) || null;
  }
  const [q] = await sql(`SELECT count(*) FILTER (WHERE title_en IS NULL AND tr_fail < $1)::int AS waiting, count(*) FILTER (WHERE title_en IS NOT NULL)::int AS translated,
      count(*) FILTER (WHERE title_en IS NULL AND tr_fail >= $1)::int AS given_up FROM ti.item WHERE lang <> 'en' AND seen_at > now() - make_interval(hours => $2::int)`, [TR.MAX_FAILS, TR.WINDOW_H]);
  const langs = await sql(`SELECT lang, count(*)::int AS n, count(title_en)::int AS translated FROM ti.item WHERE seen_at > now() - interval '24 hours' GROUP BY 1 ORDER BY 2 DESC`);
  const stats = updateModelStats(mstats.stats || {}, out.calls);
  await kvPut('translate:models', { at: new Date().toISOString(), stats, order: rankModels(models, stats) });
  await kvPut('translate:status', { at: new Date().toISOString(), window_h: TR.WINDOW_H, ...q, langs_24h: langs, models: rankModels(models, stats).slice(0, 6) });
  await recordVolume([['titles_translated', out.translated]]);
  return { ...out, calls: out.calls.slice(0, 12), queue: q, ms: Date.now() - t0 };
}
