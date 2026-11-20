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
export const TR = { WINDOW_H: 48, BATCH: 40, BATCHES: 4, DAILY: 200, MAX_FAILS: 2, BUDGET_MS: 120000, CALL_MS: 75000, MIN_CALL_MS: 20000, MAX_TOKENS: 6000, PROMPT_V: 1 };

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
export function parseTranslations(content, n) {
  const s = String(content || '').replace(/^```(?:json)?\s*|\s*```\s*$/g, '');
  const a = s.indexOf('{'), b = s.lastIndexOf('}');
  if (a < 0 || b <= a) throw new Error('no JSON object in the answer');
  const j = JSON.parse(s.slice(a, b + 1));
  const out = new Map();
  for (const r of Array.isArray(j.t) ? j.t : []) {
    const i = +r.i;
    if (Number.isInteger(i) && i >= 1 && i <= n && !out.has(i)) out.set(i, String(r.en == null ? '' : r.en));
  }
  return out;
}
const TR_SYS = `Translate each numbered news headline into English. Answer with one JSON object only: {"t": [{"i": 1, "en": "..."}, ...]}, one entry per headline, same numbers.
Keep names of people, organisations, products, malware and threat groups, CVE ids, numbers and dates exactly; transliterate names written in another script. Translate only: no notes, no explanations, no added context.`;

// --- the job ----------------------------------------------------------------------------------------------------------------
async function trBudget(want) {
  const day = new Date().toISOString().slice(0, 10), b = (await kvGet('translate:budget')) || {};
  const used = b.day === day ? b.used || 0 : 0, grant = Math.max(0, Math.min(want, TR.DAILY - used));
  if (grant) await kvPut('translate:budget', { day, used: used + grant, cap: TR.DAILY });
  return grant;
}
export async function pendingTitles(limit, skip = []) {
  return sql(`SELECT link, title, lang FROM ti.item WHERE lang <> 'en' AND title_en IS NULL AND tr_fail < $1 AND seen_at > now() - make_interval(hours => $2::int)
      AND NOT (link = ANY(ARRAY(SELECT jsonb_array_elements_text($4::jsonb))))
    ORDER BY CASE WHEN category IN ('vulnerability', 'government', 'research', 'cyber-news', 'topic-cyber', 'community') THEN 0 WHEN category IN ('topic-theater', 'geopolitics', 'defense', 'maritime', 'think-tank') THEN 1 ELSE 2 END,
      seen_at DESC LIMIT $3::int`, [TR.MAX_FAILS, TR.WINDOW_H, limit, JSON.stringify(skip)]);
}
// A batch stops at the run's deadline: each request gets what is left of it (at most CALL_MS), and no request starts with
// less than MIN_CALL_MS left. Translation needs little reasoning, so requests ask for low effort and a short answer.
export async function translateBatch(rows, opts = {}, deadline = Date.now() + TR.BUDGET_MS) {
  const chat = opts.chat || orChat, models = opts.models || (await reportModels());
  const user = rows.map((r, n) => `${n + 1}\t[${r.lang}]\t${String(r.title).replace(/\s+/g, ' ').slice(0, 300)}`).join('\n');
  const calls = [];
  for (const model of models.slice(0, 4)) {
    const left = deadline - Date.now();
    if (left < TR.MIN_CALL_MS) return { done: null, calls, stop: 'run time spent', answered: calls.some((c) => c.ok) };
    if (!opts.chat && !(await trBudget(1))) return { done: null, calls, stop: 'daily allowance spent' };
    const a = await chat(model, [{ role: 'system', content: TR_SYS }, { role: 'user', content: user }], null, Math.min(TR.CALL_MS, left - 5000),
      { reasoning: { effort: 'low', exclude: true }, max_tokens: TR.MAX_TOKENS, temperature: 0.1 });
    const call = { model, ok: a.ok, status: a.status || null, error: a.ok ? null : String(a.error || '').slice(0, 120) };
    calls.push(call);
    // A refused key or balance stops the run. A 429 is often one upstream provider's limit on one free model
    // (20 November 2026: two of three runs met one on the first model), so the next model is tried.
    if ([401, 402].includes(a.status)) return { done: null, calls, stop: `endpoint answered HTTP ${a.status}` };
    if (a.status === 429) continue;
    if (!a.ok) continue;
    let got;
    try { got = parseTranslations(a.msg.content, rows.length); } catch (e) { call.error = 'unreadable answer: ' + e.message; continue; }
    if (got.size < rows.length / 2) { call.error = `answered ${got.size} of ${rows.length} lines`; continue; }
    const done = rows.map((r, n) => {
      const en = got.get(n + 1);
      const f = en == null ? ['not answered'] : checkTranslation(r.title, r.lang, en);
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
  // A title tried in this run waits for the next one (and, as models fail over, perhaps another model).
  const tried = [];
  for (let b = 0; b < TR.BATCHES && Date.now() - t0 < TR.BUDGET_MS - TR.MIN_CALL_MS; b++) {
    const rows = await pendingTitles(TR.BATCH, tried);
    tried.push(...rows.map((r) => r.link));
    if (!rows.length) break;
    const r = await translateBatch(rows, opts, t0 + TR.BUDGET_MS);
    out.calls.push(...r.calls);
    out.batches++; out.sent += rows.length;
    if (!r.done) {
      out.stop = r.stop;
      // When a model answered but nothing readable came back, the lines count a failure, so one poison title cannot
      // hold the queue. Timeouts, refusals and the run's own deadline say nothing about the titles and count nothing.
      if (r.answered) await sql(`UPDATE ti.item SET tr_fail = tr_fail + 1 WHERE link = ANY(ARRAY(SELECT jsonb_array_elements_text($1::jsonb)))`, [rows.map((x) => x.link)]);
      break;
    }
    const ok = r.done.filter((d) => d.ok), bad = r.done.filter((d) => !d.ok);
    await sqlTx([
      ...(ok.length ? [[`UPDATE ti.item i SET title_en = x.en, tr_model = x.model, tr_at = now() FROM jsonb_to_recordset($1::jsonb) AS x(link text, en text, model text) WHERE i.link = x.link`, [ok.map(({ link, en, model }) => ({ link, en, model }))]]] : []),
      ...(bad.length ? [[`UPDATE ti.item SET tr_fail = tr_fail + 1 WHERE link = ANY(ARRAY(SELECT jsonb_array_elements_text($1::jsonb)))`, [bad.map((d) => d.link)]]] : []),
    ]);
    out.translated += ok.length; out.failed += bad.length;
    for (const d of bad) for (const w of d.why) { const k = w.replace(/CVE-\S+|\d{4,}/g, '#'); out.reasons[k] = (out.reasons[k] || 0) + 1; }
  }
  const [q] = await sql(`SELECT count(*) FILTER (WHERE title_en IS NULL AND tr_fail < $1)::int AS waiting, count(*) FILTER (WHERE title_en IS NOT NULL)::int AS translated,
      count(*) FILTER (WHERE title_en IS NULL AND tr_fail >= $1)::int AS given_up FROM ti.item WHERE lang <> 'en' AND seen_at > now() - make_interval(hours => $2::int)`, [TR.MAX_FAILS, TR.WINDOW_H]);
  const langs = await sql(`SELECT lang, count(*)::int AS n, count(title_en)::int AS translated FROM ti.item WHERE seen_at > now() - interval '24 hours' GROUP BY 1 ORDER BY 2 DESC`);
  await kvPut('translate:status', { at: new Date().toISOString(), window_h: TR.WINDOW_H, ...q, langs_24h: langs });
  await recordVolume([['titles_translated', out.translated]]);
  return { ...out, calls: out.calls.slice(0, 12), queue: q, ms: Date.now() - t0 };
}
