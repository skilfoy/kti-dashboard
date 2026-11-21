# Non-English collection (3.10.0)

The source network reads publishers in more than a dozen languages. Release 3.10.0 does three things for them:
- it tags every entry with the language its text is written in;
- it translates non-English titles into English under deterministic checks;
- it feeds those English titles to entity matching, triage and search.

It also adds national CERTs, security press and theater press in their own languages, together with Google News queries in each theater's languages.

## Language identification

`detectLang` (`neon/parts/37q-translate.mjs`) works in two stages.

**Script.** It reads the script first:
- Japanese kana before Han;
- Hangul;
- Cyrillic: Ukrainian by і ї є ґ, Russian by ы э, Serbian by ј љ њ ћ ђ џ, Bulgarian by a doubled ъ;
- Arabic script: Urdu by ٹ ڈ ڑ ں ے ھ, Persian by پ چ ژ گ ک ی;
- Hebrew, Devanagari, Thai and Greek.

**Function words.** For Latin-script text it counts function words and the letters particular to each language: English, Spanish, Portuguese, French, German, Italian, Dutch, Polish, Turkish, Indonesian and Swedish, with Vietnamese by its diacritics.

A Latin-script result needs two signals, or one with no English signal at all. A tie leaves the language unsettled. An entry takes the language of its own title and summary, and the feed's tag only when the text does not settle it.

Before 3.10.0 the tag was the feed's, from five scripts. As a result:
- Japanese was stored as zh, Ukrainian as ru, and Urdu as ar;
- the German, French, Spanish, Hebrew and Hindi Google News queries were stored as en.

`pipeline/feeds_build.py` ports the same rules for feed tags. `test/fixtures/lang_samples.json` holds the cases both implementations must return.

## Title translation

The `translate` job runs in every slot, right after `sources`:

1. **Queue.** It takes non-English titles of the last 48 hours in this order: cyber categories, then theater and geopolitical press from theaters at ThreatCon 4 or above (by the feed's region), then the rest of that press, then everything else. Newest first within each group.
2. **Request.** Each round sends up to three batches of 40 at once to the reports' free hosted models, each batch starting on a different model. A run makes up to three rounds within 120 seconds. The job has its own allowance of 420 requests a day (kv `translate:budget`), taken one request at a time in one SQL statement.
3. **Checks.** A translation is stored in `ti.item.title_en`, with the model and time, only when all of these hold:
   - each line is answered once;
   - the text is mostly Latin letters;
   - the length is plausible;
   - every CVE id and every number of four or more digits in the source is kept (Arabic-Indic and full-width digits count as their ASCII digits);
   - for a non-Latin source, the text differs from the source.
4. **Failures.** A title that fails waits for the next run, and after two failures it is left untranslated. A 429 passes the batch to the next model. Timeouts and the run's own deadline count nothing against the titles.

## Where the English titles go

- **Entities:** the entities job reads translated titles as a third source, in `tr_at` order. A Russian entry that names Sandworm Team becomes a mention, and its entry document carries the English title.
- **Triage:** triage labels the English title.
- **Search:** search matches the English title through its own expression index (`item_tsv_en`). The Search page leads with the translation, marked "translated from" with the original beside it.
- **Sources page:** the network summary gives the last day's languages and how many titles carry a translation (kv `translate:status`).

## New sources

In `data/sources/core.json`; the weekly registry rebuild validates each one and keeps those that answer:

- **National CERTs and agencies in their own language:** JPCERT/CC, CERT Polska, BSI, INCIBE-CERT, NCSC-NL.
- **Security press:** Security NEXT, ScanNetSecurity, Boannews, heise Security, ZATAZ, Una al Día, Red Hot Cyber, CISO Advisor, SecurityLab.ru, Anti-Malware.ru, Habr, FreeBuf, Sekurak, Niebezpiecznik, Security.NL.
- **Theater press:** the BBC World Service in Persian, Arabic, Russian, Ukrainian, Urdu, Hindi, Chinese, Korean, Spanish, French, Hausa, Amharic, Somali and Turkish; the DW Persian, Arabic, Russian, Ukrainian, Chinese and Urdu services; Yonhap, NHK, Liberty Times and Ynet. Each carries its theater id.
- **Google News queries:** cyber queries in Persian, Simplified Chinese, Japanese, Korean, Russian, Arabic, Thai, Romanian and Czech. The new `gnews_topics_theater_lang` holds 21 queries in theaters' own languages, such as Houthi in Arabic, Hezbollah in Hebrew, PLA incursions in Traditional Chinese, North Korean missiles in Korean, and the Sahel in French.

## Limits

- A machine translation of a headline can drop nuance or mistranslate a name. The original stays beside it, and the link goes to the publisher.
- Summaries are not translated, so entity matching on a non-English entry rests on its title alone.
- The detector works on short text. A headline made only of names and numbers stays with the feed's tag.
