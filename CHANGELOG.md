# Changelog

## 3.4.2 (19 November 2026)

- Precision, from the first complete pass over the 67,830 stored entries. The most-named list held clear false matches, all from everyday words that MISP and Malpedia carry as aliases: Derusbi's "PHOTO" (94 entries), DONOT matching the words "do not" (73), Sea Turtle's "SILICON" (57), Earth Lusca's "Chromium" (78), the leak-site group "Global" (54), Broomstick's "Clean Up" (34), the "CALENDAR" family (34) and Qilin's "Agenda".
- Gazetteer rules (version 2):
  - An all-caps or camel-case word is still a word, so it is counted only capitalized, and only beside a cue when common.
  - A name made only of everyday words, or of four letters or fewer, needs a cue word.
  - A KEV vendor or product name outranks another entity's alias.
- Matcher rules (version 2):
  - A name of letters only matches as many words as it has.
  - Cue words are typed. Threat names need a threat word (ransomware, gang, hackers, APT, backdoor). Vendors need a vulnerability word (flaw, patch, zero-day, CVE). Generic words (security, cyber, attack, campaign, operation) no longer vouch.
- A change of either rules version re-derives every mention. Entries in the store are read again; older entry documents are matched again on their titles.
- Collector 2026-11-19.5.

## 3.4.1 (19 November 2026)

- The entities job's first live run read 876,000 rows in 95 seconds (251 MB of query results, 174 MB sent) and stored 1,375 mentions. The sources job stamps each insert with one `now()`, so up to 9,196 entries share a seen_at to the microsecond. The watermark kept a millisecond copy, which sorts before all of them, so the job reread the same 3,000 entries until its budget ran out. The job was paused (lease held) at 15:27 UTC. The watermark now keeps seen_at as text at full precision, and a batch that does not move it stops the run.
- Collector 2026-11-19.4.

## 3.4.0 (19 November 2026)

- Entity graph. A gazetteer built daily in the site build (`pipeline/build_gazetteer.py`, published at `/data/entity_gazetteer.json`) holds about 7,900 entities with 11,100 names: ATT&CK groups, software and campaigns, MISP threat actors, Malpedia families (new source: the MISP galaxy Malpedia cluster, CC BY-SA 4.0), leak-site extortion groups, KEV vendors, products and CVEs, with 5,700 curated relationships. Same-thing entries collapse: a MISP actor into the ATT&CK group it cites or whose alias it bears, a leak-site group into the ATT&CK group or Malpedia family of its name.
- The collector's new `entities` job (every slot, after the sources job) reads each collected entry and advisory once and stores the entities it names (`ti.mention`, with the entry in `ti.mdoc`, both kept 400 days). Matching is deterministic: multi-word and digit names in any case, single words only capitalized and, when common in general news (measured daily over the collection), beside a cue word; product names beside their vendor; countries only beside another entity.
- `/api/graph` serves the summary (rising and new entities, the most named per type, the strongest co-mentions by entries times normalized PMI, curated relationships), an entity's card, the entries two entities share, and name lookup. The new Graph page (tab 8) draws the co-mention network and each entity's neighbourhood; search hits list the entities they name. TAXII 2.1 gains an entity graph collection with curated and observed (co-mention) relationships kept apart.
- Removed the Oracle A1 launcher (`ocia1`, `37j-oci.mjs` and its data sources row) after Sean dropped Oracle on 19 November; the hosting decision is deferred and documented in the work tracker.
- Collector auto-deploy: a lease held more than 20 minutes ahead is an operator's pause and no longer holds the switch, and the gdelt run and `op=status` are each asked again for up to two minutes after the pin. The first two 3.4.0 deploys rolled back because a warm instance still answered on the old bundle (once the status, once the run).
- Collector 2026-11-19.3. Schema: `ti.entity`, `ti.erel`, `ti.mdoc`, `ti.mention`, keyset indexes on `ti.item` and `ti.advisory`, lease row `entities`.

## 3.3.0 (19 November 2026)

- Retired the sample organizational estate at Sean's instruction: the platform is a public piece and has no client or organization behind it. Removed the Residual risk page and its calculations, the `assets`, `controls` and `exposure_darkweb` datasets (sample rows on documentation IP space and invented coverage figures), the AutoRecon and darknet-mcp-server ingests, the live exposure monitor (`/api/exposure`, `live_exposure`) with its HIBP and GreyNoise health probes, method rules A3b, B8 and B9, and follow-ons FP-002 and FP-007. Defense page and method wording that assumed an organization's own rule inventory, visibility or estate now speaks to any defender. The tabs renumber from 7 (Actors).
- Carry-forward datasets are now verticals, osint_tools, indicator_rules and chokepoints.
- Collector 2026-11-19.2 (health probes only).

## 3.2.2 (19 November 2026)

- The Neon console showed the project at 98.2% of its 5 GB monthly transfer while `data_transfer_bytes` read 3.23 GB. The allowance is shared by Postgres, object storage and Functions, and Function egress (what the function sends out, SQL request bodies included) is not in `data_transfer_bytes`. The runs' own `db.sent_kb` showed the sources job sending about 4.2 MB a run (19 MB an hour): every entry of every feed it read, summaries included, with ON CONFLICT dropping the ones already stored. The sources job was paused (its lease held) with Sean's approval on 19 November at 03:10 UTC.
- The sources job now sends 12 characters of each entry's fingerprint, gets back the ones not stored, and inserts only those. Its result reports `entries` (read) and `new_entries` (sent).
- Collector 2026-11-19.1.

## 3.2.1 (18 November 2026)

- Measured after 3.2.0 (20:33 to 23:23 UTC): bucket reads 2.1 MB an hour (atlas 0.97, bundle 0.54, triage mirror 0.53, the A1 retrier's settings and bootstrap 0.05), query results 2.35 MB an hour (triage 0.86, of which one six-hourly full mirror refresh was 1.8 MB; sources 0.47; GDELT 0.43; infra 0.31). The meter rose about 5.9 MB an hour against the 6.2 MB an hour that 5 GB allows for the rest of November.
- GDELT reads the world atlas only when a file arrives to be parsed (half the runs on 18 November found none), and concurrent callers share one atlas read. The triage mirror's full refresh is daily instead of six-hourly; the row count check and the verifier overlay already keep the mirror exact between refreshes.
- Expected: about 0.7 MB an hour less, so about 5.2 MB an hour, and November near 4.7 GB.
- Collector 2026-11-18.6.

## 3.2.0 (18 November 2026)

- Transfer, storage side. Neon's transfer meter counts object storage reads as well as query results. The bucket's GET log for 07:08 to 17:24 UTC on 18 November held 86 MB, about three quarters of the meter's rise over those hours: the world atlas (28.7 MB, 38 reads at 756 KB), the code bundle (23.6 MB, 60 cold starts), the bundle's kept copy (14.9 MB, read back on every cold start to check it was there), the triage mirror (14.8 MB) and the triage evaluation set (2.6 MB). The 3.0.4 mirror had moved the triage window's reads from Postgres to the bucket at a third of the size, so it still saved transfer, though less than its note claimed.
- The loader reads the bundle from a gzipped copy (`code/collector.mjs.gz`, 135 KB for 400 KB) when that copy holds the pinned source, and from the plain object otherwise; it keeps its fallback copy gzipped and checks for it with HEAD. Reference files (the atlas, the evaluation set, the link list, the source registry) are read from gzipped copies first (`refGet`; the atlas is 229 KB gzipped). The triage window's mirror is kept in memory by the instance that wrote it, so a triage run reads the object once instead of twice. `op=push` takes `gz=1` to upload a gzipped copy.
- Transfer, Postgres side. Each run's `db` record put the triage evaluation first among query results (232 KB an hour) although the evaluation is complete and makes no request. A complete evaluation under the current prompt now returns on its stored summary and reads the gold set again once a day. The sources job (126 KB a run), infra (184 KB) and GDELT (92 KB) read what their work needs; they leave Neon with the database move.
- Expected effect: bucket reads from about 8.6 MB an hour to about 2.5 MB, query results from about 2.4 MB an hour to about 2.1 MB, and the meter from about 11.5 MB an hour to about 5 MB. At that rate November ends near 4.4 GB of the 5 GB allowance.
- Collector 2026-11-18.5; loader redeployed.

## 3.1.1 (18 November 2026)

- Transfer accounting both ways: each run records the bytes it sent with its queries (`db.sent_kb`) beside the bytes it read (`db.kb`), to reconcile the jobs' share against Neon's meter.
- The A1 launcher shows its public key again whenever Oracle rejects its signature, so a lost or replaced key can be registered without a redeploy.
- Collector 2026-11-18.4.

## 3.1.0 (18 November 2026)

- Database on Oracle Cloud, groundwork. Neon transfer kept running at about 11 MB an hour after 3.0.4 and 3.0.5, which reaches the Free plan's 5 GB around 25 to 27 November. The database moves to an Always Free Oracle Ampere A1 server (10 TB of outbound transfer a month). `ops/oracle/` holds the server bootstrap (Postgres 17 on the local socket, SearXNG, Caddy with automatic HTTPS, nightly dumps, host hardening), the SQL gateway that answers Neon's SQL-over-HTTP contract so the collector changes only its URL and credential (tested with the collector's client against Postgres: types, JSON, transactions, rollback on error), and the migration tool.
- The collector reads `TI_SQL_URL` and `TI_SQL_TOKEN` when set, and otherwise uses Neon. Each run records the query-result bytes it read (`db.kb`), which makes the transfer budget measurable per job.
- Chicago had no free A1 capacity in any availability domain on 18 November, and the tenancy's limit for AMD micros is zero. The new `ocia1` job asks for the A1 server in every slot until a launch succeeds, then returns at once. It signs Oracle API requests with a key it generates itself, whose private half never leaves the bucket.
- Collector 2026-11-18.3.

## 3.0.5 (18 November 2026)

- Search fallback, second pass. Live, the 3.0.4 fallback for "Optimizely security incident November 2026 malicious code supply chain attack" matched 1,672 entries and ranked generic supply chain stories first, because every word under the 3 percent line counted alike. The fallback now requires the rarest name in the query (a capitalised word: Optimizely, Bybit), or the rarest word when the query names none, and ranks entries that also carry the other distinctive words first: 114 Optimizely entries.
- Report breadth. A report subject of two or more words with fewer than 15 entries that carry every word ("Optimizely breach": 6) adds the entries that carry its name after them, so the evidence and the further-reporting list reach the subject's full coverage (114 entries). Live on 3.0.4, Google News links resolved through the article endpoint: four of five pages read where none had been.
- Collector 2026-11-18.2.

## 3.0.4 (18 November 2026)

- Postgres transfer. The Free plan allows 5 GB a month of data returned through the Neon proxy and suspends compute past it; on 18 November the project had used 2.97 GB with 13 days left. pg_stat_statements (now enabled) put the triage window first: two full reads of the 72-hour window an hour (the stored stories new titles join, then the published list), about 1.4 MB, and the hourly evaluation run read it again. The window now lives as a gzipped mirror in the bucket; a run reads only the rows labelled since, the verified rows and a count, and falls back to a full read every six hours, on a count mismatch, or when the mirror is missing. The fires job returned all 9,400 prior cells to judge novelty; it now returns only the prior cells today's detections touch. Search runs its four statements in one round trip.
- Search. A query of three or more words that no entry carries in full falls back to its distinctive words (those in at most 3 percent of the window's entries), all of them, then any of them, and the page says so. An agent query such as "Optimizely security incident November 2026 malicious code supply chain attack" had returned nothing.
- Reports. All five types ran on Optimizely after 3.0.3 (technical 127 s and 9 sources, brief 101 s and 7, executive 68 s and 19, summary 68 s and 6, practitioner 138 s and 15), but the summary's revision round added no citation although 108 platform entries from 102 publishers covered the subject. The revision now names the uncited sources from publishers the draft does not cite, and a report closes with "Further reporting in the collection": up to 15 entries that matched the subject search, one per uncited publisher, listed as coverage the model did not check fact by fact. Google News links are decoded to the publisher's URL (the id itself for older links, Google News's article endpoint for current ones) before the Bing title search, which had missed four of four links in one run.
- Collector 2026-11-18.1.

## 3.0.3 (17 November 2026)

- Report reliability. A technical deep-dive on Optimizely failed when three free models in turn ran past the 110-second deadline with a context swollen by full pages. The agent now keeps its working context under 90,000 characters (older tool results cut to their opening 1,200 characters, pages read to 7,000), gives a model that misses its deadline or is rate-limited one more try on half that context, writes the report without tools once two models have failed, reasons at low effort in tool rounds and medium effort for the writing, and allows 150 seconds a tool round, 240 for the writing and nine minutes in all. A failed report shows its error and a Retry button.
- Collector 2026-11-17.9.

## 3.0.2 (17 November 2026)

- Corroboration depth for agentic reports: a draft citing fewer than eight distinct sources (or all of them, when fewer were seen) goes back to the model once to corroborate each key fact from the listed sources; the revision is kept when it cites more. The first practitioner report (Optimizely, retail SOC direction) started at once and finished in 144 seconds but cited 4 sources.
- Collector 2026-11-17.8.

## 3.0.1 (17 November 2026)

- First production runs of 3.0: the sources job read 520 feeds in 150 seconds with none failing (19 healed: 17 through Google News, 2 through discovery) and stored 15,190 entries; the store held 21,835 entries from 1,891 publishers. A search for Optimizely returns 77 entries from 72 publishers. The first agentic report (an intelligence brief on the Optimizely script hijacking) took about three minutes on nvidia/nemotron-3-ultra-550b-a55b:free.
- Reports start the moment they are queued; the upload trigger and the scheduled job remain as fallbacks (the first report waited 11 minutes for them).
- The report agent resolves Google News links to the publisher's page before reading them, and names the publisher of every web result.
- TAXII 2.1 paths answer with the trailing slash the specification uses.
- Collector 2026-11-17.7.

## 3.0.0 (17 November 2026)

- Source network. 863 validated feeds replace the 44 news feeds and the 6-hourly blog reading: 417 research and CTI blogs, 60 security news outlets, 25 CERTs and agencies, 12 vulnerability sources, 198 regional and world news feeds, 14 think tanks, maritime, defense and community feeds, and 116 Google News query feeds (cyber topics in English and 28 other language and country editions, two queries a theater). The registry (`data/feeds.json`) merges a curated core with four open lists; `pipeline/feeds_build.py` validated all 2,048 candidates and kept those with an entry in the last 180 days. Feeds are read every 20 minutes, hourly or every four hours by volume, with conditional requests. A failing feed heals itself through its stored alternate, a feed found on the publisher's pages, or a Google News site: feed; 27 core outlets that refuse cloud requests (among them Dawn, Pakistan Today, The News International, the Associated Press of Pakistan, Addis Standard, The Reporter, Borkena, The EastAfrican, ReliefWeb, Cybernews, ISW and SC Media) are read that way, which restores Pakistani and Ethiopian press. A weekly workflow rebuilds, validates and ships the registry.
- Search. One search box on every page and a Search & reports page: full text over everything collected in 45 days (title and publisher summary), the advisories, and the platform's own judgments, evidence items, theaters, ATT&CK groups and warning indicators, with the machine-triage label on each hit, one row per story with its other carriers, a day histogram and filters. On 17 November the collector held 12 reports of the Optimizely script hijacking from 12 publishers within hours, which no page could surface; the search finds them.
- Agentic reports. From any search: an intelligence brief, executive summary, technical deep-dive, technical summary or practitioner report, with an optional direction of the reader's own. A free reasoning model on OpenRouter (chosen at run time from the free models with tools and a 200k-token or larger context, handing over to the next on failure) starts from the platform's collected reporting and corroborates it with tool calls the collector answers: platform search, web search (Bing News, Google News and DuckDuckGo free; Tavily, Brave or SearXNG when configured) and page reading. Every claim cites a numbered source the agent was given; the source list is built by the code. Reports have their own links, a library and Markdown download; limits per address and per day keep it free.
- Detection coverage by judgment (Defense page): each judgment's ATT&CK technique scope (its vector's techniques, the techniques of the ATT&CK groups it names, techniques it cites) against the SigmaHQ rule index, with stable and high-severity counts and the techniques without a Sigma rule.
- TAXII 2.1 read-only server at `/taxii2/`: key judgments, advisories and agentic reports as STIX 2.1, with added_after polling, paging and manifests.
- Triage capacity for the larger network: a 400-title pool and up to eight labelling requests a run.
- Collector 2026-11-17.6.

## 2.8.1 (17 November 2026)

- The four candidate outlets refused the collector too (Borkena answers a challenge page, The Reporter Ethiopia 304, The News International and the Associated Press of Pakistan 403) and leave the list, which holds 44 outlets that answer. The collector notes every outlet tried and refused so none is retried. Pakistani press comes from The Express Tribune; Ethiopian press has no feed that accepts cloud requests, so the Horn of Africa reads two Somali outlets and the international wires.
- Collector 2026-11-17.5.

## 2.8.0 (17 November 2026)

- One lead per story across hours. A title that is the same story as one already labelled in the 72-hour window takes that story's label and joins it, with no model request; hourly feeds carry a story for hours after its first title. Stories labelled in different runs merge in the triage document when they carry the same theater label and the titles share at least four words and 70 percent of the shorter title's words (the three Kyiv bridge strikes headlines of 17 November, from Deutsche Welle and France 24, now read as one lead with its other carriers).
- Ethiopian and Pakistani press: Addis Standard and Pakistan Today refused the collector (HTTP 403). Two candidates each now take their place, Borkena and The Reporter for Ethiopia, The News International and the Associated Press of Pakistan; the first run shows which answer, and those that refuse leave the list.
- Collector 2026-11-17.4.

## 2.7.2 (17 November 2026)

- Infra job: four runs between 08:40 and 10:12 UTC on 17 November failed with "ON CONFLICT DO UPDATE command cannot affect row a second time" when a feed listed one address in two spellings (IPv6 in upper and lower case reads as one inet). Both upserts now keep one row per key. Collector 2026-11-17.3.
- Four panels threw or misread on live data while every offline check passed, because list and record cells arrive from the runtime as JSON text: the Sources page's advisory table and machine triage card, and the Method page's STIX export. The triage card and the Theaters page read the evaluation record as text, so the site kept the model's labels and the theater leads hidden after the evaluation passed on 16 November. All now read cells through `TI.list` and `TI.obj`.
- The Site workflow gains a browser check on the production service's current answers (`test/save_live.mjs`), so page code that throws on real data shapes fails the check before it reaches the public site.
- Theaters page: the leads table takes the full page width. Sources page: the news table names each theater beside its id.

## 2.7.1 (17 November 2026)

- Theater news, first production run: 43 of 46 feeds answered with 959 titles of the last 72 hours. Three refused the collector and are replaced: ReliefWeb (HTTP 406) by UN News, The EastAfrican (404) by Addis Standard, which adds Ethiopian press to the Horn of Africa, and Dawn (403) by Pakistan Today, which keeps Pakistani press beside The Hindu for South Asia.
- Runbook: after a function deploy, a warm instance of the previous deployment can answer for a few minutes; confirm the version with a run that includes a job the previous version also has.
- Collector 2026-11-17.2.

## 2.7.0 (17 November 2026)

- Theater news. A new hourly collector job reads 46 news feeds for titles, links and publication times: both parties' press where a theater has two (Ukrinform and Meduza, the Jerusalem Post and Middle East Eye, Dawn and The Hindu, Yonhap and NK News, Radio Tamazuj and Dabanga), regional outlets for the theaters that international wires cover thinly (the Horn of Africa, Sudan, the Sahel, Central Asia, Afghanistan and Pakistan, the Balkans and NATO's eastern flank), and maritime and defense trade press. The Sources page lists each outlet, what it answered and its titles of the last 72 hours. The triage tier reads the titles with the blogs and advisories, taking each kind in turn so none crowds out the others.
- Leads by theater. The machine tier's evaluation passed on 16 November at 749 of 1,007 gold items (theater accuracy 0.924, vector accuracy 0.787, false vector rate 0.01), so the site now shows its theater and vector labels, and the Theaters page lists the selected theater's leads of relevance 2 or more with the outlets that also carried the story and the second model's verdict. The table hides itself whenever a prompt or model change sends the tier back to evaluation. The daily run starts each theater's review from these leads.
- Citation repair queue. `pipeline/citation_queue.py` orders the cited pages the citation check found gone, not carrying their item, or carrying it only in part behind a ranked judgment, and gives each its repair: the publisher's new address or an archived copy, the dated article for a page that changes after it is cited (live prices, daily bulletins, briefs), or the page that carries the claim. The daily run repairs up to five a run and never deletes an item to clear the queue. Items computed from a dataset ("Feed data") are reported as `derived` and leave the mismatch count.
- Monitoring that tracks the running code. Every job run records the collector version it ran under; the failure count that opens an alert counts failures under the running version only (all failures stay in `failed_24h_all`), so a fault a deploy has fixed stops raising an alert at the deploy. The alert workflow measures a job's silence from the health record's own time, so a record written before a late scheduled run no longer makes hourly jobs read as silent. These two rules account for the open alerts on lists, leak sites, link health and advisories.
- GreyNoise leaves the documented gaps. Its keyless lookup refused cloud egress on and off from 3 to 9 November and has passed all 341 checks since 10 November; a failing streak is now a finding like any other feed's. The key stays optional.
- Blogs: 23 CTI blogs whose feed address discovery missed (among them Proofpoint, Fortinet, NCSC UK, Google Cloud threat intelligence, ESET, Wiz and Volexity) now carry their feed address directly.
- Collector 2026-11-17.1.

## 2.6.0 (16 November 2026)

- Competing hypotheses rated across the evidence base: all 370 evidence rows of the seven ranked judgments now carry a rating against each stated alternative (ledger R-0032). Every judgment holds against its tested alternatives. Four alternatives are marked as ones little evidence bears on, which names where collection is thin: a US clearance of Hormuz by force (KJ-02), law-enforcement pressure cutting extortion (KJ-04), enforcement reducing North Korean placements (KJ-05) and eviction of the PRC actor from carriers (KJ-07).
- The model request cap follows the OpenRouter account. A credited account (1,000 free-model requests a day) gets a cap of 600, up to three labelling requests a run and up to eight evaluation batches a run; an account on the free tier keeps 45 and one.
- Ten more advisory feeds, each confirmed live: Sophos, GitLab, Chrome releases, Zero Day Initiative, JPCERT/CC, Japan Vulnerability Notes, CERT-Bund (BSI), CERT-FR alerts and advisories, NCSC-NL. Twenty-four in all. An entry a feed lists twice, or a page two feeds carry, is stored once (the first deploy of this release failed on a duplicate and the loader fell back to the previous bundle, as designed).
- Calibration by likelihood term on Method, and a print or save-as-PDF button on the Brief.

## 2.5.0 (16 November 2026)

- Labelling has first call on the day's model requests. The verifier and the evaluation spend only what is left above labelling's reserve for the remaining hours; on 16 November the shared budget ran out by 15:00 UTC and nine hourly runs labelled nothing.
- Actor ledger. Names the triage tier kept over 30 days, with stories, publishers and the latest headline, matched in the browser to MITRE ATT&CK groups by name or alias and to the ranked judgments that name them.
- Corroboration by judgment on Method: publishers and source categories behind each ranked judgment's supporting items, with a flag when support leans on one origin.
- Advisories as STIX 2.1 on Method: vulnerability objects by CVE, labelled when KEV lists them, and one report per advisory.
- Seven days in review on the Brief: level and trend moves, judgment and indicator changes, items added by theater, outcomes recorded and lead use.
- The validator warns for each ranked judgment whose evidence still lacks ratings against its alternatives, so the daily run sees the backlog.

## 2.4.0 (15 November 2026)

- KEV watchlist. Advisory CVEs that KEV does not list are ranked by a fixed weighted score over EPSS percentile, edge-device publisher, exploitation wording, publisher count and the vendor's share of KEV additions. First scores are kept and the ranking is scored against what KEV lists afterwards (NDCG and top-decile capture); the first figures appear after a week of tracking.
- Verifier. A second free-model request re-labels relevance 3 stories; disagreement lowers the story to 2. It can lower a label and never raise one.
- Competing hypotheses. Evidence rows can rate their item against each alternative a judgment states (`ach`), the validator checks the ratings, and Method publishes the matrix per ranked judgment. The daily run fills the ratings as it reviews each judgment.
- Lead watch tightened. Generic phrases ("Extortion Group", "North Korean", agency and vendor names) no longer count as actors, in the collector and in the watch; a relevance 3 lead that carries a ranked judgment's theater is raised.

## 2.3.0 (15 November 2026)

The machine tier in production, measured, and wired to the analyst run.

- Machine triage live on free models. Requests ask for low reasoning effort with a 12,000-token allowance after the first production run returned empty answers from reasoning models; an empty answer records its finish reason.
- Story clustering. New titles are grouped into stories (shared words, or a shared CVE identifier) before triage, one request covers up to 25 stories, and a story's label is stored for every publisher that carried it. The lead list shows one row per story with the other publishers.
- KEV marks on leads. CVE identifiers are read from the advisory feed and from the title, and matched to the KEV catalog the advisory job last read.
- Intraday lead watch. Twice an hour, without a model, one GitHub issue (`lead-watch`) stays open while a relevance 3 lead names a KEV CVE or an actor a ranked judgment names. The daily run opens those leads first. No level moves between analyst runs.
- Lead feedback (`leads.json`). The analyst run records what it did with every lead it opened: used, duplicate, rejected or wrong. Method publishes the tier's precision from that record.
- Triage evaluation on the schedule: one batch an hour at :19 until the 1,007 analyst-labelled items are scored.
- Six more advisory feeds, each confirmed live: Canadian Centre for Cyber Security, NCSC (UK) reports, MS-ISAC, Splunk, Tenable, AWS security bulletins. Fourteen in all.

## 2.2.0 (14 November 2026)

Proof for the citations, a wider collection surface, and a machine reading tier that runs through the day without spending the analyst model.

### Analytic integrity
- Citation verification. `pipeline/verify_citations.py` fetches every cited page without a model and classes the result: the item's stored excerpt found on the page, the title's figures and names found, a weak match, a mismatch, a page that needs a browser, a publisher that refuses automated requests, or a page that is gone. The Site workflow runs it on every build, keeps its state between runs, and rechecks each page every 45 days. Method publishes the result per item and in aggregate.
- Excerpts. From I-1126 each item carries `excerpt`, 60 to 400 characters copied from the fetched page, and `fetched_at`. The excerpt stays in the repository; the site publishes only whether one exists. A new item whose page is gone or whose excerpt is absent from the page fails the build.
- `main` is protected. The daily run opens a pull request, the `site` check validates, verifies citations and tests it, and only a passing check merges.
- Marking moved from TLP:AMBER to TLP:GREEN on the page, the STIX export and the judgments: the site surfaces public data through public interfaces. PAP:AMBER stays.

### Collection
- Vendor and CERT advisories (`psirt` job, every three hours): Fortinet, Palo Alto Networks, Cisco, SonicWall, Ivanti, Microsoft MSRC, CISA and CERT-EU, each from its own feed, with CVE identifiers extracted and cross-referenced with CISA KEV. Served at `/api/context?type=psirt` and shown on Sources.
- Machine triage (`triage` job, hourly): a free hosted model labels the titles the blogs and advisory jobs collected (relevance, vector, theater, actors) under closed lists and deterministic rule checks, inside a daily request budget. Output is a lead list marked "Machine triage, unreviewed" at `/api/context?type=triage`; the tier writes no judgment, ThreatCon or evidence item. It ships dark and makes no request until `OPENROUTER_API_KEY` is set in the collector's environment.
- Triage evaluation (`triageeval`, on demand): the tier's labels are scored against the analyst's own on the 1,007 evidence items (`lib/triage-gold.json`). The site hides the model's vector and theater labels until the full set clears the published thresholds.
- Probes: the Wikidata check accepts a ranged answer, blocklist.de is asked for one kilobyte, and the NGA broadcast-warning gap covers the HTTP 503 it now returns.
- `collector-deploy.yml` pins its actions to commit hashes.

### Fixes
- The collector test's GDELT fixture follows the clock. Pinned to 17 October, it left the 30-day recheck window on 14 November and would have failed every later deploy.
- The validate and verify steps of the Site workflow run under `pipefail`; `tee` had been masking a failing validator's exit code.

## 2.1.0 (13 November 2026)

A review of the whole platform (site, service, collector, pipeline, data, workflows, tracker and the scheduled reassessment) and the upgrade that came out of it. Findings and the backlog they opened are in the Notion page "KTI platform review, 13 November 2026".

### Analytic integrity
- Change log. `data/authored/history.json` records one event whenever a theater's ThreatCon level or trend, a judgment's title, likelihood, severity, status, rank or horizon, a warning indicator's state, or a vector's level or trend moves. The validator writes it and `--check` refuses a build whose tracked values differ from it. Backfilled from Git to 30 October 2026 by `pipeline/backfill_history.py` (151 baseline rows, 5 changes across runs R-0012 to R-0024).
- Judgment horizons. Every live judgment carries `horizon`, the date by which it is scored. A reassessment fails while a horizon has passed without an outcome and a new horizon.
- Forecast record. `data/authored/outcomes.json` holds one row per passed horizon with the outcome and the cited items behind it; the validator derives the Brier score. KJ-01 and KJ-02 were scored for their 3 November horizon (both held) and re-issued with new horizons; their titles no longer read "through the midterms" ten days after the midterms.
- Review cadence. `review_by` is derived from `last_reviewed` and the level (CRITICAL and HIGH 2 days, ELEVATED 4, GUARDED and NORMAL 7). A reassessment fails while a theater is past it, a ranked judgment has gone 7 days without review, or a requirement has gone 35.
- Currency rules fail the reassessment and print as warnings under `--check`, so an overdue review never blocks a feed deploy.
- More validator rules: item lane and date precision, no future publication date, a headline-only item at credibility 3 or lower, ICD-203 likelihood terms, judgment status, a 3,500-character cap on a theater's basis, and the remaining writing rules that a pattern can catch ("X is not Y. It is Z.", "x becomes y when z", negative-then-positive pairs, more than two em dashes in a field). Checks per run rose from about 48,000 to about 125,000.
- Data corrections: I-066 (a headline-only item) regraded from credibility 2 to 3; I-725 date precision normalised; the basis of T-RSY, T-HRM, T-UKR and T-SDN cut from as much as 6,958 characters of accumulated daily entries to the standing rationale plus the newest developments.

### Site
- Brief leads with "Since the last reassessment": the latest run's logged changes, the net change in cited items, the last ThreatCon level change on record and the changes of the previous 14 days.
- Judgment cards show the date each is scored by. Theater detail shows when the current level and trend took effect.
- Method gains the forecast record (outcomes, Brier score, open horizons) and the full change log.
- `/feed.json`: a JSON Feed with one entry per run and the changes it logged.
- Security headers on every response: a content security policy that keeps scripts, styles, fonts and connections to this origin and forbids framing, `nosniff`, a referrer policy, a permissions policy and a cross-origin opener policy.
- Tabs follow the WAI-ARIA pattern (one tab stop, arrow keys, Home and End, `aria-controls`). In-page links open the page they point into. A print stylesheet turns the open page into a handout.
- The STIX export carries each judgment's horizon.

### Operations
- The operator host (`threat-feeds-skilfoys-projects.vercel.app`) stopped following production deploys on 2 November and served that day's build and service code for eleven days; runs R-0013 to R-0024 read it and recorded stale catalog versions in the ledger. The workflow now points it at every deployment, and the runbook reads site data from the public host.
- The smoke test fails when the public site serves a commit other than the one just deployed, when the security headers are missing, or when the change feed is absent.
- "Reassessment watch" (`.github/workflows/reassessment-watch.yml`): twice a day, without a model, one issue stays open while the ledger holds no daily reassessment from the last 25 hours or a review is overdue.
- "Collector alerts" no longer raises the maritime job for failing with "no source answered": all four of its sources are documented gaps, and that failure restates them. A silent job or another error still raises it.
- Site and watch workflows pin their actions to commit hashes. `collector-deploy.yml` is left on tags until the next collector change, because editing it starts a run that waits at the production approval gate.

### Not changed
- The collector (`neon/`), the service routes (`api/`, `lib/`), verticals, controls, assets, exposure, OSINT toolkit, indicator rules and chokepoints.
- The TLP:AMBER and PAP:AMBER markings, by the owner's standing choice.
