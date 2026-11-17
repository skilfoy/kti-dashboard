# Changelog

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
