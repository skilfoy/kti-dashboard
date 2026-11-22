# Open-source disclosure watch

Added in 3.14.0. Collector job `osswatch` (`neon/parts/37r-osswatch.mjs`), every three hours at :04 UTC from 02:04.
Published as the document `osswatch` (`/api/context?type=osswatch`, dataset `live_osswatch`) and shown on the
Vulnerabilities page in the card "Open-source disclosures ahead of the CVE record".

## What it answers

Which flaws in widely deployed open-source projects have been disclosed but are not yet described by a complete CVE
record, and by how many days did disclosure lead the record? Advisory databases, fuzzing services, mailing lists and
bug-bounty platforms often publish first; the CVE record, its CVSS, CWE and affected versions follow later or never.

## Sources

| Source | What is read | Terms kept to |
| --- | --- | --- |
| OSV.dev export (`osv-vulnerabilities.storage.googleapis.com`) | The first 512 KB of `modified_id.csv` for npm, PyPI, Maven, Go, crates.io, NuGet, RubyGems, Packagist, Hex, Pub, GitHub Actions, OSS-Fuzz, Hackage, CRAN and SwiftURL; then each record not read at its current modification time (up to 900 a run). Malicious-package reports (`MAL-`) are skipped. | CC BY 4.0 with each database's own terms. Title, link, dates, aliases, CWE, severity |
| oss-security (`seclists.org/rss/oss-sec.rss`) | Root posts (replies are left out), with the CVE ids printed in the title | Titles and links only |
| HackerOne Hacktivity (`/v1/hackers/hacktivity`) | Disclosed reports, newest first, until the window or a page already held; the watch keeps reports to open-source programs (`H1_OSS`, every `ibb` handle, or a program named like an OSS-Fuzz project); every program's reports count toward the weakness table | Title, link, dates, CWE, severity, CVE ids, program. No report text, no AI summary |
| CVE Services (`cveawg.mitre.org`) | `/api/cve/{id}` for a disclosure's first CVE id; on 404, `/api/cve-id/{id}` for its state | CVE Terms of Use |
| ecosyste.ms (`packages.ecosyste.ms`) | One package record per package, cached a week: critical flag, usage ranking, dependent packages and repositories | CC BY-SA 4.0 |
| OSS-Fuzz projects (`google/oss-fuzz`, `projects/`) | Directory names, daily, through the GitHub trees API | Apache-2.0 repository; names only |

## Method

- **Window.** Disclosures published in the last 30 days; rows are kept 45 days and OSV records' read marks 60.
- **Widely deployed** (`reach`). A package is `wide` when ecosyste.ms marks it critical or ranks it in the top 1% of its
  registry by usage, `limited` otherwise (left out of the document), and `unmeasured` until its lookup runs or when
  ecosyste.ms does not index its registry (Drupal's Packagist, SwiftURL). An OSS-Fuzz report is `wide`. An oss-security
  post or a HackerOne report is `wide` when it names an OSS-Fuzz project (whole words; names that are also common words
  in post titles are skipped), `unmeasured` otherwise. The page shows `wide` rows by default.
- **CVE record** (`cve_state`). `none`: the disclosure carries no CVE id. `reserved`: the id exists with no record.
  `incomplete`: the record lacks CVSS, a CWE or affected versions (listed in `cve_gaps`). `complete`. `rejected`.
  `unknown`: CVE Services knows no such id. An incomplete or unchecked record is asked about again every six hours (up
  to 250 lookups a run); `cve_complete_seen` is the first run that found it complete.
- **Lead.** Days from the disclosure to the CVE record's publication. Negative when the CVE came first, as when GitHub
  reviews an advisory for an older CVE. The document splits disclosures with a record into those whose record came a
  day or more later (`lead_n`, with `median_lead_days` over them), within a day (`same_day`) and before (`cve_first`).
- **Ahead.** True when the disclosure has no complete CVE record, or its record was published at least a day later. An
  oss-security post whose title names no CVE id is not judged, because the post body may name one.
- **Bug-bounty weaknesses.** Counts of disclosed Hacktivity reports by weakness over the window, all programs and
  open-source programs apart, with the CWE id from the API's weakness list (with a token) or a built-in table. The base
  rates card shows them beside each CWE.

## Keys

None needed. `HACKERONE_API_USERNAME` and `HACKERONE_API_TOKEN` (a personal hacker API token) give documented access at
600 reads a minute, 100 reports a page and the weakness list; without them Hacktivity is read anonymously (50 a page,
built-in weakness table). `GITHUB_TOKEN` (a fine-grained token with no permissions) lifts the GitHub API limit for the
OSS-Fuzz list. All three live only in the Neon function's environment (docs/secrets-and-keys.md).

## First live runs (22 November 2026, from the build workspace)

Every source answered. The first three runs worked through the 30-day backlog of OSV records, 900 at a time, in 13 to 17
seconds each; the fourth found nothing new and took 1.5 seconds. Then: 653 disclosures listed, 524 in widely deployed
projects, 86 of them ahead of a complete record. Of the 470 with a CVE record, 33 had it published a day or more after the
disclosure (median 9.3 days), 183 within a day, and 254 after the CVE (mostly GitHub reviews of older CVEs).

## Checks

`node test/osswatch_test.mjs .` (fixture answers for every source, PGlite) runs in the offline suite.
