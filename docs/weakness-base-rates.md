# Weakness base rates by product family

Added in 3.14.0. Built by `pipeline/build_baserates.py` in the site build, after `build_data.py`, from every CVE List V5
record. Shown on the Vulnerabilities page in the card "Weakness base rates by product family" and in the Base rate column
of the KEV and pre-KEV early-warning tables.

## What it answers

How often has a given weakness (CWE), in a given kind of product, reached exploitation? For a firewall or VPN
authentication bypass the answer is very different from a SQL injection in a student PHP project, and the early-warning
table is easier to order with that prior beside each CVE. The rate describes past CVEs of the same kind. It makes no
forecast for any single CVE and sets no level or judgment.

## Inputs

| Input | Source | Fetched by |
| --- | --- | --- |
| Every CVE record (state, publication date, CNA, affected vendor and product, CWE) | CVE List V5 daily archive: release `cve_<day>_0000Z` of CVEProject/cvelistV5, asset `<day-1>_all_CVEs_at_midnight.zip.zip` (about 670 MB, 430,000 records in November 2026) | `pipeline/fetch_cvelist.py` |
| Exploitation, weaponization and PoC signals for every CVE | t0sche/cvss-bt (`cvss-bt.csv`: CISA KEV, VulnCheck KEV, Metasploit, Nuclei, Exploit-DB, GitHub PoC) | `pipeline/fetch.py` |
| CISA KEV catalog | cisagov/kev-data | `pipeline/fetch.py` |
| The rows to annotate | `kev.json` and `early_warning.json` from `build_data.py` | the same build |

## Method

- **Window.** CVEs published in the 36 months that end 90 days before the build, so every CVE counted has had at least
  90 days for exploitation evidence to appear. CVE List V5 records carry a CWE and a vendor for most CVEs only from 2023
  on (60% of 2023 records carry both, 85% of 2026 records), so the window does not reach further back.
- **Product family.** `pipeline/families.py`, one deterministic taxonomy for every vulnerability row on the site. The
  five edge-device classes of the Edge-device lens come first (unchanged); then single-family CNAs (Wordfence, Patchstack
  and WPScan for WordPress, Chrome, the Linux kernel CNA, Jenkins, GitLab, Android); then patterns over the record's
  vendor and product (the title and description when the record names neither); then CNAs that mostly assign for one
  family; then a package registry named in the record. A CVE nothing matches is Unclassified: it counts in All families
  only. In November 2026, 82% of window CVEs and 92.5% of KEV entries are classified. The families table on the page
  shows how each family's CVEs were placed.
- **CWE.** The CNA's CWE identifiers, else CISA's ADP ones. A CVE listing two CWEs counts in both cells, so a family's
  CWE shares can add up to more than 100%.
- **Outcomes.** Exploited: CISA KEV or VulnCheck KEV lists the CVE. Weaponized: a Metasploit module or a Nuclei
  template exists. PoC public: Exploit-DB or a GitHub PoC repository (PoC-in-GitHub). A CVE counts once per outcome.
- **Rate and interval.** Exploited CVEs over CVEs in the cell, with a Wilson 95% interval. Lift is the cell's rate over
  its family's rate (exploited CVEs over CWE-known CVEs in the family).
- **Cells kept.** Cells with fewer than 15 CVEs are left out of `weakness_rates`; cells under 30 are marked `small` and
  hidden on the page unless asked for.
- **Per CVE.** Each KEV and early-warning CVE takes its product family (KEV rows from CISA's vendor, product and name;
  early-warning rows from the record) and its first listed CWE (the record's, else the KEV entry's). Its base is the
  family's cell for that CWE when the cell holds at least 30 CVEs, else the same CWE across all families when that holds
  30, else none. The tooltip says which.

## Datasets

| Dataset | Rows |
| --- | --- |
| `weakness_rates` | one per family and CWE (and All families and CWE): CVEs, share, exploited, rate, interval, lift, weaponized and PoC rates, rank in family |
| `weakness_families` | one per family: CVEs, CWE coverage, exploitation, weaponization and PoC rates, family rate, top three CWEs, how its CVEs were placed, window, CVE List V5 tag |
| `weakness_cve` | one per KEV and early-warning CVE: family, first CWE, how many more it lists, base scope, base CVEs, rate, interval, lift |

## What it found (22 November 2026)

153,492 CVEs in the window, 88% with a CWE, 1.5% exploited. Network edge: 3.4% exploited, with authentication bypass by
an alternate path (CWE-288) at 33% of 42 CVEs, deserialization (CWE-502) at 19% of 36 and missing authentication
(CWE-306) at 13% of 99. Small web applications: 0.07% of 5,960. Operating systems: 41% of records carry a CWE, the
lowest coverage of any family, because the Linux kernel CNA's records mostly omit one.

## Checks

`python3 -I pipeline/families.py --self-test` and `python3 -I pipeline/build_baserates.py --self-test` (a synthetic
archive) run in the offline suite (`node test/run_all.mjs`).
