# Sigma detection drafts (3.8.0)

The `sigma` job (`neon/parts/37o-sigma.mjs`) drafts Sigma rules for the threats the collection reports now. A free hosted model writes each draft from the publishers' own pages. Deterministic checks then decide whether it is kept. The output is a lead list for a detection engineer. Nothing here is tested against telemetry, and no draft should be deployed as it stands.

## When it runs

- In the :34 slot, after `entities` and `watch`, at most one subject an hour and six a day (`SIGMA.DAILY`, kv `sigma:budget`). Every model request also counts against the reports' daily allowance (kv `report:budget`), because the two share the OpenRouter key.
- A subject is eligible when it meets all of these:
  - it is a malware family, tool, actor, campaign, extortion brand or CVE;
  - three or more publishers named it in 14 days, with at least one entry in the `research` category;
  - it has not been drafted in 21 days, or in 3 days after a failed attempt (`no_source` or `error`).
- Subjects with an alert in the last 7 days go first, then those with the most research entries and publishers.
- The model is the reports' free model list (`reportModels()`). A model whose answer cannot be read as JSON passes the subject to the next model.

## What the model sees

- Up to five of the subject's entry pages, one per publisher, research entries first. The pages come from the report agent's fetcher (`fetchPage`, which resolves Google News links). A page counts only when its text names the subject or one of its aliases.
- The model gets 12,000 characters of each page, within a 48,000-character pack. It never searches the web.
- The prompt asks for JSON only. Values must be copied exactly as the sources print them, and each rule needs a threat-specific value. When the reporting names no concrete artefact, the model answers with no rules and gives a reason.

## The checks

`checkRule` accepts a rule only when every check passes:

| Check | Rule |
|---|---|
| Log source | A category from the Sigma taxonomy with its product. For example, `process_creation` takes windows, linux or macos, and `proxy`, `webserver` and `dns` take no product. Alternatively, `windows` with service `security` or `system`. |
| Fields | The taxonomy's field names for that log source. Accepted modifiers are `contains`, `startswith`, `endswith`, `all` and `windash`. Regular expressions, CIDR matching and keyword lists are refused. |
| Condition | Parsed (`and`, `or`, `not`, parentheses, `1 of`/`all of` a pattern or `them`). It names only defined selections and uses every one. It must be false when no selection matches, which refuses a bare `not filter`. |
| Grounding | Every detection value is checked against the fetched pages. The comparison is lower-case, refanged, split into wildcard fragments, and works on whitespace and JSON-escaped backslashes. A path may also join two printed pieces at one separator, such as a registry key and a value name reported apart. Windows event ids are exempt. In selections named `filter*`, standard install prefixes are also accepted (`C:\Windows\System32\`, `C:\Program Files\` and the like). |
| Specificity | At least one grounded value of 8 characters or more that is not a common system binary, interpreter or path. |
| Tags | At least one ATT&CK technique id. It must exist in ATT&CK v20: the collector reads the Defense page's technique table (`/data/defense_techniques.json`) and keeps a copy in the bucket at `ref/attack_techniques.json.gz`. Tactic tags come from the same table. Other tags are dropped. |
| Level | `low`, `medium` or `high`. An unreviewed draft is never `critical`. |
| Evidence | The numbers of the sources the rule rests on. These become its `references`. |

A failing rule goes back to the model once, with the checker's failures. Whatever still fails is stored as rejected, with the reasons, and shown on the page.

## The YAML

The collector writes the YAML; the model never does:

- `status: experimental`;
- a deterministic UUID from the subject, log source and detection;
- an author line naming the model and saying "unreviewed";
- the cited pages as references;
- the `detection.emerging-threats` tag.

The offline test parses every draft it produces with pySigma 2.1.0 and runs pySigma's core validators. Only the validators that download ATT&CK or D3FEND are skipped.

## Where it shows

- Table `ti.sigma`: one row per attempt, with the outcome (`draft`, `rejected`, `none`, `no_source` or `error`), the rules with their checks, the pages read (address and title, never their text) and the model calls. Rows are kept 365 days.
- Document `sigma` (`/api/context?type=sigma`, dataset `live_sigma`). The Defense page's "Sigma drafts from current reporting" card reads it. A technique with no public Sigma rule is marked as a gap.
- `/api/sigma` returns the attempts and rules as JSON. `?format=yaml` returns every accepted draft as one multi-document file, `?id=` returns one draft, and `?subject=` filters by entity.

## Limits

- Grounding proves that a value was printed in a cited page. It does not prove that the value is malicious, current or seen in the reader's environment.
- Specificity removes the emptiest rules, but a rule can still match benign software that shares a file name.
- One subject an hour on free models is a slow cadence. A busy week produces a backlog, and the subjects that publishers name most are drafted first.
