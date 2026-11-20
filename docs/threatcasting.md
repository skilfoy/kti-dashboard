# Threatcasting: futures and signposts (3.9.0)

The `foresight` job (`neon/parts/37p-foresight.mjs`) gives each theater at ThreatCon 4 or above three futures over six months. It links each future to the theater's warning indicators as signposts. The watch W-4B alerts when a signpost indicator changes state. This answers the advancement plan's B69 and G45 work items with machine drafts. It does not replace an analyst-run threatcasting workshop (B68).

## What a future holds

The three futures follow the three paths in Suryavanshi, *Corporate Intelligence for Risk Management*, ch10:

- **escalation:** the accelerating path;
- **continuation:** the gradual path;
- **de-escalation:** the constrained path.

Each future is written in Vanatta and Johnson's threatcasting frame (2018). It has:
- a person, given as a role and never a named individual;
- a place;
- the activity the person is doing when the threat lands;
- the adversary's view: what they want and why now;
- the enabling conditions;
- the effects.

Each future is then backcast as three to six milestones, from the horizon back to now. It also carries two to five preparedness actions that a reader in the sector could take now, and it cites the theater's items it builds on.

Every future names its signposts:
- **Existing indicators:** indicator ids of that theater, each with the state the future expects (`present` or `absent`).
- **Proposed indicators:** up to three that the list lacks. A proposal is never added to `theater_indicators` or `indicator_rules`; those stay analyst-owned.

## When it runs

- The job runs in the :04 slot, drafts one theater at most per run, and is capped at eight sets a day (kv `foresight:budget`). It uses the reports' free model list, and each request also counts against `report:budget`.
- A theater is due in this order:
  1. it has no accepted set;
  2. its threatcon, label, trend or any indicator state changed since its accepted set, provided that set is a day old or more;
  3. its set is older than 7 days.
- A rejected or failed attempt waits 6 hours before the next try. The theater keeps its last accepted set meanwhile.
- The inputs are the site's own `/data/theaters.json`, `/data/theater_indicators.json` and `/data/items.json`. A copy of each is kept in the bucket under `ref/` for when the site does not answer.

## The checks

`checkSet` keeps a set only when all of these hold:

- There are three futures, one of each kind, with distinct names. Each has a narrative of 120 characters or more and a complete threatcast.
- Every signpost is an indicator of that theater.
  - An escalation future expects escalation indicators present and de-escalation indicators absent. A de-escalation future expects the reverse.
  - The escalation and de-escalation futures never expect the same state of the same indicator.
- Each future has three or more signposts in all, one or more of them an existing indicator.
- Each future has three to six backcast milestones and two or more preparedness actions.
- Each future cites one or more of the items the model was given, and nothing else.
- No future uses the first person, addresses the reader's own organisation or client, or carries a probability or percentage. Futures are not forecasts.

A failing set goes back to the model once, with the failures. A set that still fails is stored as rejected, with the reasons.

## The reading

`readSet` scores each future by the share of its existing-indicator signposts that the analyst's current indicator states meet:
- An expected `present` is met by Observed or Confirmed, and half met by Emerging.
- An expected `absent` is met by Not observed, and half met by Emerging.

A future leads only when two or more of its signposts are met and its score is 0.2 or more above the next future's. Otherwise the indicators do not separate the futures. Proposed indicators are not measured and not counted.

The Theaters page also shows, beside each signpost, the measured proposal from the warning rules whenever one is live. The reading is a count of the analyst's own states. It is never a forecast, and a match never confirms a future.

## The signpost watch (W-4B)

The `watch` job compares every indicator's authored state with the state recorded at its last run (kv `signpost:states`). When an indicator named as a signpost changes state, it opens an alert. The alert names the indicator, the change, its item, and the futures whose signposts the new state now meets.

The watch reads nothing until a future exists. Its first run after that records the states and opens nothing. The subject is `indicator:<id>:<state>`, so a further change opens a further alert.

## Where it shows

- Table `ti.foresight`: one row per attempt. Accepted sets are kept; other attempts are kept 365 days.
- Document `foresight`:
  - available at `/api/context?type=foresight` (dataset `live_foresight`) and at `/api/foresight?theater=`;
  - shown on the Theaters page in the "Futures and signposts" card for the selected theater;
  - carries the signpost index the watch reads.

## Limits

- The futures are only as good as the theater's authored assessment and items. The model cannot see beyond them, and the checks test structure and grounding in the theater's indicators. They do not test analytic quality.
- The reading follows the authored indicator states, which the daily reassessment maintains. A measured change shows on the page as a proposal until the analyst applies it.
- Six months is the only horizon so far. The plan's 18-month and longer horizons remain open.
