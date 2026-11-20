/* Loaders for the live threat-feeds datasets. Each is a same-origin query to the threat-feeds service under /api;
   the loader unwraps the runtime's fetch envelope {success,status,text}, decodes the
   packed and compact wire formats (tfwire.js) and returns the rows the endpoint produced. These refresh in-browser
   via the Refresh button and the interval timer. */
(() => {
  // Unwrap web_fetch_vercel_url's answer to the endpoint's JSON body.
  function raw(answer) {
    let env = answer;
    if (typeof env === 'string') { try { env = JSON.parse(env); } catch { return null; } }
    if (env && typeof env.text === 'string') { try { return JSON.parse(env.text); } catch { return null; } }
    if (env && env.body) return env.body;
    return env;
  }
  const body = (answer) => { const b = raw(answer); return b && window.TI_WIRE ? window.TI_WIRE.unpack(b) : b; };
  function loader(id, desc) {
    dash.loader(id, {
      description: desc,
      fn: ({ answer }) => {
        const b = body(answer);
        if (!b) throw new Error('threat-feeds returned a response this loader could not parse');
        if (b.error) throw new Error('threat-feeds: ' + b.error + (b.status ? ' (upstream ' + b.status + ')' : ''));
        // Columns are the union of every row's keys: rows a collector has not finished enriching lack the later keys.
        if (Array.isArray(b.rows)) return { data: b.rows, columns: [...new Set(b.rows.flatMap((r) => (r && typeof r === 'object' ? Object.keys(r) : [])))], meta: metaOf(b) };
        return { data: [b], columns: Object.keys(b), meta: metaOf(b) };
      },
    });
  }
  function metaOf(b) {
    const m = [];
    if (b.source) m.push({ label: 'Source', value: String(b.source) });
    if (b.generated) m.push({ label: 'Fetched', value: String(b.generated) });
    if (b.count != null) m.push({ label: 'Rows', value: String(b.count) });
    if (b.catalogVersion) m.push({ label: 'Catalog', value: String(b.catalogVersion) });
    return m;
  }
  loader('live_ransomware', 'Most recent ransomware/extortion leak-site claims from ransomware.live, via the threat-feeds proxy.');
  loader('live_epss', "FIRST EPSS highest-scoring CVEs today, via the threat-feeds proxy.");
  loader('live_threatfox', 'Most recent abuse.ch ThreatFox indicators of compromise, via the threat-feeds proxy.');
  // Press-reported attacks: one row per report with the victim, the settled country and its basis, the article and
  // any leak-site match. The threat-feeds service settles ransomware.live's free-text country codes (35-cyber.mjs).
  // The candidate countries of an unplaced row come as a list; the row keeps them as comma-separated ISO codes, since
  // the dashboard stores a list cell as its JSON text.
  dash.loader('live_cyberattacks', {
    description: 'Cyberattacks disclosed in the press, collected by ransomware.live, with the victim country settled by threat-feeds, via the threat-feeds proxy.',
    fn: ({ answer }) => {
      const b = body(answer);
      if (!b) throw new Error('threat-feeds returned a response this loader could not parse');
      if (b.error) throw new Error('threat-feeds: ' + b.error + (b.status ? ' (upstream ' + b.status + ')' : ''));
      const rows = (b.rows || []).map((r) => (Array.isArray(r.cc_candidates) ? { ...r, cc_candidates: r.cc_candidates.join(',') } : r));
      return { data: rows, columns: rows.length ? Object.keys(rows[0]) : [], meta: metaOf(b) };
    },
  });
  // Context feeds for the theater assessments (neon/parts/36-context.mjs, refreshed hourly by the collector).
  loader('live_lanes', "Lanes relationship temperatures per country pair (lanes.news open data, CC BY 4.0, derived from GDELT) with 7-day means and each pair's latest daily page, via threat-feeds /api/context.");
  loader('live_ofac', "OFAC Recent Actions, the two newest listing pages, with the programs, action types and theaters read from OFAC's titles, via threat-feeds /api/context.");

  // GDELT armed-conflict events: rows of mixed kind (cell, country, base, event) plus a header row (kind "meta")
  // carrying the window so the page can label hours and compute the anomaly ratio.
  dash.loader('live_gdelt', {
    description: 'Armed-conflict events from GDELT 2.0 15-minute exports over the last 24 hours, with a 48-hour baseline, via the threat-feeds proxy.',
    fn: ({ answer }) => {
      const b = body(answer);
      if (!b) throw new Error('threat-feeds returned a response this loader could not parse');
      if (b.error) throw new Error('threat-feeds: ' + b.error);
      const header = { kind: 'meta', latest: b.latest, hours: b.hours, baseline: b.baseline, actors: b.actors, quads: b.quads,
        events_kept: b.events_kept, files_ok: b.files_ok, files_requested: b.files_requested, served_from: b.served_from || 'live', base30_days: b.base30_days || 0,
        generated: b.generated };
      const rows = [header, ...(b.rows || [])];
      return { data: rows, columns: rows.length ? Object.keys(rows[0]) : [], meta: metaOf(b) };
    },
  });


  // Health is a record, not rows. Shape it into rows by kind: "upstream" (what the proxy reaches right now), "feed"
  // (the collector's 24-hour and 7-day uptime per upstream, checked every 30 minutes), "job" (collector runs) and one
  // "meta" row with DShield Infocon and check times.
  dash.loader('live_health', {
    description: 'Live reachability of each upstream feed, plus the collector\'s uptime record and job runs, reported by the threat-feeds /api/health endpoint.',
    fn: ({ answer }) => {
      const b = body(answer);
      if (!b || typeof b !== 'object') throw new Error('health response unparseable');
      const up = b.upstreams || {};
      const ttlLabel = (t) => (t == null ? '' : t < 60 ? t + ' s' : t < 3600 ? Math.round(t / 60) + ' min' : Math.round(t / 3600) + ' h');
      const rows = Object.entries(up).map(([feed, v]) => ({ kind: 'upstream', feed, ok: v.ok ? 'Up' : 'Down', status: v.status ?? '', ms: v.ms ?? null, cache: ttlLabel(v.ttl), note: v.error || '' }));
      const c = b.collector || {};
      // A documented gap (state known_gap, collector 2026-11-02.1 on) reads "Known gap" rather than "Down".
      for (const f of c.feeds || []) rows.push({ kind: 'feed', feed: f.feed, ok: f.state === 'known_gap' ? 'Known gap' : f.ok === true ? 'Up' : f.ok === false ? 'Down' : '', status: f.status ?? '', ms: f.ms ?? null, note: f.gap || '',
        uptime_24h: f.uptime_24h, uptime_7d: f.uptime_7d, p50_ms: f.p50_ms, failing_streak: f.failing_streak || 0, last_ok: f.last_ok || '', last_fail: f.last_fail || '' });
      for (const j of c.jobs || []) rows.push({ kind: 'job', feed: 'job:' + j.job, job: j.job, ok: j.ok ? 'Up' : 'Down', last_run: j.last_run || '', ms: j.ms ?? null, runs_24h: j.runs_24h || 0, failed_24h: j.failed_24h || 0, note: j.error || '' });
      // Each feed's latest snapshot size against its 30-day median, from the collector's volume baseline (B5).
      for (const v of c.volume || []) rows.push({ kind: 'volume', feed: v.feed, n: v.n ?? null, at: v.at || '', median_30d: v.median_30d ?? null, ratio: v.ratio ?? null, runs: v.runs ?? null, baseline_days: v.baseline_days ?? 0, flag: v.flag || '' });
      rows.push({ kind: 'meta', feed: 'collector', infocon: c.infocon || '', checked_at: c.checked_at || '', collector: c.ok ? 'Up' : 'Down', note: c.ok ? '' : String(c.reason || '') });
      return { data: rows, columns: ['kind', 'feed', 'ok', 'status', 'ms', 'cache', 'note'], meta: [{ label: 'Checked', value: String(b.at || '') }] };
    },
  });

  // Reported hostile infrastructure for the map: compact nodes decoded to one row per host, plus a "meta" row, one
  // "layer" row per feed (listed, mapped, new in 24 hours, reachability) and the collector's family, country and
  // 30-day trend rows.
  dash.loader('live_threatmap', {
    description: 'Reported malicious infrastructure (Feodo Tracker C2, ThreatFox ip:port, DShield sources, URLhaus hosts) placed by IP geolocation, from the threat-feeds collector.',
    fn: ({ answer }) => {
      const b = body(answer);
      if (!b) throw new Error('threat-feeds returned a response this loader could not parse');
      if (b.error) throw new Error('threat-feeds: ' + b.error + (b.detail ? ' (' + b.detail + ')' : ''));
      const nodes = window.TI_WIRE.threatmapNodes(b) || (b.rows || []).filter((r) => r.kind === 'node');
      const layers = Object.entries(b.layers || {}).map(([layer, v]) => ({ kind: 'layer', layer, name: v.name, url: v.url, ok: v.ok, status: v.status, listed: v.listed, nodes: v.nodes, geolocated: v.geolocated, new_24h: v.new_24h, drawn: v.drawn, gated: !!v.gated, note: v.note || '' }));
      const meta = { kind: 'meta', generated: b.generated, served_from: b.served_from || '', age_min: b.age_min ?? null, stale: !!b.stale, nodes: Array.isArray(b.nodes) ? b.nodes.length : b.nodes ?? nodes.length, geolocated: b.geolocated ?? nodes.length,
        geo_pending: (b.geo && b.geo.pending) || 0, note: b.note || b.live_error || '',
        // How "new in 24 hours" was judged: source listing times only until the collector has watched for a day.
        new_basis: b.new_basis || (b.served_from === 'live' ? 'source' : ''), observing_since: b.observing_since || '',
        // Admiralty credibility of the mapped hosts (counts by grade) and the incident taxonomy the nodes carry.
        credibility: b.credibility ? JSON.stringify(b.credibility) : '', taxonomy: b.taxonomy || '' };
      const rest = (b.rows || []).filter((r) => r.kind !== 'node');
      const rows = [meta, ...layers, ...nodes, ...rest];
      return { data: rows, columns: ['kind', 'layer', 'ip', 'port', 'lat', 'lon', 'cc', 'family', 'first_seen', 'ref'], meta: metaOf(b) };
    },
  });

  // IODA country-level internet disruption events over 7 days, kept by the collector.
  dash.loader('live_outages', {
    description: 'IODA (Georgia Tech) country-level internet outage events over 7 days, from the threat-feeds collector.',
    fn: ({ answer }) => {
      const b = body(answer);
      if (!b) throw new Error('threat-feeds returned a response this loader could not parse');
      if (b.error) throw new Error('threat-feeds: ' + b.error);
      const rows = (b.rows || []).map((r) => ({ kind: 'outage', cc: r.cc, name: r.name || '', start_at: r.start_at, end_at: r.end_at || '', level: r.level || '', score: r.score ?? null,
        datasource: r.datasource || '', ongoing: !!r.ongoing }));
      return { data: rows, columns: ['kind', 'cc', 'name', 'start_at', 'end_at', 'level', 'score', 'datasource', 'ongoing'], meta: metaOf(b) };
    },
  });

  // Reported state-nexus targeting from the MISP galaxy threat-actor cluster with CFR tracker fields.
  dash.loader('live_actors', {
    description: 'MISP galaxy threat-actor cluster: attributed origin and CFR Cyber Operations Tracker suspected victims, as actor, origin-victim pair and origin rows.',
    fn: ({ answer }) => {
      const b = body(answer);
      if (!b) throw new Error('threat-feeds returned a response this loader could not parse');
      if (b.error) throw new Error('threat-feeds: ' + b.error);
      const rows = (b.rows || []).map((r) => (r.kind === 'actor' ? { ...r, victims: (r.victims || []).join(','), targets: (r.targets || []).join(', '), other: (r.other || []).join(', '), aka: (r.aka || []).join(', ') }
        : r.kind === 'pair' ? { ...r, actors: (r.actors || []).join(', ') } : r));
      return { data: rows, columns: ['kind', 'name', 'origin', 'victims', 'confidence', 'o', 't', 'n'], meta: [...metaOf(b), { label: 'Cluster version', value: String(b.cluster_version || '') }] };
    },
  });

  // ---- Collector documents: threat-feeds /api/context store types and /api/enrich ----
  // The dashboard keeps every cell as text, a number or a boolean, so a list or record in these documents leaves the
  // loader as its JSON text and the page reads it back with TI.list and TI.obj. Each loader puts the document's own
  // fields (source, terms, method, counts, window, freshness) in one "meta" row ahead of its rows.
  const cellOf = (v) => (v !== null && typeof v === 'object' ? JSON.stringify(v) : v);
  const flat = (o) => { const r = {}; for (const [k, v] of Object.entries(o || {})) if (v !== undefined) r[k] = cellOf(v); return r; };
  const headOf = (b, skip = []) => {
    const hd = { kind: 'meta' };
    for (const [k, v] of Object.entries(b)) if (!['rows', 'enc', 'data', 'bytes', ...skip].includes(k) && v !== undefined) hd[k] = cellOf(v);
    return hd;
  };
  function docLoader(id, desc, shape) {
    dash.loader(id, {
      description: desc,
      fn: ({ answer }) => {
        const b = body(answer);
        if (!b) throw new Error('threat-feeds returned a response this loader could not parse');
        if (b.error) throw new Error('threat-feeds: ' + b.error + (b.note ? ' (' + b.note + ')' : '') + (b.store ? ' [collector store: ' + b.store + ']' : ''));
        const rows = shape ? shape(b) : [headOf(b), ...(b.rows || []).map(flat)];
        const cols = [...new Set(rows.flatMap((r) => Object.keys(r)))];
        return { data: rows, columns: cols, meta: metaOf(b) };
      },
    });
  }
  // NASA FIRMS thermal anomalies: one "aoi" row per area of interest (24-hour counts against the collector's daily
  // baseline, novel 0.1-degree cells once the baseline holds 7 days), then the detections the collector kept.
  docLoader('live_fires', 'NASA FIRMS VIIRS thermal anomalies in the kinetic theaters over 24 hours, per area of interest against the collector\'s daily baseline, with the detections kept (novel cells first), via threat-feeds /api/context.',
    (b) => [headOf(b, ['aois']), ...(b.aois || []).map((a) => ({ kind: 'aoi', ...flat(a) })), ...(b.rows || []).map(flat)]);
  // Maritime security: one "source" row per upstream with what it answered (refused, withdrawn or frozen sources say
  // so), one "theater" row per theater with advisories, incidents and warnings, then the records themselves.
  docLoader('live_maritime', 'Maritime security sources (MARAD MSCI advisories, NGA ASAM, NGA broadcast navigational warnings, UKMTO): each source\'s status and staleness, counts by theater and the records, via threat-feeds /api/context.',
    (b) => [headOf(b, ['sources', 'by_theater']), ...(b.sources || []).map((s) => ({ kind: 'source', ...flat(s) })),
      ...Object.entries(b.by_theater || {}).map(([t, c]) => ({ kind: 'theater', theater_id: t, ...flat(c) })), ...(b.rows || []).map(flat)]);
  docLoader('live_leaksites', 'ThreatCluster\'s first-party leak-site crawl cross-checked against ransomware.live per group: claims in 30 days and in the shared window, matches, and corroboration counting first-party rows only, via threat-feeds /api/context.');
  docLoader('live_lists', 'Free IPv4 blocklists checked against the hosts on the threat map: entries, hosts matched, overlap with other operators\' lists and each list\'s role in the credibility count, via threat-feeds /api/context.');
  docLoader('live_blogs', 'First-party CTI blogs from the awesome_threat_intel_blogs list (CC BY 4.0): each blog\'s feed status and the last 7 days of item titles and links, via threat-feeds /api/context.');
  docLoader('live_psirt', 'Vendor PSIRT and national CERT advisory feeds read from each publisher: title, link, date and CVE identifiers, with CVEs listed in CISA KEV marked, via threat-feeds /api/context.');
  docLoader('live_triage', 'Machine triage of collected titles by a free hosted language model under deterministic checks: relevance, vector, theater and actors per title, unreviewed, with the tier\'s evaluation against analyst labels, via threat-feeds /api/context.');
  docLoader('live_news', 'Theater news feeds read every hour from each outlet: title, link and date only, labelled by the triage tier, via threat-feeds /api/context.');
  docLoader('live_sources', 'The KTI source network: every feed the collector reads (data/feeds.json), its state and healed route, via threat-feeds /api/context.');
  docLoader('live_graph', 'The entity graph over the collection: entities named in the last 30 days with counts, publishers, rise scores and rising and new flags, the strongest co-mention edges and the curated relationships among them, via threat-feeds /api/context.');
  docLoader('live_alerts', 'Change alerts from the standing watches: one row per watch with its requirement and alert count, and one per alert with its headline, entity, entries, publishers, dates and latest entries, via threat-feeds /api/context.');
  docLoader('live_scorecard', 'The platform\'s measured track record: KEV foresight, pre-KEV surge alerts and watchlist CVEs that KEV later listed, triage agreement with the analyst, and source and collector health, with each measure\'s daily series, via threat-feeds /api/context.');
  docLoader('live_cyphys', 'Cyber-physical coincidences per country over 72 hours: IODA outage hours and signals, GDELT material-conflict z score, threat reporting naming the country by publishers against its usual rate, and state-attributed actors named, with which signals are elevated, via threat-feeds /api/context.');
  docLoader('live_foresight', 'Threatcasting futures: for each theater at ThreatCon 4 and above, three futures (escalation, continuation, de-escalation) with their threatcast, signposts read against the current indicator states, proposed indicators, backcast milestones, preparedness actions and cited items, the reading, and the drafting attempts with the checker\'s reasons, via threat-feeds /api/context.');
  docLoader('live_sigma', 'Sigma detection drafts: per drafting attempt the subject, outcome and pages read, and per rule its title, log source, ATT&CK techniques with public Sigma coverage, level, the checker\'s result and the YAML of accepted drafts, via threat-feeds /api/context.');
  docLoader('live_links', 'Daily link checks of the source registry, the OSINT toolkit and the pivot patterns: status, reason and last good check per link, via threat-feeds /api/context.');
  docLoader('live_unit42', 'Palo Alto Networks Unit 42 Timely Threat Intel notes (GitHub, GPL-3.0): date, title, link and indicator counts by type, indicators left out, via threat-feeds /api/context.');
  docLoader('live_genioc', 'Gen Threat Labs indicator folders (github.com/gendigitalinc/ioc, DRL 1.1): per family the files, YARA rules and counts of hashes and network indicators, via threat-feeds /api/context.');
  docLoader('live_lanesreg', 'Lanes News outlet registry and naming choices (lanes.news/data, CC BY 4.0): each outlet\'s country, language, funding and lanes, and 14 days of which side\'s wording each press lane uses, via threat-feeds /api/context.');
  docLoader('live_ransompay', 'Ransomwhere crowdsourced ransomware payment dataset (CC BY 4.0) by family: addresses, transactions and USD at transaction time, with the newest transaction date, via threat-feeds /api/context.');
  docLoader('live_sec8k', 'SEC EDGAR Form 8-K filings over 90 days: Item 1.05 material cybersecurity incident disclosures and their amendments, and Item 8.01 filings whose own text names an incident (candidates), with filer sector from SIC, via threat-feeds /api/context.');
  // On-demand enrichment of one public indicator. With no indicator chosen the service answers 400 and asks for one;
  // that is an idle state, shown as such, not a failure.
  dash.loader('live_enrich', {
    description: 'On-demand enrichment of one public ASN, IPv4 address, domain, file hash or actor name by free public analyzers (CIRCL BGP Ranking, IP-to-ASN and hashlookup, abuse.ch MalwareBazaar and YARAify, cl0q, Tranco, ORKL, the collector\'s own holdings), each result with its analyzer, page and retrieval time, via threat-feeds /api/enrich.',
    fn: ({ answer, args }) => {
      const b = body(answer);
      if (!b) throw new Error('threat-feeds returned a response this loader could not parse');
      // The route answers this only when no valid type and value reached it (an unset or unfilled filter).
      if (b.error && /must be one of/.test(String(b.error))) return { data: [{ kind: 'idle', note: 'No indicator chosen' }], columns: ['kind', 'note'], meta: [] };
      const asked = String((args && args.url) || '').match(/[?&]type=([^&]*)&q=([^&]*)/);
      const qv = asked ? decodeURIComponent(asked[2] || '') : '';
      if (b.error) throw new Error('threat-feeds: ' + b.error + (b.reason ? ' (' + b.reason + ')' : ''));
      if (b.ok === false) return { data: [{ kind: 'invalid', type: b.type || '', q: b.q || qv, note: String(b.error || 'not a valid value for this type') }], columns: ['kind', 'type', 'q', 'note'], meta: [] };
      const head = { kind: 'meta', type: b.type, q: b.q, at: b.at };
      const rows = [head, ...(b.results || []).map((r) => ({ kind: 'result', type: b.type, q: b.q, analyzer: r.analyzer, label: r.label, page: r.page || '', ok: !!r.ok, cached: !!r.cached, at: r.at || '', error: r.error || '', data: r.data == null ? '' : JSON.stringify(r.data) }))];
      return { data: rows, columns: ['kind', 'type', 'q', 'analyzer', 'label', 'page', 'ok', 'cached', 'at', 'error', 'data'], meta: [{ label: 'Indicator', value: (b.type || '') + ' ' + (b.q || '') }, { label: 'Read', value: String(b.at || '') }] };
    },
  });

  // OFAC SDN changes read from the Treasury page of each recent action (G61): one row per vessel designated or delisted
  // and one per entry under a CYBER program. The collector's lists arrive as JSON text; an action whose page the current
  // parser has not read yet (no page_read) is left out until it has.
  const jlist = (x) => { if (Array.isArray(x)) return x; if (typeof x === 'string' && x.trim()[0] === '[') { try { const a = JSON.parse(x); return Array.isArray(a) ? a : []; } catch { return []; } } return []; };
  const change = (a) => (a === 'removed' ? 'Delisted' : a === 'updated' ? 'Updated' : 'Designated');
  dash.calc('ofac_listings', {
    title: 'OFAC vessel and cyber listings',
    description: 'Vessels OFAC designated or delisted, and entries under its cyber-related programs, read from the Treasury page of each recent action: name, aliases, IMO, MMSI, call sign, type and flag as OFAC prints them.',
    inputs: ['live_ofac'],
    fn: (live_ofac) => {
      const out = [];
      for (const r of live_ofac || []) {
        if (!r.page_read) continue;
        const base = { date: r.date, action_id: r.id, url: r.url, title: r.title, theaters: r.theaters || '' };
        for (const v of jlist(r.vessels)) out.push({ key: ['vessel', r.id, v.action, v.imo || v.name].join(':'), kind: 'vessel', ...base, change: change(v.action), name: v.name || '',
          aliases: jlist(v.aliases).join('; '), imo: v.imo || null, mmsi: v.mmsi || null, call_sign: v.call_sign || null, type: v.type || null, flag: v.flag || null, programs: jlist(v.programs).join(', ') });
        for (const c of jlist(r.cyber_entries)) out.push({ key: ['cyber', r.id, c.action, c.name].join(':'), kind: 'cyber', ...base, change: change(c.action), name: c.name || '',
          aliases: '', imo: null, mmsi: null, call_sign: null, type: c.kind || null, flag: null, programs: jlist(c.programs).join(', ') });
      }
      return out;
    },
  });

  // Sources the collector could not read at its last run, in their own answers: map layers that did not answer and
  // maritime sources that refused, withdrew or froze.
  dash.calc('source_gaps', {
    title: 'Sources not answering',
    description: 'Threat-map layers and maritime sources that did not give current data at the collector\'s last run, with what each answered.',
    inputs: ['live_threatmap', 'live_maritime'],
    fn: (live_threatmap, live_maritime) => [
      ...(live_threatmap || []).filter((r) => r.kind === 'layer' && r.ok === false).map((r) => ({ key: 'layer:' + r.layer, source: r.name, url: r.url, status: r.status, feeds: 'Threat map layer', answered: r.note || 'No answer at the last run' })),
      ...(live_maritime || []).filter((r) => r.kind === 'source' && !r.ok).map((r) => ({ key: 'maritime:' + r.id, source: r.id, url: r.url, status: r.status, feeds: 'Maritime security', answered: r.error || 'No answer at the last run' })),
    ],
  });

  // ---- Aggregations of the live claims (loaders reshape; calcs aggregate) ----
  dash.calc('live_rw_summary', {
    title: 'Live ransomware claims summary',
    description: 'Counts the live leak-site claims by recency and highlights the most active group and financial-sector share.',
    inputs: ['live_ransomware'],
    fn: (live_ransomware) => {
      const rows = live_ransomware || [];
      const now = Date.now();
      const since = (h) => rows.filter((r) => { const t = Date.parse((r.discovered || '').replace(' ', 'T') + 'Z'); return isFinite(t) && now - t <= h * 3600e3; }).length;
      const byGroup = {};
      for (const r of rows) byGroup[r.group] = (byGroup[r.group] || 0) + 1;
      const top = Object.entries(byGroup).sort((a, b) => b[1] - a[1])[0] || ['', 0];
      const fin = rows.filter((r) => /financ/i.test(r.sector || '')).length;
      return [{ total: rows.length, last_24h: since(24), last_7d: since(168), top_group: top[0], top_group_claims: top[1], financial: fin }];
    },
  });

  dash.calc('live_rw_by_group', {
    title: 'Live claims by group',
    description: 'The live leak-site claims aggregated by group.',
    inputs: ['live_ransomware'],
    fn: (live_ransomware) => {
      const by = {};
      for (const r of (live_ransomware || [])) {
        const g = r.group || 'unknown';
        by[g] = by[g] || { group: g, claims: 0, financial: 0, countries: new Set() };
        by[g].claims += 1;
        if (/financ/i.test(r.sector || '')) by[g].financial += 1;
        if (r.country) by[g].countries.add(r.country);
      }
      return Object.values(by).map((x) => ({ group: x.group, claims: x.claims, financial: x.financial, countries: x.countries.size })).sort((a, b) => b.claims - a.claims);
    },
  });

  dash.calc('live_rw_by_sector', {
    title: 'Live claims by vertical',
    description: "Live leak-site claims counted for each critical-infrastructure vertical by matching the start of its sector label (ransomware.live labels such as 'Energy & Utilities' differ from the snapshot's).",
    inputs: ['live_ransomware', 'verticals'],
    fn: (live_ransomware, verticals) => {
      const rows = live_ransomware || [];
      const total = rows.length;
      return (verticals || []).map((v) => {
        const key = String(v.sectors || '').toLowerCase().split(/[ /&]/)[0].slice(0, 7);
        const claims = rows.filter((r) => String(r.sector || '').toLowerCase().includes(key)).length;
        return { vertical_id: v.vertical_id, sector: v.sectors, match: key, claims, share: total ? Math.round((claims / total) * 1000) / 1000 : 0 };
      });
    },
  });

  dash.calc('live_epss_kev', {
    title: 'Live EPSS leaders against KEV',
    description: "Today's highest EPSS scores joined to the KEV catalog: a high score with no KEV listing is a candidate for the early-warning watch.",
    inputs: ['live_epss', 'kev'],
    fn: (live_epss, kev) => {
      const K = new Map((kev || []).map((k) => [k.cve, k]));
      return (live_epss || []).map((r) => {
        const k = K.get(r.cve);
        return { cve: r.cve, epss: r.epss, percentile: r.percentile, date: r.date, in_kev: k ? 'Yes' : 'No', vendor: k ? k.vendor : '', product: k ? k.product : '', ransomware: k ? k.ransomware : '' };
      });
    },
  });

  dash.calc('live_tf_by_malware', {
    title: 'Live IOCs by malware family',
    description: 'Recent abuse.ch ThreatFox indicators grouped by malware family, with indicator types and the newest first-seen time.',
    inputs: ['live_threatfox'],
    fn: (live_threatfox) => {
      const by = {};
      for (const r of (live_threatfox || [])) {
        const m = r.malware || 'Unknown';
        const x = (by[m] = by[m] || { malware: m, iocs: 0, types: new Set(), threat: new Set(), newest: '' });
        x.iocs += 1;
        if (r.type) x.types.add(r.type);
        if (r.threat) x.threat.add(r.threat);
        if (String(r.first_seen || '') > x.newest) x.newest = String(r.first_seen || '');
      }
      return Object.values(by).map((x) => ({ malware: x.malware, iocs: x.iocs, types: [...x.types].join(', '), threat: [...x.threat].join(', '), newest: x.newest })).sort((a, b) => b.iocs - a.iocs);
    },
  });

  dash.calc('live_tf_summary', {
    title: 'Live IOC summary',
    description: 'Count of recent ThreatFox indicators, distinct malware families, and the most frequent family.',
    inputs: ['live_tf_by_malware'],
    fn: (rows) => {
      const iocs = (rows || []).reduce((s, r) => s + r.iocs, 0);
      return [{ iocs, families: (rows || []).length, top_family: rows && rows[0] ? rows[0].malware : '' }];
    },
  });

  dash.calc('live_epss_summary', {
    title: 'Live EPSS summary',
    description: "How many of today's highest-EPSS CVEs are absent from KEV.",
    inputs: ['live_epss_kev'],
    fn: (rows) => [{ scored: (rows || []).length, not_in_kev: (rows || []).filter((r) => r.in_kev === 'No').length, in_kev: (rows || []).filter((r) => r.in_kev === 'Yes').length }],
  });

  dash.calc('live_rw_by_country', {
    title: 'Live claims by country',
    description: 'The live leak-site claims aggregated by victim country (ISO-2), for the world map.',
    inputs: ['live_ransomware'],
    fn: (live_ransomware) => {
      const by = {};
      for (const r of (live_ransomware || [])) { const c = r.country || ''; if (c) by[c] = (by[c] || 0) + 1; }
      return Object.entries(by).map(([country, claims]) => ({ country, claims })).sort((a, b) => b.claims - a.claims);
    },
  });

  // ---- GDELT armed-conflict events ----
  const gdHeader = (rows) => (rows || []).find((r) => r.kind === 'meta') || {};

  dash.calc('live_gdelt_meta', {
    title: 'GDELT window',
    description: 'The GDELT fetch window: latest 15-minute export, live hours, baseline hours, events kept and files read.',
    inputs: ['live_gdelt'],
    fn: (live_gdelt) => {
      const h = gdHeader(live_gdelt);
      return [{ latest: h.latest || '', hours: h.hours || 24, baseline: h.baseline || 0, actors: h.actors || '', quads: h.quads || '',
        events: h.events_kept || 0, files_ok: h.files_ok || 0, files_requested: h.files_requested || 0 }];
    },
  });

  dash.calc('live_gdelt_cells', {
    title: 'GDELT conflict grid',
    description: 'Armed-conflict events collapsed to 1-degree map cells, summed across the live window and kept per hour bucket for the time slider.',
    inputs: ['live_gdelt'],
    fn: (live_gdelt) => (live_gdelt || []).filter((r) => r.kind === 'cell').map((r) => ({ lat: r.lat, lon: r.lon, h: r.h, n: r.n, m: r.m })),
  });

  dash.calc('live_gdelt_by_country', {
    title: 'GDELT conflict by country',
    description: 'Armed-conflict events per country over the live window against the per-day baseline, with an anomaly ratio (live rate / baseline daily rate). A ratio above 1.5 is a surge.',
    inputs: ['live_gdelt'],
    fn: (live_gdelt) => {
      const rows = live_gdelt || [];
      const h = gdHeader(rows);
      const liveHours = h.hours || 24;
      const baseHours = h.baseline || 0;
      const live = {}, base = {}, mentions = {};
      for (const r of rows) {
        if (r.kind === 'country') { live[r.iso2] = (live[r.iso2] || 0) + r.n; mentions[r.iso2] = (mentions[r.iso2] || 0) + r.m; }
        else if (r.kind === 'base') base[r.iso2] = (base[r.iso2] || 0) + r.n;
      }
      const out = [];
      for (const iso2 of new Set([...Object.keys(live), ...Object.keys(base)])) {
        const liveRate = (live[iso2] || 0) / liveHours;
        const baseRate = baseHours ? (base[iso2] || 0) / baseHours : 0;
        out.push({ country: iso2, events: live[iso2] || 0, mentions: mentions[iso2] || 0, baseline: base[iso2] || 0,
          ratio: baseRate ? Math.round((liveRate / baseRate) * 100) / 100 : (live[iso2] ? null : 0),
          surge: baseRate && liveRate / baseRate >= 1.5 && (live[iso2] || 0) >= 5 ? 'Yes' : 'No' });
      }
      return out.sort((a, b) => b.events - a.events);
    },
  });

  dash.calc('live_gdelt_events', {
    title: 'GDELT top conflict events',
    description: 'The most-mentioned armed-conflict events in the live window, one per source article, with CAMEO root label, actors, place and link.',
    inputs: ['live_gdelt'],
    fn: (live_gdelt) => {
      // CAMEO root codes 14-20: protest through unconventional mass violence.
      const ROOT = { 14: 'Protest', 15: 'Force posture', 16: 'Reduce relations', 17: 'Coerce', 18: 'Assault', 19: 'Fight', 20: 'Mass violence' };
      return (live_gdelt || []).filter((r) => r.kind === 'event').map((r) => ({
        event: ROOT[+r.root] || ('CAMEO ' + r.root), cameo: r.code, place: r.place || r.iso2 || '', country: r.iso2 || '',
        actor1: r.actor1 || '', actor2: r.actor2 || '', goldstein: r.goldstein, mentions: r.mentions, sources: r.sources,
        hours_ago: r.h, url: r.url,
      })).sort((a, b) => b.mentions - a.mentions);
    },
  });

  dash.calc('live_gdelt_theaters', {
    title: 'GDELT conflict by theater',
    description: 'Armed-conflict events summed over the theater countries, so each theater carries a live conflict tempo and surge flag beside its assessment.',
    inputs: ['live_gdelt', 'theaters'],
    fn: (live_gdelt, theaters) => {
      const rows = live_gdelt || [];
      const h = gdHeader(rows);
      const liveHours = h.hours || 24, baseHours = h.baseline || 0;
      const live = {}, base = {};
      for (const r of rows) { if (r.kind === 'country') live[r.iso2] = (live[r.iso2] || 0) + r.n; else if (r.kind === 'base') base[r.iso2] = (base[r.iso2] || 0) + r.n; }
      return (theaters || []).map((t) => {
        const ccs = String(t.countries || '').split(',').filter(Boolean);
        const ev = ccs.reduce((s, c) => s + (live[c] || 0), 0);
        const bs = ccs.reduce((s, c) => s + (base[c] || 0), 0);
        const liveRate = ev / liveHours, baseRate = baseHours ? bs / baseHours : 0;
        return { theater_id: t.theater_id, name: t.name, events: ev, baseline: bs,
          ratio: baseRate ? Math.round((liveRate / baseRate) * 100) / 100 : null,
          surge: baseRate && liveRate / baseRate >= 1.5 && ev >= 5 ? 'Yes' : 'No' };
      }).sort((a, b) => b.events - a.events);
    },
  });

  // ---- Map layers ----
  dash.calc('live_gdelt_flows', {
    title: 'GDELT conflict arcs',
    description: 'Actor-to-action arcs from the live GDELT window: where the coder placed Actor 1 to where it placed the action, with events, mentions, distinct articles and recency. Pairs reported by one article are flagged single-source.',
    inputs: ['live_gdelt'],
    fn: (live_gdelt) => (live_gdelt || []).filter((r) => r.kind === 'flow').map((r) => ({
      key: [r.src_lat, r.src_lon, r.dst_lat, r.dst_lon].join(','), src_lat: r.src_lat, src_lon: r.src_lon, dst_lat: r.dst_lat, dst_lon: r.dst_lon,
      src_place: r.src_place || '', dst_place: r.dst_place || '', src_iso2: r.src_iso2 || '', dst_iso2: r.dst_iso2 || '', src_type: r.src_type || 0, dst_type: r.dst_type || 0,
      root: r.root, code: r.code, actor1: r.actor1 || '', actor2: r.actor2 || '', n: r.n, m: r.m, articles: r.articles ?? 1, h: r.h, hours_seen: r.hours_seen || 1,
      single_source: (r.articles ?? 1) < 2 ? 'Yes' : 'No', url: r.url })),
  });

  dash.calc('live_attrib_pairs', {
    title: 'Attributed origin to victim pairs',
    description: 'Country pairs from the MISP galaxy threat-actor cluster: attributed origin to CFR suspected-victim country, with the number of actors and their names. Historical attribution, not observed traffic.',
    inputs: ['live_actors'],
    fn: (live_actors) => (live_actors || []).filter((r) => r.kind === 'pair').map((r) => ({ o: r.o, t: r.t, n: r.n, actors: String(r.actors || '') })),
  });

  dash.calc('live_tm_families', {
    title: 'Hostile infrastructure by family',
    description: 'Listed hosts per malware family across the C2, IOC and malware-host layers of the collector document, with the mapped hosts new in the last 24 hours: listed by their source in that window, or first observed by the collector in it once the collector has watched for a day.',
    inputs: ['live_threatmap'],
    fn: (live_threatmap) => {
      const by = new Map();
      for (const r of live_threatmap || []) {
        if (r.kind === 'family' && r.family && r.family !== 'scanning') { const x = by.get(r.family) || { family: r.family, c2: 0, ioc: 0, url: 0, total: 0, mapped: 0, fresh: 0 }; x[r.layer] = (x[r.layer] || 0) + r.n; x.total += r.n; by.set(r.family, x); }
      }
      for (const r of live_threatmap || []) if (r.kind === 'node' && by.has(r.family)) { const x = by.get(r.family); x.mapped++; if (r.new) x.fresh++; }
      return [...by.values()].sort((a, b) => b.total - a.total);
    },
  });

  dash.calc('live_health_upstreams', {
    title: 'Live upstream reachability',
    description: 'The upstream rows of live_health: what the threat-feeds proxy reaches right now, with HTTP status, latency and proxy cache window.',
    inputs: ['live_health'],
    fn: (live_health) => (live_health || []).filter((r) => r.kind === 'upstream' || !r.kind),
  });

  // What each upstream and collector job feeds on this dashboard, so a failing row says what it takes down.
  const FEEDS_INTO = {
    cisa_kev: 'The proxy KEV route; the KEV catalog here comes from the cisagov/kev-data mirror in the daily refresh', dshield: 'Scanning sources layer, Infocon', epss: 'EPSS leaders (Vulnerabilities)',
    feodo: 'C2 servers layer', gdelt_doc_api: 'Nothing on this page yet (planned theater volume baselines)', gdelt_exports: 'Conflict arcs and intensity',
    geojs: 'Geolocation fallback for the infrastructure layers', ip_api: 'Geolocation for the infrastructure layers',
    ioda: 'Internet outages layer',
    ransomware_live: 'Leak-site claims (Ransomware), reported attacks layer', threatfox: 'IOC endpoints layer, live IOCs', tor_exits: 'Tor exit relays (IP lists)',
    lanes: 'Relationship temperatures (Theaters)', ofac_recent_actions: 'OFAC Recent Actions (Theaters)',
    urlhaus: 'Malware hosts layer', 'job:gdelt': 'Conflict arcs and intensity', 'job:infra': 'Infrastructure layers', 'job:health': 'This uptime record, Infocon',
    'job:ioda': 'Internet outages layer', 'job:snap': 'Last-good copies of the live feeds', 'job:retention': 'Database housekeeping',
  };
  dash.calc('live_collector_uptime', {
    title: 'Collector uptime record',
    description: "The collector's checks of every upstream every 30 minutes: 24-hour and 7-day uptime, median latency and the current failing streak, with the collector's own job runs and the part of this dashboard each one feeds.",
    inputs: ['live_health'],
    fn: (live_health) => (live_health || []).filter((r) => r.kind === 'feed' || r.kind === 'job').map((r) => ({ ...r, feeds: FEEDS_INTO[r.kind === 'job' ? 'job:' + r.job : r.feed] || '' })),
  });


  function TI_INT(n) { return n == null ? '' : Number(n).toLocaleString('en-US'); }
})();
