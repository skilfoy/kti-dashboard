/* Context feeds and analyst pivots. Lanes relationship temperatures and OFAC Recent Actions (threat-feeds
   /api/context, collected hourly) attached to the theater assessments; the OSINT toolkit table on the Sources page;
   and the outbound pivot links the theater detail and the map's selection panel offer. Every link pattern here was
   read off the target site on 2026-10-19 (Lanes bridge pages, Nations Online profiles, cl0q network pages,
   bgp.he.net, GreyNoise and AbuseIPDB IP pages, OFAC action pages). Tools without a confirmed pattern open their
   front page. */
(() => {
  const { h, v } = TI;
  const X = (TI.ctx = {});
  const name = (cc) => (window.TI_ISONAME && window.TI_ISONAME[cc]) || cc || '';
  const a = (href, text, title) => h('a', { href, target: '_blank', rel: 'noopener noreferrer', text, title: title || null });

  // ---------------------------------------------------------------- pivots
  // Nations Online profile slugs, read from its countries index on 2026-10-19 (no slug published for South Sudan).
  // [slug, the short name Nations Online uses]
  const NO = {
    AD: ['andorra', 'Andorra'], AE: ['arab_emirates', 'United Arab Emirates'], AF: ['afghanistan', 'Afghanistan'],
    AG: ['antigua_barbuda', 'Antigua and Barbuda'], AI: ['anguilla', 'Anguilla'], AL: ['albania', 'Albania'], AM: ['armenia', 'Armenia'],
    AO: ['angola', 'Angola'], AR: ['argentina', 'Argentina'], AS: ['american_samoa', 'American Samoa'], AT: ['austria', 'Austria'],
    AU: ['australia', 'Australia'], AW: ['aruba', 'Aruba'], AZ: ['azerbaijan', 'Azerbaijan'], BA: ['bosnia_herzegovina', 'Bosnia and Herzegovina'],
    BB: ['barbados', 'Barbados'], BD: ['bangladesh', 'Bangladesh'], BE: ['belgium', 'Belgium'], BF: ['burkina_faso', 'Burkina Faso'],
    BG: ['bulgaria', 'Bulgaria'], BH: ['bahrain', 'Bahrain'], BI: ['burundi', 'Burundi'], BJ: ['benin', 'Benin'], BM: ['bermuda', 'Bermuda'],
    BN: ['brunei', 'Brunei'], BO: ['bolivia', 'Bolivia'], BR: ['brazil', 'Brazil'], BS: ['bahamas', 'Bahamas'], BT: ['bhutan', 'Bhutan'],
    BW: ['botswana', 'Botswana'], BY: ['belarus', 'Belarus'], BZ: ['belize', 'Belize'], CA: ['canada', 'Canada'], CD: ['congo_droc', 'DR Congo'],
    CF: ['central_african_republic', 'Central African Republic'], CG: ['congo_roc', 'Republic of the Congo'], CH: ['switzerland', 'Switzerland'],
    CI: ['cote_d_ivoire', "Cote d'Ivoire"], CL: ['chile', 'Chile'], CM: ['cameroon', 'Cameroon'], CN: ['china', 'China'],
    CO: ['colombia', 'Colombia'], CR: ['costa_rica', 'Costa Rica'], CU: ['cuba', 'Cuba'], CV: ['cape_verde', 'Cabo Verde'], CY: ['cyprus', 'Cyprus'],
    CZ: ['czech_republic', 'Czechia'], DE: ['germany', 'Germany'], DJ: ['djibouti', 'Djibouti'], DK: ['denmark', 'Denmark'],
    DM: ['dominica', 'Dominica'], DO: ['dominican_republic', 'Dominican Republic'], DZ: ['algeria', 'Algeria'], EC: ['ecuador', 'Ecuador'],
    EE: ['estonia', 'Estonia'], EG: ['egypt', 'Egypt'], ER: ['eritrea', 'Eritrea'], ES: ['spain', 'Spain'], ET: ['ethiopia', 'Ethiopia'],
    FI: ['finland', 'Finland'], FJ: ['fiji', 'Fiji'], FM: ['micronesia', 'Micronesia'], FO: ['faroe_islands', 'Faroe Islands'],
    FR: ['france', 'France'], GA: ['gabon', 'Gabon'], GB: ['united_kingdom', 'United Kingdom'], GD: ['grenada', 'Grenada'],
    GE: ['georgia', 'Georgia'], GF: ['french_guiana', 'French Guiana'], GH: ['ghana', 'Ghana'], GL: ['greenland', 'Greenland'],
    GM: ['gambia', 'Gambia'], GN: ['guinea', 'Guinea'], GP: ['guadeloupe', 'Guadeloupe'], GQ: ['equatorial_guinea', 'Equatorial Guinea'],
    GR: ['greece', 'Greece'], GT: ['guatemala', 'Guatemala'], GU: ['guam', 'Guam'], GW: ['guinea_bissau', 'Guinea-Bissau'], GY: ['guyana', 'Guyana'],
    HK: ['hong_kong', 'Hong Kong'], HN: ['honduras', 'Honduras'], HR: ['croatia', 'Croatia'], HT: ['haiti', 'Haiti'], HU: ['hungary', 'Hungary'],
    ID: ['indonesia', 'Indonesia'], IE: ['ireland', 'Ireland'], IL: ['israel', 'Israel'], IN: ['india', 'India'], IQ: ['iraq', 'Iraq'],
    IR: ['iran', 'Iran'], IS: ['iceland', 'Iceland'], IT: ['italy', 'Italy'], JM: ['jamaica', 'Jamaica'], JO: ['jordan', 'Jordan'],
    JP: ['japan', 'Japan'], KE: ['kenya', 'Kenya'], KG: ['kyrgyzstan', 'Kyrgyzstan'], KH: ['cambodia', 'Cambodia'], KI: ['kiribati', 'Kiribati'],
    KM: ['comoros', 'Comoros'], KN: ['saint_kitts_nevis', 'Saint Kitts and Nevis'], KP: ['korea_north', 'North Korea'],
    KR: ['korea_south', 'South Korea'], KW: ['kuwait', 'Kuwait'], KZ: ['kazakhstan', 'Kazakhstan'], LA: ['laos', 'Laos'], LB: ['lebanon', 'Lebanon'],
    LC: ['saint_lucia', 'Saint Lucia'], LI: ['liechtenstein', 'Liechtenstein'], LK: ['sri_lanka', 'Sri Lanka'], LR: ['liberia', 'Liberia'],
    LS: ['lesotho', 'Lesotho'], LT: ['lithuania', 'Lithuania'], LU: ['luxembourg', 'Luxembourg'], LV: ['latvia', 'Latvia'], LY: ['libya', 'Libya'],
    MA: ['morocco', 'Morocco'], MC: ['monaco', 'Monaco'], MD: ['moldova', 'Moldova'], ME: ['montenegro', 'Montenegro'],
    MG: ['madagascar', 'Madagascar'], MH: ['marshall_islands', 'Marshall Islands'], MK: ['macedonia_rep', 'North Macedonia'], ML: ['mali', 'Mali'],
    MM: ['myanmar', 'Myanmar'], MN: ['mongolia', 'Mongolia'], MO: ['macau', 'Macau'], MP: ['northern_mariana_islands', 'Northern Mariana Islands'],
    MQ: ['martinique', 'Martinique'], MR: ['mauritania', 'Mauritania'], MS: ['montserrat', 'Montserrat'], MT: ['malta', 'Malta'],
    MU: ['mauritius', 'Mauritius'], MV: ['maldives', 'Maldives'], MW: ['malawi', 'Malawi'], MX: ['mexico', 'Mexico'], MY: ['malaysia', 'Malaysia'],
    MZ: ['mozambique', 'Mozambique'], NA: ['namibia', 'Namibia'], NC: ['new_caledonia', 'New Caledonia'], NE: ['niger', 'Niger'],
    NG: ['nigeria', 'Nigeria'], NI: ['nicaragua', 'Nicaragua'], NL: ['netherlands', 'Netherlands'], NO: ['norway', 'Norway'], NP: ['nepal', 'Nepal'],
    NR: ['nauru', 'Nauru'], NZ: ['new_zealand', 'New Zealand'], OM: ['oman', 'Oman'], PA: ['panama', 'Panama'], PE: ['peru', 'Peru'],
    PF: ['french_polynesia', 'French Polynesia'], PG: ['papua_new_guinea', 'Papua New Guinea'], PH: ['philippines', 'Philippines'],
    PK: ['pakistan', 'Pakistan'], PL: ['poland', 'Poland'], PN: ['pitcairn', 'Pitcairn'], PR: ['puerto_rico', 'Puerto Rico'],
    PS: ['palestinian_territory', 'Palestine'], PT: ['portugal', 'Portugal'], PW: ['palau', 'Palau'], PY: ['paraguay', 'Paraguay'],
    QA: ['qatar', 'Qatar'], RE: ['reunion', 'Reunion'], RO: ['romania', 'Romania'], RS: ['serbia', 'Serbia'], RU: ['russia', 'Russia'],
    RW: ['rwanda', 'Rwanda'], SA: ['saudi_arabia', 'Saudi Arabia'], SB: ['solomon_islands', 'Solomon Islands'], SC: ['seychelles', 'Seychelles'],
    SD: ['sudan', 'Sudan'], SE: ['sweden', 'Sweden'], SG: ['singapore', 'Singapore'], SI: ['slovenia', 'Slovenia'], SK: ['slovakia', 'Slovakia'],
    SL: ['sierra_leone', 'Sierra Leone'], SM: ['san_marino', 'San Marino'], SN: ['senegal', 'Senegal'], SO: ['somalia', 'Somalia'],
    SR: ['suriname', 'Suriname'], ST: ['sao_tome_principe', 'Sao Tome and Principe'], SV: ['el_salvador', 'El Salvador'], SY: ['syria', 'Syria'],
    SZ: ['swaziland', 'Eswatini'], TD: ['chad', 'Chad'], TG: ['togo', 'Togo'], TH: ['thailand', 'Thailand'], TJ: ['tajikistan', 'Tajikistan'],
    TL: ['timor_leste', 'Timor-Leste'], TM: ['turkmenistan', 'Turkmenistan'], TN: ['tunisia', 'Tunisia'], TO: ['tonga', 'Tonga'],
    TR: ['turkey', 'Turkey'], TT: ['trinidad_and_tobago', 'Trinidad and Tobago'], TV: ['tuvalu', 'Tuvalu'], TW: ['taiwan', 'Taiwan'],
    TZ: ['tanzania', 'Tanzania'], UA: ['ukraine', 'Ukraine'], UG: ['uganda', 'Uganda'], US: ['united_states', 'United States'],
    UY: ['uruguay', 'Uruguay'], UZ: ['uzbekistan', 'Uzbekistan'], VA: ['vatican', 'Vatican City'],
    VC: ['saint_vincent_grenadines', 'Saint Vincent and the Grenadines'], VE: ['venezuela', 'Venezuela'],
    VG: ['virgin_islands_british', 'British Virgin Islands'], VI: ['virgin_islands_us', 'US Virgin Islands'], VN: ['vietnam', 'Vietnam'],
    VU: ['vanuatu', 'Vanuatu'], WS: ['samoa', 'Samoa'], XK: ['kosovo', 'Kosovo'], YE: ['yemen', 'Yemen'], ZA: ['south_africa', 'South Africa'],
    ZM: ['zambia', 'Zambia'], ZW: ['zimbabwe', 'Zimbabwe'] };
  const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const P = (TI.pivot = {
    country: (cc) => (NO[cc] ? { label: NO[cc][1], href: 'https://www.nationsonline.org/oneworld/' + NO[cc][0] + '.htm', title: 'Nations Online country profile' } : null),
    // A mapped infrastructure node: the address on GreyNoise and AbuseIPDB, its autonomous system on cl0q and bgp.he.net.
    node: (n) => {
      const out = [];
      if (n && IPV4.test(String(n.ip || ''))) {
        out.push({ label: 'GreyNoise', href: 'https://viz.greynoise.io/ip/' + n.ip, title: 'GreyNoise Visualizer record for this address' });
        out.push({ label: 'AbuseIPDB', href: 'https://www.abuseipdb.com/check/' + n.ip, title: 'AbuseIPDB reports for this address' });
      }
      const asn = String((n && n.asn) || '').replace(/^AS/i, '');
      if (/^\d{1,10}$/.test(asn)) {
        out.push({ label: 'cl0q AS' + asn, href: 'https://cl0q.com/network/' + asn, title: 'Sites cl0q has indexed on this autonomous system' });
        out.push({ label: 'bgp.he.net', href: 'https://bgp.he.net/AS' + asn, title: 'Hurricane Electric BGP view of this autonomous system' });
      }
      return out;
    },
    soar: { label: 'Soar Atlas imagery', href: 'https://soaratlas.com/', title: 'Soar Atlas maps and satellite imagery (opens the atlas; search the place there)' },
    hull: { label: 'HullCipher sanctioned ships', href: 'https://hullcipher.com/', title: 'HullCipher map of ships on sanctions lists (terrestrial AIS)' },
  });

  // ---------------------------------------------------------------- Lanes
  // A Lanes pair attaches to a theater whose country list holds both of its countries, or by the two rules below,
  // where one party sits outside the theater's list: Palestine for the Israel, Lebanon and Syria theater, and the
  // United States for the Strait of Hormuz and the Gulf.
  const RULES = { 'israel-palestine': ['T-LEV'], 'usa-iran': ['T-HRM'] };
  X.lanesFor = (theaterId) => {
    if (!TI.ready('live_lanes', 'theaters')) return [];
    const t = TI.rows('theaters').find((x) => x.theater_id === theaterId);
    if (!t) return [];
    const ccs = String(t.countries || '').split(',').filter(Boolean);
    return TI.rows('live_lanes').filter((r) => (r.a2 && r.b2 && ccs.includes(r.a2) && ccs.includes(r.b2)) || (RULES[r.conflict] || []).includes(theaterId))
      .map((r) => ({ ...r, basis: r.a2 && r.b2 && ccs.includes(r.a2) && ccs.includes(r.b2) ? 'both countries in the theater' : 'mapping rule' }));
  };
  const theatersOf = (r) => {
    if (!TI.ready('theaters')) return [];
    // Most specific first: the theater with the fewest countries.
    return TI.rows('theaters').filter((t) => {
      const ccs = String(t.countries || '').split(',');
      return (r.a2 && r.b2 && ccs.includes(r.a2) && ccs.includes(r.b2)) || (RULES[r.conflict] || []).includes(t.theater_id);
    }).sort((x, y) => String(x.countries || '').split(',').length - String(y.countries || '').split(',').length);
  };
  const pair = (r) => `${r.a_name} and ${r.b_name}`;
  const signed = (x) => (x == null ? '' : (x > 0 ? '+' : '') + d3.format('.2f')(x));
  const lanesMeta = () => {
    const rows = TI.rows('live_lanes') || [];
    const latest = rows.reduce((m, r) => (r.date > m ? r.date : m), '');
    const age = latest ? Math.floor((Date.now() - Date.parse(latest + 'T00:00:00Z')) / 864e5) : null;
    return { latest, age };
  };

  // ---------------------------------------------------------------- OFAC
  X.ofacFor = (theaterId) => (TI.ready('live_ofac') ? TI.rows('live_ofac').filter((r) => String(r.theaters || '').split(',').includes(theaterId)) : []);
  const ofacSpan = () => {
    const rows = TI.ready('live_ofac') ? TI.rows('live_ofac') : [];
    const ds = rows.map((r) => r.date).filter(Boolean).sort();
    return { n: rows.length, from: ds[0] || '', to: ds[ds.length - 1] || '' };
  };
  const tname = (ids) => {
    const m = TI.ready('theaters') ? TI.index(TI.rows('theaters'), 'theater_id') : new Map();
    return String(ids || '').split(',').filter(Boolean).map((id) => (m.get(id) || {}).short || (m.get(id) || {}).name || id).join(', ');
  };

  // Vessels designated or delisted and cyber-program entries, from the ofac_listings calc (G61).
  X.ofacListings = (sec) => {
    const tv = sec.querySelector('#tbl-ofac-vessels'), tc = sec.querySelector('#tbl-ofac-cyber'), note = sec.querySelector('#ofac-list-note');
    const ready = TI.ready('ofac_listings') && TI.ready('live_ofac');
    const rows = ready ? TI.rows('ofac_listings') : [];
    if (note) {
      TI.clear(note);
      if (ready) {
        const acts = TI.rows('live_ofac'), read = acts.filter((r) => r.page_read).length, sp = ofacSpan();
        const ves = rows.filter((r) => r.kind === 'vessel'), des = ves.filter((r) => r.change === 'Designated'), del = ves.filter((r) => r.change === 'Delisted');
        const flags = Object.entries(des.reduce((t, r) => { if (r.flag) t[r.flag] = (t[r.flag] || 0) + 1; return t; }, {})).sort((x, y) => y[1] - x[1]).slice(0, 4);
        const cy = rows.filter((r) => r.kind === 'cyber');
        note.append(h('span', {}, `OFAC's pages for ${read} of the ${sp.n} newest actions (${sp.from} to ${sp.to}) have been read. They designate `,
          v('strong', 'ofac_listings', 'change', null, String(des.length)), ` vessel${des.length === 1 ? '' : 's'} and delist ${del.length}`,
          flags.length ? `; the designated vessels fly ${flags.map(([f, n]) => `${f} (${n})`).join(', ')}` : '', '. ',
          cy.length ? `${cy.length} entr${cy.length === 1 ? 'y falls' : 'ies fall'} under a cyber-related program.` : 'No entry falls under a cyber-related program.',
          read < sp.n ? ` The remaining ${sp.n - read} pages are read over the next collector runs.` : ''));
      }
    }
    if (tv && TI.tableState(tv, ['ofac_listings', 'live_ofac'])) {
      TI.table(tv, rows.filter((r) => r.kind === 'vessel'), [
        { field: 'date', label: 'Action date', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'change', label: 'Change' },
        { field: 'name', label: 'Vessel', link: 'url', cls: 'ti-wrap' },
        { field: 'imo', label: 'IMO', cls: 'ti-nowrap' },
        { field: 'type', label: 'Type', cls: 'ti-wrap', hideSm: true },
        { field: 'flag', label: 'Flag', cls: 'ti-wrap' },
        { field: 'aliases', label: 'Also listed as', cls: 'ti-wrap', hideSm: true },
        { field: 'call_sign', label: 'Call sign', hideSm: true },
        { field: 'mmsi', label: 'MMSI', hideSm: true },
        { field: 'programs', label: 'Program', cls: 'ti-wrap', hideSm: true },
        { field: 'theaters', label: 'Theater', get: (r) => tname(r.theaters), cls: 'ti-wrap', hideSm: true },
      ], { sort: 'date', dir: 'desc', limit: 120, empty: 'None of the actions read so far designates or delists a vessel.' });
    }
    if (tc && TI.tableState(tc, ['ofac_listings', 'live_ofac'])) {
      TI.table(tc, rows.filter((r) => r.kind === 'cyber'), [
        { field: 'date', label: 'Action date', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'change', label: 'Change' },
        { field: 'name', label: 'Name', link: 'url', cls: 'ti-wrap' },
        { field: 'type', label: 'Listed as', hideSm: true },
        { field: 'programs', label: 'Programs', cls: 'ti-wrap' },
      ], { sort: 'date', dir: 'desc', empty: 'No entry in the actions read so far falls under a cyber-related program (CYBER tags).' });
    }
  };

  // ---------------------------------------------------------------- theater detail block
  // Appended under the assessment: the pair temperatures, the OFAC actions naming the theater's programs, a country
  // profile per theater country and the imagery and maritime pivots.
  X.theaterDetail = (el, t) => {
    const w = { theater_id: t.theater_id };
    const dl = h('dl', { class: 'ti-dl ti-ctx' });
    const row = (label, ...kids) => dl.append(h('dt', { text: label }), h('dd', {}, ...kids));
    // Relationship temperature.
    if (TI.failed('live_lanes')) row('Relationship temperature', 'Lanes feed unavailable.');
    else if (!TI.ready('live_lanes')) row('Relationship temperature', h('span', { class: 'dash-skeleton', text: 'Loading' }));
    else {
      const ls = X.lanesFor(t.theater_id), m = lanesMeta();
      if (!ls.length) row('Relationship temperature', 'Lanes tracks no country pair for this theater.');
      for (const r of ls) {
        const wr = { conflict: r.conflict };
        row('Relationship temperature',
          h('span', {}, pair(r), ': ', v('strong', 'live_lanes', 't7', wr, d3.format('.2f')(r.t7 ?? r.temperature)), ' 7-day mean',
            r.t7_prev != null ? ` (prior 7 days ${d3.format('.2f')(r.t7_prev)}, ${signed(r.delta7)})` : '',
            `, on Lanes' 0 cooperative to 1 open-conflict scale. Latest row ${r.date}`, m.age != null && m.age > 2 ? `, ${m.age} days old` : '', '. '),
          a(r.bridge_url, 'Lanes bridge'),
          r.daily_url ? [' · ', a(r.daily_url, 'Latest daily page', 'AI-compiled by Lanes from cited reporting; not human-reviewed')] : null,
          r.basis === 'mapping rule' ? h('span', { class: 'ti-ctx-note', text: ' One party sits outside this theater\'s country list; attached by mapping rule.' }) : null);
      }
    }
    // OFAC.
    if (TI.failed('live_ofac')) row('OFAC actions', 'OFAC feed unavailable.');
    else if (!TI.ready('live_ofac')) row('OFAC actions', h('span', { class: 'dash-skeleton', text: 'Loading' }));
    else {
      const os = X.ofacFor(t.theater_id), sp = ofacSpan();
      if (!os.length) row('OFAC actions', `None of the ${sp.n} newest Recent Actions (${sp.from} to ${sp.to}) names a program mapped to this theater.`);
      else {
        const top = os[0];
        const ids = new Set(os.map((r) => r.id));
        const ves = TI.ready('ofac_listings') ? TI.rows('ofac_listings').filter((r) => r.kind === 'vessel' && r.change === 'Designated' && ids.has(r.action_id)) : [];
        row('OFAC actions', h('span', {}, v('strong', 'live_ofac', 'theaters', null, String(os.length)), ` of the ${sp.n} newest Recent Actions (${sp.from} to ${sp.to}) name a program mapped to this theater. Latest ${top.date}: `),
          a(top.url, top.title), ves.length ? h('span', {}, '. Together they designate ', v('strong', 'ofac_listings', 'change', null, String(ves.length)),
            ` vessel${ves.length === 1 ? '' : 's'}, listed under OFAC vessels and cyber designations below.`) : '');
      }
    }
    // FIRMS thermal anomalies, maritime sources and the Lanes outlet registry (intel.js).
    if (TI.intel) TI.intel.theaterRows(row, t);
    // Country profiles and pivots.
    const ccs = String(t.countries || '').split(',').filter(Boolean);
    const prof = ccs.map(P.country).filter(Boolean);
    if (prof.length) row('Country profiles', ...prof.flatMap((p, i) => [i ? ', ' : '', a(p.href, p.label, p.title)]), h('span', { class: 'ti-ctx-note', text: ' (Nations Online)' }));
    const maritime = TI.ready('chokepoints') && TI.rows('chokepoints').some((c) => c.theater_id === t.theater_id);
    row('Pivots', a(P.soar.href, P.soar.label, P.soar.title), maritime ? [' · ', a(P.hull.href, P.hull.label, P.hull.title)] : null);
    el.append(h('h3', { class: 'ti-h3 ti-ctx-h', text: 'Context feeds and pivots' }), dl);
  };

  // ---------------------------------------------------------------- theater page cards
  function lanesChart(box, rows) {
    const list = rows.slice().sort((x, y) => (y.t7 ?? 0) - (x.t7 ?? 0));
    const days = [...new Set(list.flatMap((r) => TI.list(r.series).map((p) => p[0])))].sort();
    if (!days.length) { TI.clear(box); box.append(h('p', { class: 'ti-card-note', text: 'No Lanes rows to chart.' })); return; }
    const rowH = 30, height = list.length * rowH + 30;
    const { svg, w } = TI.svg(box, height);
    const lw = TI.textWidth(svg, list.map(pair)) + 12;
    const vw = 52;
    const x = d3.scaleUtc([TI.parseDay(days[0]), TI.parseDay(days[days.length - 1])], [lw, w - vw - 8]);
    const g = svg.append('g');
    const ticks = x.ticks(5);
    g.selectAll('line.ti-grid-line').data(ticks).join('line').attr('class', 'ti-grid-line').attr('x1', (d) => x(d)).attr('x2', (d) => x(d)).attr('y1', 4).attr('y2', height - 22);
    g.selectAll('text.tick').data(ticks).join('text').attr('x', (d) => x(d)).attr('y', height - 6).attr('text-anchor', 'middle').text((d) => TI.dayLabel(d));
    const tip = TI.tip(box);
    list.forEach((r, i) => {
      const y0 = 6 + i * rowH, y = d3.scaleLinear([0, 1], [y0 + rowH - 8, y0 + 2]);
      g.append('text').attr('class', 'ti-lbl').attr('x', lw - 8).attr('y', y0 + rowH / 2).attr('dy', '0.35em').attr('text-anchor', 'end').text(pair(r));
      g.append('line').attr('class', 'ti-ctx-amber').attr('x1', lw).attr('x2', w - vw - 8).attr('y1', y(0.3)).attr('y2', y(0.3));
      const pts = TI.list(r.series).filter((p) => Array.isArray(p) && p[1] != null).map((p) => [x(TI.parseDay(p[0])), y(p[1]), p]);
      g.append('path').attr('class', 'ti-ctx-line').attr('d', d3.line()(pts.map((p) => [p[0], p[1]])));
      g.selectAll(null).data(pts).join('circle').attr('class', 'ti-ctx-pt').attr('cx', (p) => p[0]).attr('cy', (p) => p[1]).attr('r', 2.2)
        .on('mousemove', (ev, p) => { const [mx, my] = d3.pointer(ev, box); tip.show(`${pair(r)} · ${p[2][0]}`, [{ text: `Temperature ${d3.format('.2f')(p[2][1])}` }, { text: `${TI.f.int(p[2][2])} articles` }], mx, my); })
        .on('mouseleave', () => tip.hide());
      g.append('text').attr('class', 'ti-lbl ti-ctx-val').attr('x', w - vw).attr('y', y0 + rowH / 2).attr('dy', '0.35em').text(r.t7 == null ? '—' : d3.format('.2f')(r.t7) + (r.delta7 == null ? '' : (r.delta7 >= 0.05 ? ' ▲' : r.delta7 <= -0.05 ? ' ▼' : '')));
    });
  }

  X.theaterCards = (sec) => {
    const tl = sec.querySelector('#tbl-lanes');
    if (tl && TI.tableState(tl, ['live_lanes'])) {
      const rows = TI.rows('live_lanes'), m = lanesMeta();
      const cnt = sec.querySelector('#lanes-asof');
      if (cnt) cnt.textContent = m.latest ? `rows to ${m.latest}${m.age != null ? `, ${m.age} days old` : ''}` : '';
      TI.table(tl, rows, [
        { field: 'conflict', label: 'Pair', link: 'bridge_url', get: pair, cls: 'ti-wrap' },
        { field: 'theater', label: 'Theater', get: (r) => theatersOf(r).map((t) => t.short || t.name).join(', ') || 'None', cls: 'ti-wrap', hideSm: true },
        { field: 't7', label: '7-day mean', num: true, fmt: 'dec2' },
        { field: 't7_prev', label: 'Prior 7', num: true, fmt: 'dec2', hideSm: true },
        { field: 'delta7', label: 'Change', num: true, get: (r) => (r.delta7 == null ? null : signed(r.delta7)) },
        { field: 'material_conflict_share', label: 'Material conflict, latest day', num: true, fmt: 'pct', hideSm: true },
        { field: 'date', label: 'Latest row', fmt: 'date', cls: 'ti-nowrap', hideSm: true },
        { field: 'daily_title', label: 'Latest daily page (AI-compiled)', link: 'daily_url', cls: 'ti-wrap', hideSm: true },
      ], { sort: 't7', dir: 'desc', empty: 'Lanes returned no pairs.', onClick: (r) => { const t = theatersOf(r)[0]; if (t && TI._selectTheater) { TI._selectTheater(t.theater_id); sec.querySelector('#theater-board').scrollIntoView({ block: 'start' }); } } });
    }
    const ch = sec.querySelector('#lanes-chart');
    if (ch && TI.chartState(ch, ['live_lanes'])) lanesChart(ch, TI.rows('live_lanes'));
    const to = sec.querySelector('#tbl-ofac');
    if (to && TI.tableState(to, ['live_ofac'])) {
      const sp = ofacSpan(), cnt = sec.querySelector('#ofac-span');
      if (cnt) cnt.textContent = sp.n ? `${sp.n} newest, ${sp.from} to ${sp.to}` : '';
      TI.table(to, TI.rows('live_ofac'), [
        { field: 'date', label: 'Date', fmt: 'date', cls: 'ti-nowrap' },
        { field: 'title', label: 'Action', link: 'url', cls: 'ti-wrap' },
        { field: 'programs', label: 'Programs named', cls: 'ti-wrap' },
        { field: 'actions', label: 'Action types', cls: 'ti-wrap', hideSm: true },
        { field: 'theaters', label: 'Theater', get: (r) => tname(r.theaters), cls: 'ti-wrap', hideSm: true },
        { field: 'added', label: 'SDN added', num: true, get: (r) => (r.page_read ? r.added : null) },
        { field: 'removed', label: 'Removed', num: true, get: (r) => (r.page_read ? r.removed : null), hideSm: true },
        { field: 'vessels', label: 'Vessels', num: true, get: (r) => (r.page_read ? TI.list(r.vessels).filter((x) => x && x.action !== 'removed').length : null), hideSm: true },
        { field: 'category', label: 'OFAC category', hideSm: true },
        { field: 'cyber', label: 'Cyber' },
      ], { sort: 'date', dir: 'desc', empty: 'OFAC listed no recent actions.' });
    }
    X.ofacListings(sec);
    if (TI.intel) TI.intel.theaterCards(sec);
  };

  // ---------------------------------------------------------------- sources page: the OSINT toolkit
  X.sourcesCards = (sec) => {
    if (TI.intel) TI.intel.sourcesCards(sec);
    const tt = sec.querySelector('#tbl-osint-tools');
    if (!tt || !TI.tableState(tt, ['osint_tools'])) return;
    const rank = { Ingested: 0, Linked: 1, Reference: 2, 'Held for decision': 3 };
    const rows = TI.rows('osint_tools').slice().sort((x, y) => (rank[x.status] ?? 9) - (rank[y.status] ?? 9) || x.tool.localeCompare(y.tool));
    TI.table(tt, rows, [
      { field: 'tool', label: 'Tool', link: 'url', cls: 'ti-nowrap' },
      { field: 'category', label: 'Category', hideSm: true },
      { field: 'purpose', label: 'What it gives an analyst', cls: 'ti-wrap' },
      { field: 'access', label: 'Access', cls: 'ti-wrap', hideSm: true },
      { field: 'status', label: 'Status', attr: { 'data-status': (r) => r.status } },
      { field: 'dashboard_use', label: 'Use here', cls: 'ti-wrap' },
      { field: 'limits', label: 'Limits', cls: 'ti-wrap', hideSm: true },
      { field: 'verified', label: 'Checked', link: 'library', cls: 'ti-wrap', hideSm: true },
    ], { empty: 'No tools listed.' });
  };
})();
