/* World threat map: a projected vector map (bundled d3-geo + topojson-client + world-atlas 110m). The base
   shading switches between vertical-calibrated ThreatCon, ransomware leak-site claims, live GDELT armed-conflict
   intensity and reported hostile infrastructure per country. Independent overlays add GDELT conflict-event dots
   (with an hour window and playback) and EIA oil-transit chokepoints; pew.js draws the live cyber layers, conflict
   arcs, outages and attribution arcs on canvases over the SVG, kept in step with its zoom. Theater markers keep their
   screen size through zoom and pan. With Globe on, globe.js draws the same shading, theaters and live layers on an
   orthographic projection instead. No tiles, no network. */
(() => {
  const { h, v } = TI;
  let base = 'theater';          // 'theater' | 'ransomware' | 'conflict' | 'infra'
  let showCells = false;         // GDELT conflict-event dots overlay
  let showChokes = false;        // oil-transit chokepoints overlay
  let labels = true;
  let hourWin = null;            // hours of the GDELT window currently shown (null = all)
  let playing = null;            // playback timer
  let zt = null;                 // last zoom transform
  let iso2num = null;
  const LV_NAME = ['', 'NORMAL', 'GUARDED', 'ELEVATED', 'HIGH', 'CRITICAL'];

  const libsReady = () => window.d3geo && window.topojson && window.TI_WORLD && window.TI_NUM2ISO;
  const reducedMotion = () => !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  function invert() {
    if (iso2num) return iso2num;
    iso2num = {};
    for (const [num, a2] of Object.entries(window.TI_NUM2ISO)) iso2num[a2] = num;
    return iso2num;
  }
  const lvColor = (lv) => (lv >= 5 ? 'var(--ti-crit)' : lv >= 4 ? 'var(--ti-high)' : lv >= 3 ? 'var(--ti-elev)' : lv >= 2 ? 'var(--ti-guard)' : 'var(--ti-norm)');
  const vertical = () => dash.params().vertical || 'financial';
  const vrtRow = () => (TI.ready('verticals') ? TI.rows('verticals').find((x) => x.vertical_id === vertical()) : null);

  function claimRows() {
    if (TI.ready('live_rw_by_country') && TI.rows('live_rw_by_country').length) return { live: true, rows: TI.rows('live_rw_by_country') };
    if (TI.ready('ransomware_countries')) return { live: false, rows: TI.rows('ransomware_countries').map((r) => ({ country: r.country, claims: r.claims_last_90d, prior: r.claims_prior_90d })) };
    return { live: false, rows: [] };
  }
  const gdMeta = () => (TI.ready('live_gdelt_meta') ? TI.rows('live_gdelt_meta')[0] : null);
  const gdCountry = () => (TI.ready('live_gdelt_by_country') ? TI.rows('live_gdelt_by_country') : []);
  const gdCells = () => (TI.ready('live_gdelt_cells') ? TI.rows('live_gdelt_cells') : []);
  const chokes = () => (TI.ready('chokepoints') ? TI.rows('chokepoints') : []);
  const gdReady = () => TI.ready('live_gdelt') && TI.rows('live_gdelt').some((r) => r.kind !== 'meta');
  const infraByCc = () => (TI.ready('live_threatmap') ? TI.rows('live_threatmap').filter((r) => r.kind === 'country') : []);
  const outagesNow = () => (TI.ready('live_outages') ? TI.rows('live_outages').filter((r) => r.kind === 'outage' && r.ongoing) : []);
  const attacksPlaced = () => (TI.ready('live_cyberattacks') ? TI.rows('live_cyberattacks').filter((r) => r.cc) : []);

  function drawMap(sec) {
    const box = sec.querySelector('#ti-map');
    const theaters = TI.ready('theaters') ? TI.rows('theaters') : [];
    if (!theaters.length) { if (TI.failed('theaters')) TI.failLine(box); else { TI.clear(box); box.classList.add('dash-skeleton'); } return; }
    if (!libsReady()) { TI.clear(box); box.append(h('div', { class: 'ti-empty', text: 'Map libraries did not load.' })); return; }
    box.classList.remove('dash-skeleton');

    const calibrated = TI.ready('theater_calibrated') ? TI.rows('theater_calibrated') : [];
    const calMap = new Map(calibrated.filter((r) => r.vertical_id === vertical()).map((r) => [r.theater_id, r]));
    const levelOf = (t) => (calMap.get(t.theater_id) || {}).calibrated || t.threatcon;

    const i2n = invert();
    const numLevel = {}, numTheaters = {};
    for (const t of theaters) {
      const lv = levelOf(t);
      for (const a2 of String(t.countries || '').split(',').filter(Boolean)) {
        const num = i2n[a2];
        if (!num) continue;
        numLevel[num] = Math.max(numLevel[num] || 0, lv);
        (numTheaters[num] = numTheaters[num] || []).push(t.short || t.name);
      }
    }
    const { live, rows: rwRows } = claimRows();
    const numClaims = {};
    let maxClaims = 1;
    for (const r of rwRows) { const num = i2n[r.country]; if (num) { numClaims[num] = (numClaims[num] || 0) + r.claims; maxClaims = Math.max(maxClaims, numClaims[num]); } }

    // Conflict choropleth: events per country over the live window, with a surge flag from the baseline ratio.
    const cRows = gdCountry();
    const numConflict = {}, numRatio = {}, numSurge = {};
    let maxConflict = 1;
    for (const r of cRows) { const num = i2n[r.country]; if (num) { numConflict[num] = r.events; numRatio[num] = r.ratio; numSurge[num] = r.surge === 'Yes'; maxConflict = Math.max(maxConflict, r.events); } }

    // Reported hostile infrastructure per country (collector counts every listed host, mapped or not).
    const numInfra = {};
    let maxInfra = 1;
    for (const r of infraByCc()) { const num = i2n[r.cc]; if (num) { numInfra[num] = r; maxInfra = Math.max(maxInfra, r.total || 0); } }
    const numOut = {};
    for (const o of outagesNow()) { const num = i2n[o.cc]; if (num) (numOut[num] = numOut[num] || []).push(o); }
    const numAtk = {};
    for (const r of attacksPlaced()) { const num = i2n[r.cc]; if (num) numAtk[num] = (numAtk[num] || 0) + 1; }

    const W = Math.max(320, box.clientWidth || 800);
    const narrow = W < 700;
    const wall = TI.pew && TI.pew.wall();
    const globe = !!(TI.globe && TI.globe.on());
    const Hh = wall ? Math.max(360, Math.round(window.innerHeight - (narrow ? 210 : 150)))
      : narrow ? Math.round(W * (globe ? 0.9 : 0.66)) : Math.round(Math.min(globe ? 640 : 600, Math.max(320, W * (globe ? 0.6 : 0.52))));
    const ms = narrow ? 0.62 : 1;
    TI.clear(box);
    const land = window.topojson.feature(window.TI_WORLD, window.TI_WORLD.objects.countries);
    const borders = window.topojson.mesh(window.TI_WORLD, window.TI_WORLD.objects.countries, (a, b) => a !== b);
    const cname = (num) => window.TI_ISONAME[window.TI_NUM2ISO[num]] || 'Unknown';

    // Tooltips shared by the flat map and the globe.
    function countryTip(d) {
      const lines = [];
      if (numLevel[d.id]) lines.push({ text: `Theater level ${numLevel[d.id]} ${LV_NAME[numLevel[d.id]]}`, color: lvColor(numLevel[d.id]) });
      if (numTheaters[d.id]) lines.push({ text: numTheaters[d.id].join(', ') });
      if (base === 'conflict' || numConflict[d.id]) lines.push({ text: `${TI.f.int(numConflict[d.id] || 0)} conflict events${numRatio[d.id] != null ? ` (${numRatio[d.id]}x baseline${numSurge[d.id] ? ', surge' : ''})` : ''}`, color: numSurge[d.id] ? 'var(--ti-crit)' : null });
      lines.push({ text: `${TI.f.int(numClaims[d.id] || 0)} leak-site claims (${live ? 'live set' : '90 days'})` });
      const inf = numInfra[d.id];
      if (inf && inf.total) lines.push({ text: `Hostile infrastructure: ${[inf.c2 ? TI.f.int(inf.c2) + ' C2' : '', inf.ioc ? TI.f.int(inf.ioc) + ' IOC endpoints' : '', inf.src ? TI.f.int(inf.src) + ' scanning sources' : '', inf.url ? TI.f.int(inf.url) + ' malware hosts' : ''].filter(Boolean).join(', ')}`, color: base === 'infra' ? 'var(--pew-ioc)' : null });
      for (const o of numOut[d.id] || []) lines.push({ text: `Internet disruption ongoing (${o.datasource || 'IODA'}${o.level ? ', ' + o.level : ''})`, color: 'var(--pew-out)' });
      if (numAtk[d.id]) lines.push({ text: `${TI.f.int(numAtk[d.id])} press-reported cyberattack${numAtk[d.id] > 1 ? 's' : ''} (ransomware.live, recent list)`, color: 'var(--pew-atk)' });
      return { head: cname(d.id), lines };
    }
    const liveTheater = (t) => (TI.ready('live_gdelt_theaters') ? TI.rows('live_gdelt_theaters').find((x) => x.theater_id === t.theater_id) : null);
    function theaterTip(t) {
      const lv = levelOf(t), c = calMap.get(t.theater_id), ct = liveTheater(t);
      const lines = [{ text: `ThreatCon ${lv} ${LV_NAME[lv]}${c && c.calibrated !== c.base ? ` (base ${c.base}, weight ${c.weight})` : ''}`, color: lvColor(lv) }, { text: `Trend: ${t.trend}` }];
      if (ct && ct.events) lines.push({ text: `${TI.f.int(ct.events)} conflict events, 24h${ct.ratio != null ? ` (${ct.ratio}x${ct.surge === 'Yes' ? ', surge' : ''})` : ''}`, color: ct.surge === 'Yes' ? 'var(--ti-crit)' : null });
      lines.push({ text: 'Click for the assessment' });
      return { head: t.name, lines };
    }
    const openTheater = (t) => { TI.go('theaters'); if (TI._selectTheater) TI._selectTheater(t.theater_id); };

    const panel = TI.resolve('var(--color-panel)', box);
    const hi = TI.resolve(TI.color(0), box);
    const claimFill = window.d3.scaleSequential([0, Math.sqrt(maxClaims)], window.d3.interpolateRgb(panel, hi));
    const conflictFill = window.d3.scaleSequential([0, Math.sqrt(maxConflict)], window.d3.interpolateRgb(panel, TI.resolve('var(--ti-crit)', box)));
    const infraFill = window.d3.scaleSequential([0, Math.log10(1 + maxInfra)], window.d3.interpolateRgb(panel, TI.resolve('var(--pew-ioc)', box)));
    const fillFor = (d) => {
      if (base === 'ransomware') { const c = numClaims[d.id]; return c ? claimFill(Math.sqrt(c)) : 'var(--color-panel)'; }
      if (base === 'conflict') { const c = numConflict[d.id]; return c ? conflictFill(Math.sqrt(c)) : 'var(--color-panel)'; }
      if (base === 'infra') { const c = numInfra[d.id]; return c && c.total ? infraFill(Math.log10(1 + c.total)) : 'var(--color-panel)'; }
      const lv = numLevel[d.id];
      return lv ? `color-mix(in srgb, ${lvColor(lv)} 55%, var(--color-panel))` : 'var(--color-panel)';
    };

    if (globe) {
      const marks = theaters.filter((t) => t.lon != null && t.lat != null && (t.lon || t.lat)).sort((a, b) => levelOf(a) - levelOf(b))
        .map((t) => ({ t, lon: t.lon, lat: t.lat, lv: levelOf(t), color: lvColor(levelOf(t)), label: t.short || t.name }));
      const gtip = TI.tip(box);
      TI.globe.render(box, { W, H: Hh, features: land.features, borders, fillFor, theaters: marks, tip: () => gtip, theaterTip, countryTip, onTheater: openTheater });
      box._resetZoom = () => TI.globe.reset();
      box._relabel = () => {};
      box._flyTo = (lon, lat) => TI.globe.flyTo(lon, lat);
      footer();
      return;
    }

    const svg = window.d3.select(box).append('svg').attr('width', '100%').attr('viewBox', `0 0 ${W} ${Hh}`).attr('height', Hh)
      .attr('role', 'img').attr('aria-label', 'World threat map').style('touch-action', 'none');
    const fitTo = narrow
      ? { type: 'MultiPoint', coordinates: [[-112, -8], [146, -8], [-112, 60], [146, 60]] }
      : { type: 'FeatureCollection', features: land.features.filter((f) => f.id !== '010') };
    const proj = window.d3geo.geoNaturalEarth1().fitExtent([[8, 8], [W - 8, Hh - 8]], fitTo);
    const path = window.d3geo.geoPath(proj);

    const zoomLayer = svg.append('g');
    zoomLayer.append('path').attr('d', path({ type: 'Sphere' })).attr('fill', 'var(--color-bg)').attr('stroke', 'var(--color-border-line)').attr('stroke-width', 0.8).attr('vector-effect', 'non-scaling-stroke');
    zoomLayer.append('path').attr('d', path(window.d3geo.geoGraticule10())).attr('fill', 'none').attr('stroke', 'var(--cds-chart-grid)').attr('stroke-width', 0.5).attr('vector-effect', 'non-scaling-stroke');

    const tip = TI.tip(box);
    zoomLayer.append('g').selectAll('path').data(land.features).join('path')
      .attr('class', 'ti-ctry').attr('d', path).attr('vector-effect', 'non-scaling-stroke')
      .attr('fill', fillFor).attr('stroke', (d) => (base === 'conflict' && numSurge[d.id] ? 'var(--ti-crit)' : 'none')).attr('stroke-width', (d) => (base === 'conflict' && numSurge[d.id] ? 1.2 : 0))
      .on('mousemove', (ev, d) => {
        const [mx, my] = window.d3.pointer(ev, box);
        const t = countryTip(d);
        tip.show(t.head, t.lines, mx, my);
      })
      .on('mouseleave', () => tip.hide());
    zoomLayer.append('path').attr('d', path(borders)).attr('fill', 'none').attr('stroke', 'var(--color-border-line)').attr('stroke-width', 0.6).attr('vector-effect', 'non-scaling-stroke').style('pointer-events', 'none');

    // Conflict-event dots (inside the zoom layer so they pan and scale with the map).
    if (showCells && gdReady()) {
      const cells = gdCells();
      const win = hourWin == null ? Infinity : hourWin;
      const shown = cells.filter((c) => c.h < win);
      const maxN = Math.max(1, window.d3.max(shown, (c) => c.n) || 1);
      const rad = window.d3.scaleSqrt([0, maxN], [1.4, 10]);
      const cl = zoomLayer.append('g').attr('class', 'ti-conflict');
      cl.selectAll('circle').data(shown).join('circle')
        .attr('cx', (c) => proj([c.lon, c.lat])[0]).attr('cy', (c) => proj([c.lon, c.lat])[1])
        .attr('r', (c) => rad(c.n)).attr('fill', 'var(--ti-crit)').attr('fill-opacity', 0.45).attr('stroke', 'var(--ti-crit)').attr('stroke-width', 0.5).attr('vector-effect', 'non-scaling-stroke')
        .on('mousemove', (ev, c) => { const [mx, my] = window.d3.pointer(ev, box); tip.show('Conflict cell', [{ text: `${TI.f.int(c.n)} events, ${TI.f.int(c.m)} mentions` }, { text: `${c.h === 0 ? 'last hour' : c.h + ' h ago'}` }], mx, my); })
        .on('mouseleave', () => tip.hide());
    }

    // Chokepoint markers (screen-fixed diamonds), re-placed with the transform.
    const ckPlaced = [];
    if (showChokes) {
      const ckg = svg.append('g').attr('class', 'ti-chokes');
      for (const c of chokes()) {
        const p = proj([c.lon, c.lat]);
        if (!p) continue;
        const g = ckg.append('g').style('cursor', 'help');
        g.append('path').attr('d', 'M0,-6 L6,0 L0,6 L-6,0 Z').attr('fill', 'var(--color-warn)').attr('stroke', 'var(--color-bg)').attr('stroke-width', 1).attr('transform', `scale(${ms})`);
        const lab = g.append('text').attr('class', 'ti-choke-label').attr('x', 8 * ms).attr('dy', '0.35em').text(c.name.replace(/ \(.*/, '').replace('Strait of ', '').replace(' and SUMED Pipeline', ''));
        g.on('mousemove', (ev) => {
          const [mx, my] = window.d3.pointer(ev, box);
          tip.show(c.name, [{ text: `${c.flow_1h25} million b/d (1H25), ${c.flow_2023} in 2023` }, { text: c.share }, c.note ? { text: c.note } : null, { text: 'EIA, updated ' + c.as_of }].filter(Boolean), mx, my);
        }).on('mouseleave', () => tip.hide());
        ckPlaced.push({ g, p });
      }
    }

    // Theater markers.
    const mk = svg.append('g');
    const placed = [];
    const order = theaters.slice().sort((a, b) => levelOf(a) - levelOf(b));
    for (const t of order) {
      if (t.lon == null || t.lat == null || (!t.lon && !t.lat)) continue;
      const p = proj([t.lon, t.lat]);
      if (!p) continue;
      const lv = levelOf(t);
      const c = calMap.get(t.theater_id);
      const g = mk.append('g').attr('class', 'ti-map-marker').style('cursor', 'pointer')
        .attr('tabindex', 0).attr('role', 'button').attr('aria-label', `${t.name}, level ${lv}`)
        .attr('data-source', 'theater_calibrated').attr('data-field', 'calibrated').attr('data-where', c ? TI.where({ key: c.key }) : null);
      if (t.trend === 'Escalating' || t.trend === 'Rising') {
        g.append('circle').attr('r', (9 + lv * 2) * ms).attr('fill', 'none').attr('stroke', lvColor(lv)).attr('stroke-width', 1).attr('stroke-dasharray', '2 3').attr('opacity', 0.9);
      }
      g.append('circle').attr('r', (4 + lv * 1.7) * ms).attr('fill', lvColor(lv)).attr('fill-opacity', 0.28).attr('stroke', lvColor(lv)).attr('stroke-width', 1.5);
      g.append('circle').attr('r', 2.6).attr('fill', lvColor(lv));
      const r = (4 + lv * 1.7) * ms;
      const lab = g.append('text').attr('class', 'ti-map-label').attr('x', r + 4).attr('dy', '0.35em').text(t.short || t.name);
      const lw = lab.node().getComputedTextLength ? lab.node().getComputedTextLength() : (t.short || t.name).length * 6.5;
      const open = () => openTheater(t);
      g.on('mousemove', (ev) => {
        const [mx, my] = window.d3.pointer(ev, box);
        const d = theaterTip(t);
        tip.show(d.head, d.lines, mx, my);
      }).on('mouseleave', () => tip.hide()).on('click', open)
        .on('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } });
      placed.push({ g, p, lab, lw, r, lv });
    }

    const place = (tr) => {
      for (const m of ckPlaced) { const [x, y] = tr.apply(m.p); m.g.attr('transform', `translate(${x},${y})`); }
      const boxes = [];
      const hit = (b) => b.x0 < 0 || b.x1 > W || b.y0 < 0 || b.y1 > Hh || boxes.some((o) => b.x0 < o.x1 && b.x1 > o.x0 && b.y0 < o.y1 && b.y1 > o.y0);
      for (const m of placed) { const [x, y] = tr.apply(m.p); m.x = x; m.y = y; m.g.attr('transform', `translate(${x},${y})`); boxes.push({ x0: x - m.r, x1: x + m.r, y0: y - m.r, y1: y + m.r }); }
      for (const m of placed.slice().sort((a, b) => b.lv - a.lv)) {
        if (!labels) { m.lab.attr('display', 'none'); continue; }
        const hh = 13;
        const slots = [
          { x: m.r + 4, y: 0, anchor: 'start', b: { x0: m.x + m.r + 3, x1: m.x + m.r + 5 + m.lw, y0: m.y - hh / 2, y1: m.y + hh / 2 } },
          { x: -m.r - 4, y: 0, anchor: 'end', b: { x0: m.x - m.r - 5 - m.lw, x1: m.x - m.r - 3, y0: m.y - hh / 2, y1: m.y + hh / 2 } },
          { x: 0, y: -m.r - 8, anchor: 'middle', b: { x0: m.x - m.lw / 2, x1: m.x + m.lw / 2, y0: m.y - m.r - 8 - hh / 2, y1: m.y - m.r - 8 + hh / 2 } },
          { x: 0, y: m.r + 9, anchor: 'middle', b: { x0: m.x - m.lw / 2, x1: m.x + m.lw / 2, y0: m.y + m.r + 9 - hh / 2, y1: m.y + m.r + 9 + hh / 2 } },
        ];
        const s = slots.find((c) => !hit(c.b));
        if (!s) { m.lab.attr('display', 'none'); continue; }
        m.lab.attr('display', null).attr('x', s.x).attr('y', s.y).attr('text-anchor', s.anchor);
        boxes.push(s.b);
      }
    };
    box._relabel = () => place(zt || window.d3.zoomIdentity);

    const zoom = window.d3.zoom().scaleExtent([1, 12]).translateExtent([[0, 0], [W, Hh]]).extent([[0, 0], [W, Hh]])
      .on('zoom', (ev) => { zt = ev.transform; zoomLayer.attr('transform', ev.transform); place(ev.transform); tip.hide(); if (TI.pew) TI.pew.transform(ev.transform); });
    svg.call(zoom);
    const start = zt || window.d3.zoomIdentity;
    svg.call(zoom.transform, start);
    place(start);
    box._resetZoom = () => svg.transition().duration(450).call(zoom.transform, window.d3.zoomIdentity);
    // Centre a point at a zoom level (the ticker and the HUD fly here), clamped by the zoom's translate extent.
    box._flyTo = (lon, lat, k = 4) => {
      const p = proj([lon, lat]);
      if (!p) return;
      const t = window.d3.zoomIdentity.translate(W / 2 - k * p[0], Hh / 2 - k * p[1]).scale(k);
      svg.transition().duration(reducedMotion() ? 0 : 900).call(zoom.transform, t);
    };
    if (TI.pew) TI.pew.attach({ box, W, H: Hh, proj, transform: start, tip: () => tip, flyTo: box._flyTo });
    footer();

    // Legend and calibration note under the map (flat map and globe).
    function footer() {
    const legend = h('div', { class: 'ti-legend' });
    if (base === 'theater') {
      for (let lv = 5; lv >= 1; lv--) { const sw = h('span', { class: 'ti-sw' }); sw.style.background = lvColor(lv); legend.append(h('span', {}, sw, LV_NAME[lv].charAt(0) + LV_NAME[lv].slice(1).toLowerCase())); }
      legend.append(h('span', {}, 'Dashed ring: escalating'));
    } else if (base === 'ransomware') {
      const ramp = h('span', { class: 'ti-ramp' }); ramp.style.background = `linear-gradient(90deg, ${panel}, ${hi})`;
      legend.append(h('span', {}, '0', ramp, TI.f.int(maxClaims) + ' claims'));
      legend.append(h('span', {}, live ? 'Live leak-site claims by victim country' : 'Leak-site claims, 90-day snapshot'));
    } else if (base === 'infra') {
      const ramp = h('span', { class: 'ti-ramp' }); ramp.style.background = `linear-gradient(90deg, ${panel}, ${TI.resolve('var(--pew-ioc)', box)})`;
      legend.append(h('span', {}, '0', ramp, TI.f.int(maxInfra) + ' hosts (log scale)'));
      legend.append(h('span', {}, 'Reported C2, IOC endpoints, scanning sources and malware hosts geolocated to each country'));
    } else {
      const ramp = h('span', { class: 'ti-ramp' }); ramp.style.background = `linear-gradient(90deg, ${panel}, ${TI.resolve('var(--ti-crit)', box)})`;
      legend.append(h('span', {}, '0', ramp, TI.f.int(maxConflict) + ' events, 24h'));
      legend.append(h('span', {}, 'Red border: surge against the 48h baseline'));
    }
    if (showCells && !globe) legend.append(h('span', {}, 'Dots: conflict-event cells'));
    if (showChokes && !globe) { const sw = h('span', { class: 'ti-sw', style: 'transform:rotate(45deg)' }); sw.style.background = 'var(--color-warn)'; legend.append(h('span', {}, sw, 'Oil chokepoints')); }
    if (globe) legend.append(h('span', {}, 'Globe: drag to turn, scroll or pinch to zoom, arrow keys and +/- on the keyboard'));
    const vrt = vrtRow();
    box.append(h('div', { class: 'ti-map-foot' }, legend, h('span', { class: 'ti-cap ti-muted' }, 'Levels calibrated for ' + (vrt ? vrt.name : vertical()))));
    }
  }

  // Time control row: shown only when a GDELT layer is active.
  function drawTime(sec) {
    const row = sec.querySelector('#map-time');
    if (!row) return;
    const active = (showCells || base === 'conflict') && gdReady();
    row.hidden = !active;
    if (!active) { stopPlay(); return; }
    const meta = gdMeta() || { hours: 24, events: 0, latest: '' };
    const max = meta.hours || 24;
    if (hourWin == null || hourWin > max) hourWin = max;
    const slider = sec.querySelector('#map-hours');
    slider.max = String(max); slider.value = String(hourWin);
    const lbl = sec.querySelector('#map-hours-label');
    if (lbl) lbl.textContent = hourWin >= max ? `last ${max}h (all)` : `last ${hourWin}h`;
    const note = sec.querySelector('#map-time-note');
    if (note) note.textContent = `${TI.f.int(meta.events)} armed-conflict events, ${meta.actors === 'armed' ? 'armed actors' : 'all actors'}; latest export ${String(meta.latest).slice(11, 16)}Z`;
  }
  function stopPlay() { if (playing) { clearInterval(playing); playing = null; const b = document.getElementById('map-play'); if (b) b.textContent = 'Play'; } }

  function drawCal(sec) {
    const el = sec.querySelector('#map-cal');
    const vrt = vrtRow();
    const vn = sec.querySelector('#map-vname');
    if (vn) vn.textContent = vrt ? vrt.name.toLowerCase() : 'the selected vertical';
    const vs = sec.querySelector('#map-vsummary');
    if (vs && vrt) vs.textContent = vrt.summary + ' Each theater ThreatCon is multiplied by this vertical\'s weight, rounded and held between 1 and 5; the weights are an analyst lens set in the build.';
    if (TI.failed('theater_calibrated', 'theaters')) { TI.failLine(el); return; }
    if (!TI.ready('theater_calibrated', 'theaters')) { TI.clear(el); el.classList.add('dash-skeleton'); return; }
    el.classList.remove('dash-skeleton');
    TI.clear(el);
    const T = TI.index(TI.rows('theaters'), 'theater_id');
    const ct = TI.ready('live_gdelt_theaters') ? TI.index(TI.rows('live_gdelt_theaters'), 'theater_id') : new Map();
    const rows = TI.rows('theater_calibrated').filter((r) => r.vertical_id === vertical())
      .sort((a, b) => b.calibrated - a.calibrated || b.shifted - a.shifted || String((T.get(a.theater_id) || {}).name).localeCompare(String((T.get(b.theater_id) || {}).name)));
    for (const r of rows) {
      const t = T.get(r.theater_id) || { name: r.theater_id };
      const w = { key: r.key };
      const d = r.shifted > 0 ? 'up' : r.shifted < 0 ? 'down' : '';
      const g = ct.get(r.theater_id);
      const cell = h('button', { class: 'ti-cal-cell', type: 'button', 'data-lv': String(r.calibrated), style: 'text-align:left;font:inherit;color:inherit;cursor:pointer' },
        h('span', { class: 'ti-cal-name', text: t.name }),
        h('span', {},
          h('span', { class: TI.lvClass(r.calibrated) }, v('span', 'theater_calibrated', 'calibrated', w, String(r.calibrated)), ' ', LV_NAME[r.calibrated]),
          ' ', h('span', { class: 'ti-muted' }, 'base ', v('span', 'theater_calibrated', 'base', w, String(r.base)), ' x ', v('span', 'theater_calibrated', 'weight', w, String(r.weight))),
          d ? h('span', { class: 'ti-delta', 'data-d': d }, ' ', d === 'up' ? '▲' : '▼', ' ', v('span', 'theater_calibrated', 'shifted', w, (r.shifted > 0 ? '+' : '') + r.shifted)) : null),
        g && g.events ? h('span', { class: 'ti-cap ti-muted' }, v('span', 'live_gdelt_theaters', 'events', { theater_id: r.theater_id }, TI.f.int(g.events)), ' conflict events, 24h',
          g.surge === 'Yes' ? h('span', { class: 'ti-delta', 'data-d': 'up' }, ' surge ', v('span', 'live_gdelt_theaters', 'ratio', { theater_id: r.theater_id }, g.ratio + 'x')) : (g.ratio != null ? h('span', {}, ' (', v('span', 'live_gdelt_theaters', 'ratio', { theater_id: r.theater_id }, g.ratio + 'x'), ')') : null)) : null);
      cell.addEventListener('click', () => { TI.go('theaters'); if (TI._selectTheater) TI._selectTheater(r.theater_id); });
      el.append(cell);
    }
  }

  function drawCountries(sec) {
    const t = sec.querySelector('#tbl-map-rw');
    if (!t) return;
    const basis = sec.querySelector('#map-rw-basis');
    const { live, rows } = claimRows();
    if (!rows.length) { TI.tableState(t, ['ransomware_countries']); return; }
    const boxEl = t.closest('.ti-tbox');
    boxEl.classList.remove('dash-skeleton');
    t.hidden = false;
    if (basis) basis.textContent = live ? 'live set' : '90-day snapshot';
    const src = live ? 'live_rw_by_country' : 'ransomware_countries';
    const list = rows.filter((r) => r.country && r.country !== 'Not identified');
    const cname = (c) => (window.TI_ISONAME && window.TI_ISONAME[c] ? `${window.TI_ISONAME[c]} (${c})` : c);
    const cols = [
      { field: 'country', label: 'Country', get: (r) => cname(r.country) },
      { field: live ? 'claims' : 'claims_last_90d', label: live ? 'Claims' : 'Claims, 90 days', num: true, fmt: 'int', get: (r) => r.claims },
    ];
    if (!live) cols.push({ field: 'claims_prior_90d', label: 'Prior 90', num: true, fmt: 'int', get: (r) => r.prior, hideSm: true });
    if (t._basis !== live) { if (t.tHead) t.tHead.remove(); t._ti = null; t._basis = live; }
    t.setAttribute('data-source', src);
    TI.table(t, list, cols, { sort: cols[1].field, dir: 'desc', limit: 60 });
  }

  // Top conflict events table (live GDELT).
  function drawConflictTable(sec) {
    const t = sec.querySelector('#tbl-map-conflict');
    if (!t) return;
    const card = sec.querySelector('#map-conflict-card');
    if (!gdReady()) { if (card) card.hidden = !TI.rows('live_gdelt') || TI.status('live_gdelt') === 'loading'; if (TI.failed('live_gdelt')) TI.tableState(t, ['live_gdelt']); return; }
    if (card) card.hidden = false;
    if (!TI.tableState(t, ['live_gdelt_events'])) return;
    const cname = (c) => (window.TI_ISONAME && window.TI_ISONAME[c] ? window.TI_ISONAME[c] : c);
    TI.table(t, TI.rows('live_gdelt_events'), [
      { field: 'event', label: 'Type' },
      { field: 'place', label: 'Place', cls: 'ti-wrap' },
      { field: 'country', label: 'Country', get: (r) => cname(r.country), hideSm: true },
      { field: 'actor1', label: 'Actor', get: (r) => [r.actor1, r.actor2].filter(Boolean).join(' / '), cls: 'ti-wrap', hideSm: true },
      { field: 'mentions', label: 'Mentions', num: true, fmt: 'int' },
      { field: 'hours_ago', label: 'Seen', get: (r) => (r.hours_ago === 0 ? '<1h' : r.hours_ago + 'h') },
      { field: 'url', label: 'Source', link: 'url', get: () => 'article' },
    ], { sort: 'mentions', dir: 'desc', limit: 60, empty: 'No armed-conflict events in the live window.' });
  }

  // Tables behind the live cyber layers: every mark on the canvas has its row here.
  function drawCyberTables(sec) {
    const cname = (c) => (window.TI_ISONAME && window.TI_ISONAME[c] ? window.TI_ISONAME[c] : c || '');
    const ago = (iso) => { const t = Date.parse(iso || ''); if (!isFinite(t)) return ''; const m = Math.round((Date.now() - t) / 60000); return m < 60 ? m + ' min' : m < 2880 ? Math.round(m / 60) + ' h' : Math.round(m / 1440) + ' d'; };
    const tf = sec.querySelector('#tbl-map-fam');
    if (tf && TI.tableState(tf, ['live_tm_families'])) {
      TI.table(tf, TI.rows('live_tm_families'), [
        { field: 'family', label: 'Family' },
        { field: 'c2', label: 'C2', num: true, fmt: 'int', hideSm: true },
        { field: 'ioc', label: 'IOC', num: true, fmt: 'int' },
        { field: 'url', label: 'Hosts', num: true, fmt: 'int', hideSm: true },
        { field: 'total', label: 'Listed', num: true, fmt: 'int' },
        { field: 'fresh', label: 'New 24h', num: true, fmt: 'int' },
      ], { sort: 'total', dir: 'desc', limit: 60, empty: 'No families in the live set.',
        onClick: (r) => { const sel = document.getElementById('map-family'); if (sel) { sel.value = r.family; sel.dispatchEvent(new Event('change', { bubbles: true })); } const box = document.getElementById('ti-map'); if (box) box.scrollIntoView({ block: 'nearest' }); } });
    }
    const to = sec.querySelector('#tbl-map-out');
    if (to && TI.tableState(to, ['live_outages'])) {
      TI.table(to, TI.rows('live_outages').filter((r) => r.kind === 'outage'), [
        { field: 'cc', label: 'Country', get: (r) => cname(r.cc) || r.name },
        { field: 'datasource', label: 'Signal' },
        { field: 'level', label: 'Level', hideSm: true },
        { field: 'score', label: 'Score', num: true, fmt: 'int', hideSm: true },
        { field: 'start_at', label: 'Started', get: (r) => String(r.start_at || '').slice(0, 16).replace('T', ' ') + 'Z', cls: 'ti-nowrap' },
        { field: 'ongoing', label: 'Now', get: (r) => (r.ongoing ? 'Ongoing' : r.end_at ? 'Ended ' + ago(r.end_at) + ' ago' : '') },
      ], { sort: 'start_at', dir: 'desc', limit: 80, empty: 'No country-level disruptions in 7 days.',
        onClick: (r) => { if (TI.pew) TI.pew.focus({ outage: r }); } });
    }
    // Press-reported attacks: every row, placed or not, with how its country was settled.
    const tk = sec.querySelector('#tbl-map-atk');
    if (tk && TI.tableState(tk, ['live_cyberattacks'])) {
      const all = TI.rows('live_cyberattacks'), placed = all.filter((r) => r.cc).length;
      const cnt = sec.querySelector('#map-atk-count');
      if (cnt) cnt.textContent = `${TI.f.int(all.length)} reports, ${TI.f.int(placed)} placed`;
      const basis = (r) => (TI.pew && TI.pew.basisText ? TI.pew.basisText(r) : r.cc_basis);
      TI.table(tk, all, [
        { field: 'added', label: 'Listed', cls: 'ti-nowrap' },
        { field: 'victim', label: 'Victim', cls: 'ti-wrap' },
        { field: 'cc', label: 'Country', get: (r) => (r.cc ? cname(r.cc) : 'Unplaced') },
        { field: 'cc_basis', label: 'Basis', get: basis, cls: 'ti-wrap', hideSm: true },
        { field: 'outlet', label: 'Report', link: 'url', get: (r) => r.outlet || 'article', cls: 'ti-wrap' },
        { field: 'claimed_by', label: 'Leak-site match', hideSm: true },
        { field: 'date', label: 'Attack date', cls: 'ti-nowrap', hideSm: true },
      ], { sort: 'added', dir: 'desc', limit: 150, empty: 'ransomware.live listed no recent press-reported attacks.',
        onClick: (r) => { if (TI.pew && r.cc) { TI.pew.focus({ attack: r }); const box = document.getElementById('ti-map'); if (box) box.scrollIntoView({ block: 'nearest' }); } } });
    }
    const ta = sec.querySelector('#tbl-map-att');
    if (ta && TI.tableState(ta, ['live_attrib_pairs'])) {
      TI.table(ta, TI.rows('live_attrib_pairs'), [
        { field: 'o', label: 'Attributed origin', get: (r) => cname(r.o) },
        { field: 't', label: 'Reported victim', get: (r) => cname(r.t) },
        { field: 'n', label: 'Actors', num: true, fmt: 'int' },
        { field: 'actors', label: 'Named actors', get: (r) => TI.list(r.actors, ', ').join(', '), cls: 'ti-wrap', hideSm: true },
      ], { sort: 'n', dir: 'desc', limit: 80, empty: 'The threat-actor cluster did not load.' });
    }
  }

  TI.page('map', (sec) => {
    TI.fillMarks(sec);
    drawMap(sec);
    drawTime(sec);
    drawCal(sec);
    drawCountries(sec);
    drawConflictTable(sec);
    drawCyberTables(sec);
    // Cyber-physical coincidences (37n-cyphys.mjs).
    const tc = sec.querySelector('#tbl-cyphys');
    if (tc && TI.tableState(tc, ['live_cyphys'])) {
      const names = (v) => TI.list(v).map((e) => TI.obj(e).n).filter(Boolean).slice(0, 5).join(', ');
      const rows = (TI.rows('live_cyphys') || []).filter((r) => r.kind === 'country').map((r) => ({ ...r, signals: ['outage', 'conflict', 'cyber'].filter((s) => String(r[s]) === 'true').join(', ') || '—',
        threat: names(r.entities), attributed: names(r.attributed_actors), graph: '#graph?id=country%3A' + r.cc }));
      TI.table(tc, rows, [
        { field: 'name', label: 'Country', link: 'graph' },
        { field: 'elevated', label: 'Signals', num: true },
        { field: 'signals', label: 'Elevated' },
        { field: 'outage_hours', label: 'Outage h', num: true },
        { field: 'conflict_z', label: 'Conflict z', num: true },
        { field: 'cyber_p', label: 'Threat publishers', num: true },
        { field: 'threat', label: 'Named beside it', cls: 'ti-wrap', hideSm: true },
        { field: 'attributed', label: 'Attributed actors named', cls: 'ti-wrap', hideSm: true },
      ], { sort: 'elevated', dir: 'desc', limit: 40, empty: 'No country has an elevated signal in 72 hours.' });
    }
    // On-demand enrichment of one public indicator (intel.js).
    if (TI.intel) TI.intel.enrichCard(sec);
  });
  dash.onData(() => TI.draw('map'));

  TI.root.addEventListener('click', (ev) => {
    const b = ev.target.closest && ev.target.closest('#map-theater, #map-ransomware, #map-conflict, #map-infra, #map-cells, #map-chokes, #map-labels, #map-reset, #map-play');
    if (!b) return;
    const box = document.getElementById('ti-map');
    if (b.id === 'map-reset') { if (box && box._resetZoom) box._resetZoom(); return; }
    if (b.id === 'map-labels') { labels = !labels; b.setAttribute('aria-pressed', String(labels)); if (box && box._relabel) box._relabel(); return; }
    if (b.id === 'map-cells') { showCells = !showCells; b.setAttribute('aria-pressed', String(showCells)); stopPlay(); TI.draw('map'); return; }
    if (b.id === 'map-chokes') { showChokes = !showChokes; b.setAttribute('aria-pressed', String(showChokes)); TI.draw('map'); return; }
    if (b.id === 'map-play') {
      if (playing) { stopPlay(); return; }
      const meta = gdMeta(); const max = (meta && meta.hours) || 24;
      hourWin = 1; b.textContent = 'Pause';
      playing = setInterval(() => { hourWin = hourWin >= max ? 1 : hourWin + 1; TI.draw('map'); }, 650);
      TI.draw('map');
      return;
    }
    // Base choropleth radio.
    base = b.id === 'map-ransomware' ? 'ransomware' : b.id === 'map-conflict' ? 'conflict' : b.id === 'map-infra' ? 'infra' : 'theater';
    for (const id of ['map-theater', 'map-ransomware', 'map-conflict', 'map-infra']) { const el = document.getElementById(id); if (el) el.setAttribute('aria-pressed', String('map-' + base === id)); }
    stopPlay();
    TI.draw('map');
  });
  TI.root.addEventListener('input', (ev) => {
    if (ev.target.id !== 'map-hours') return;
    stopPlay();
    hourWin = +ev.target.value;
    TI.draw('map');
  });
})();
