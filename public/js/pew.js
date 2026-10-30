/* Live cyber and conflict layers for the world map, drawn on two canvases laid over the SVG map and kept in step with
   its zoom. Every mark traces to a reported record:
     C2 servers        abuse.ch Feodo Tracker botnet controllers
     IOC endpoints     abuse.ch ThreatFox ip:port indicators
     Scanning sources  SANS ISC DShield top reported attackers
     Malware hosts     abuse.ch URLhaus hosts serving malware now
     Conflict arcs     GDELT 2.0: where the coder placed Actor 1 to where it placed the action, armed actors, CAMEO 15-20
     Outages           IODA country-level internet disruptions
     Reported attacks  ransomware.live press tracking: attacks disclosed in the news, in the victim's country
     Attribution arcs  MISP galaxy / CFR Cyber Operations Tracker: attributed origin to suspected victim (historical)
     Thermal anomalies NASA FIRMS VIIRS detections in the kinetic theaters over 24 hours; a ring marks a novel 0.1-degree
                       cell (no detection there in the 30 days before) once the collector holds 7 days of cells
   Hostile infrastructure is located by IP geolocation, which places hosting rather than operators, and arcs carry no
   claim of traffic between their ends. A reported attack marks the victim's country only, spread in a spiral around
   the country's centre, with the basis on which threat-feeds settled ransomware.live's free-text country code. Animation is presentation only: a comet runs along an arc, a ring marks a
   record new in the last 24 hours (listed by its source in that window, or first observed by the collector in it once
   the collector has watched for a day), and Replay re-runs the last 24 hours in the order the sources timed it. */
(() => {
  const P = (TI.pew = {});
  const LAYERS = ['c2', 'ioc', 'src', 'url'];
  const NAMES = { c2: 'C2 servers', ioc: 'IOC endpoints', src: 'Scanning sources', url: 'Malware hosts' };
  const SOURCES = { c2: 'abuse.ch Feodo Tracker', ioc: 'abuse.ch ThreatFox', src: 'SANS ISC DShield', url: 'abuse.ch URLhaus' };
  const ROOT = { 15: 'Force posture', 16: 'Reduce relations', 17: 'Coerce', 18: 'Assault', 19: 'Fight', 20: 'Mass violence' };
  const GEO = { 1: 'country centroid', 2: 'US state', 3: 'US city', 4: 'city', 5: 'province' };
  // Admiralty credibility grades as the collector assigns them to mapped hosts (38-lists.mjs).
  const CRED = { 1: 'confirmed by three or more operators', 2: 'probably true, two operators', 3: 'possibly true, the map source alone' };
  const reduced = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  const store = {
    get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage unavailable */ } },
  };
  const DEF = { c2: true, ioc: true, src: true, url: true, attacks: true, flows: true, outages: true, fires: true, attrib: false, singles: false, motion: !reduced, family: '', folded: null };
  const opt = Object.assign({}, DEF, store.get('ti-pew', {}));
  if (reduced && store.get('ti-pew', null) == null) opt.motion = false;
  P.opt = opt;
  const save = () => store.set('ti-pew', opt);

  // ------------------------------------------------------------------ data from the dashboard datasets
  const rows = (id) => (TI.ready(id) ? TI.rows(id) || [] : []);
  P.nodes = () => rows('live_threatmap').filter((r) => r.kind === 'node' && r.lat != null && r.lon != null);
  P.layerStats = () => Object.fromEntries(rows('live_threatmap').filter((r) => r.kind === 'layer').map((r) => [r.layer, r]));
  P.tmMeta = () => rows('live_threatmap').find((r) => r.kind === 'meta') || null;
  P.flows = () => rows('live_gdelt_flows');
  P.outages = () => rows('live_outages').filter((r) => r.kind === 'outage');
  // NASA FIRMS detections kept by the collector (novel cells first), and its areas of interest.
  P.fires = () => rows('live_fires').filter((r) => r.kind === 'fire' && r.lat != null && r.lon != null);
  P.fireAois = () => rows('live_fires').filter((r) => r.kind === 'aoi');
  P.pairs = () => rows('live_attrib_pairs');
  P.actors = () => rows('live_actors').filter((r) => r.kind === 'actor');
  // Press-reported attacks (neon/parts/35-cyber.mjs): every row, and the rows whose country was settled.
  P.attacksAll = () => rows('live_cyberattacks');
  P.attacks = () => P.attacksAll().filter((r) => r.cc);
  // ransomware.live dates its additions by day (UTC here); "fresh" is added today or yesterday.
  const dayUTC = (back) => new Date(Date.now() - back * 864e5).toISOString().slice(0, 10);
  const freshAtk = (r) => !!r.added && r.added >= dayUTC(1);
  const sameAtk = (a, b) => a === b || (a && b && a.victim === b.victim && a.date === b.date && a.url === b.url);
  // Older reports fade: full strength for two days, then 85% to a week, 65% to two weeks, 50% beyond.
  function attackAlpha(r) {
    const age = (Date.parse(dayUTC(0) + 'T00:00:00Z') - Date.parse(r.added + 'T00:00:00Z')) / 864e5;
    return !isFinite(age) ? 0.5 : age <= 1 ? 1 : age <= 7 ? 0.85 : age <= 14 ? 0.65 : 0.5;
  }
  // How the threat-feeds service settled each row's country, in words (the rules are in 35-cyber.mjs).
  const BASIS = {
    'code+domain': () => 'feed code, confirmed by the victim domain',
    'code+outlet': (r) => `feed code ${r.cc_feed}, settled by the outlet's country`,
    'code+title': (r) => `feed code ${r.cc_feed}, settled by the headline`,
    'code-alias': (r) => `feed code ${r.cc_feed} read as ${cname(r.cc)}`,
    'domain-abbrev': (r) => `victim domain; the feed wrote ${r.cc_feed}`,
    domain: () => 'victim domain; no usable feed code',
    'outlet-abbrev': (r) => `outlet's country; the feed wrote ${r.cc_feed}`,
    code: () => 'feed code as given',
    unresolved: (r) => { const cands = TI.list(r.cc_candidates); return cands.length ? `not placed: ${r.cc_feed} could be ${cands.map((c) => cname(c)).join(' or ')}` : `not placed: feed code ${r.cc_feed || 'missing'}`; },
  };
  const basisText = (r) => (BASIS[r.cc_basis] ? BASIS[r.cc_basis](r) : r.cc_basis || '');

  // ------------------------------------------------------------------ colour
  // Computed colours arrive as rgb(), rgba() or, for color-mix() tokens, color(srgb r g b) in 0-1 units.
  const parse = (c) => {
    const s = String(c);
    let m = s.match(/rgba?\(([^)]+)\)/);
    if (m) return m[1].split(/[\s,/]+/).filter(Boolean).slice(0, 3).map(Number);
    m = s.match(/color\(srgb\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)/);
    if (m) return [m[1], m[2], m[3]].map((x) => Math.round(+x * 255));
    return [200, 60, 60];
  };
  let PAL = null;
  function palette(within) {
    const tok = (v) => parse(TI.resolve(v, within));
    const bg = tok('var(--color-bg)');
    const dark = (0.2126 * bg[0] + 0.7152 * bg[1] + 0.0722 * bg[2]) / 255 < 0.42;
    PAL = {
      dark, c2: tok('var(--pew-c2)'), ioc: tok('var(--pew-ioc)'), src: tok('var(--pew-src)'), url: tok('var(--pew-url)'), out: tok('var(--pew-out)'),
      atk: tok('var(--pew-atk)'), fire: tok('var(--pew-fire)'), r15: tok('var(--ti-elev)'), r16: tok('var(--ti-guard)'), r17: tok('var(--ti-high)'), r18: tok('var(--ti-crit)'), r19: tok('var(--ti-crit)'), r20: tok('var(--pew-mass)'),
      fg: tok('var(--color-fg)'), bg: tok('var(--color-bg)'),
      origin: { CN: tok('var(--pew-cn)'), RU: tok('var(--pew-ru)'), IR: tok('var(--pew-ir)'), KP: tok('var(--pew-kp)'), '*': tok('var(--pew-oth)') },
    };
    sprites = new Map();
    return PAL;
  }
  const rgba = (c, a) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;
  const rootColor = (r) => PAL['r' + r] || PAL.r18;
  const originColor = (cc) => PAL.origin[cc] || PAL.origin['*'];
  // Pre-rendered glow sprites, one per colour and size.
  let sprites = new Map();
  function sprite(c, r, glow) {
    const key = c.join(',') + '|' + r + '|' + glow;
    let s = sprites.get(key);
    if (s) return s;
    const R = Math.ceil(r * (glow ? (PAL.dark ? 3 : 2.2) : 1.4)) + 1, cv = document.createElement('canvas'), d = Math.min(2, window.devicePixelRatio || 1);
    cv.width = cv.height = R * 2 * d;
    const g = cv.getContext('2d');
    g.scale(d, d);
    if (glow) {
      const gr = g.createRadialGradient(R, R, 0, R, R, R);
      gr.addColorStop(0, rgba(c, PAL.dark ? 0.42 : 0.26)); gr.addColorStop(0.35, rgba(c, PAL.dark ? 0.16 : 0.09)); gr.addColorStop(1, rgba(c, 0));
      g.fillStyle = gr; g.fillRect(0, 0, R * 2, R * 2);
    }
    g.beginPath(); g.arc(R, R, r, 0, Math.PI * 2);
    g.fillStyle = rgba(c, 0.95); g.fill();
    g.lineWidth = 0.8; g.strokeStyle = PAL.dark ? 'rgba(0,0,0,0.55)' : 'rgba(255,255,255,0.85)'; g.stroke();
    s = { cv, R };
    sprites.set(key, s);
    return s;
  }
  // Diamonds for press-reported attacks; a hollow centre marks one ransomware.live matched to a leak-site claim.
  function gem(c, r, claimed) {
    const key = 'gem|' + c.join(',') + '|' + r + '|' + (claimed ? 1 : 0);
    let s = sprites.get(key);
    if (s) return s;
    const R = Math.ceil(r * (PAL.dark ? 3 : 2.2)) + 1, cv = document.createElement('canvas'), d = Math.min(2, window.devicePixelRatio || 1);
    cv.width = cv.height = R * 2 * d;
    const g = cv.getContext('2d');
    g.scale(d, d);
    const gr = g.createRadialGradient(R, R, 0, R, R, R);
    gr.addColorStop(0, rgba(c, PAL.dark ? 0.4 : 0.24)); gr.addColorStop(0.35, rgba(c, PAL.dark ? 0.14 : 0.08)); gr.addColorStop(1, rgba(c, 0));
    g.fillStyle = gr; g.fillRect(0, 0, R * 2, R * 2);
    const q = r * 1.3;
    g.beginPath(); g.moveTo(R, R - q); g.lineTo(R + q, R); g.lineTo(R, R + q); g.lineTo(R - q, R); g.closePath();
    g.fillStyle = rgba(c, 0.95); g.fill();
    g.lineWidth = 0.9; g.strokeStyle = PAL.dark ? 'rgba(0,0,0,0.6)' : 'rgba(255,255,255,0.9)'; g.stroke();
    if (claimed) { g.beginPath(); g.arc(R, R, r * 0.42, 0, Math.PI * 2); g.fillStyle = rgba(PAL.bg, 1); g.fill(); }
    s = { cv, R };
    sprites.set(key, s);
    return s;
  }

  // ------------------------------------------------------------------ geometry
  let H = null;            // host: { box, W, H, proj, flyTo, tip, transform }
  let canS = null, canD = null, cs = null, cd = null, dpr = 1, scale = 1, offY = 0;
  let T = { k: 1, x: 0, y: 0 };
  let G = { nodes: [], arcs: [], outs: [], attrib: [], atks: [], grid: new Map(), cell: 6 };
  const hash = (s) => { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return (h >>> 0) / 4294967296; };
  let labelPts = null;
  function countryPoints() {
    if (labelPts) return labelPts;
    labelPts = new Map();
    if (!window.topojson || !window.TI_WORLD || !window.d3geo) return labelPts;
    const fc = window.topojson.feature(window.TI_WORLD, window.TI_WORLD.objects.countries);
    for (const f of fc.features) {
      const iso = window.TI_NUM2ISO && window.TI_NUM2ISO[f.id];
      if (!iso || !f.geometry) continue;
      let best = f.geometry;
      if (f.geometry.type === 'MultiPolygon') {
        let a = -1;
        for (const poly of f.geometry.coordinates) { const g = { type: 'Polygon', coordinates: poly }; const ar = window.d3geo.geoArea(g); if (ar > a) { a = ar; best = g; } }
      }
      const c = window.d3geo.geoCentroid(best);
      if (isFinite(c[0]) && isFinite(c[1])) labelPts.set(iso, c);
    }
    return labelPts;
  }
  P.countryPoint = (iso) => countryPoints().get(iso) || null;

  // A projected great-circle arc between two lon/lat points, split where it crosses the map edge, lifted off the
  // surface in proportion to its length so neighbouring arcs separate.
  function arcPath(a, b, steps) {
    const interp = window.d3geo.geoInterpolate(a, b);
    const pts = [];
    for (let i = 0; i <= steps; i++) { const p = H.proj(interp(i / steps)); if (!p) return null; pts.push(p); }
    for (let i = 1; i < pts.length; i++) if (Math.abs(pts[i][0] - pts[i - 1][0]) > H.W * 0.4) return null;
    const [x0, y0] = pts[0], [x1, y1] = pts[pts.length - 1];
    const dx = x1 - x0, dy = y1 - y0, len = Math.hypot(dx, dy) || 1;
    const lift = Math.min(70, Math.max(5, len * 0.18)), nx = -dy / len, ny = dx / len, sgn = ny > 0 ? -1 : 1;
    const out = new Float32Array(pts.length * 2);
    let total = 0;
    for (let i = 0; i < pts.length; i++) {
      const t = i / steps, s = Math.sin(Math.PI * t) * lift * sgn;
      out[i * 2] = pts[i][0] + nx * s; out[i * 2 + 1] = pts[i][1] + ny * s;
      if (i) total += Math.hypot(out[i * 2] - out[i * 2 - 2], out[i * 2 + 1] - out[i * 2 - 1]);
    }
    return { pts: out, len: total };
  }

  function prepare() {
    const N = [], grid = new Map(), cell = G.cell;
    const fam = opt.family, ms = H.W < 700 ? 0.62 : 1;
    for (const n of P.nodes()) {
      if (!opt[n.layer]) continue;
      const p = H.proj([n.lon, n.lat]);
      if (!p) continue;
      const r = ms * (n.layer === 'c2' ? 3.4 : n.layer === 'src' ? Math.min(6, 2.4 + Math.sqrt(n.count || 1) / 9) : n.layer === 'url' ? Math.min(5.2, 2.1 + Math.sqrt(n.count || 1) / 3) : 2.2);
      const o = { n, x: p[0], y: p[1], r, hit: !fam || n.family === fam, ph: hash(n.ip + n.port) };
      N.push(o);
      const k = Math.floor(o.x / cell) + ',' + Math.floor(o.y / cell);
      let b = grid.get(k); if (!b) grid.set(k, (b = [])); b.push(o);
    }
    const order = { url: 0, ioc: 1, src: 2, c2: 3 };
    N.sort((a, b) => order[a.n.layer] - order[b.n.layer] || (a.n.new ? 1 : 0) - (b.n.new ? 1 : 0));
    const A = [];
    if (opt.flows) {
      for (const f of P.flows()) {
        if (!opt.singles && (f.articles || 1) < 2) continue;
        const a = arcPath([f.src_lon, f.src_lat], [f.dst_lon, f.dst_lat], 40);
        if (!a) continue;
        A.push({ f, ...a, c: rootColor(+f.root), w: ms * Math.min(3, 0.8 + Math.log2(1 + (f.m || 1)) / 3), ph: hash(f.key || f.url || ''), per: 2.2 + Math.min(3.2, a.len / 160) });
      }
    }
    const O = [];
    if (opt.outages) {
      for (const o of P.outages()) {
        const c = P.countryPoint(o.cc);
        if (!c) continue;
        const p = H.proj(c);
        if (p) O.push({ o, x: p[0], y: p[1], ph: hash(o.cc + o.start_at) });
      }
    }
    const R = [];
    if (opt.attrib) {
      for (const pr of P.pairs()) {
        const a = P.countryPoint(pr.o), b = P.countryPoint(pr.t);
        if (!a || !b) continue;
        const arc = arcPath(a, b, 36);
        if (!arc) continue;
        R.push({ pr, ...arc, c: originColor(pr.o), w: ms * Math.min(2.6, 0.6 + Math.sqrt(pr.n) / 2), ph: hash(pr.o + pr.t), per: 6 + Math.min(5, arc.len / 120) });
      }
    }
    // Reported attacks: one diamond per row in the victim's country, newest at the country point and the rest on a
    // golden-angle spiral around it, so a country with many reports reads as a cluster.
    const K = [];
    if (opt.attacks) {
      const by = new Map();
      for (const r of P.attacks()) { const a = by.get(r.cc) || []; a.push(r); by.set(r.cc, a); }
      for (const [cc, list] of by) {
        const c = P.countryPoint(cc), p = c && H.proj(c);
        if (!p) continue;
        list.forEach((r, k) => {
          const rad = 4.6 * ms * Math.sqrt(k), ang = k * 2.399963;
          K.push({ row: r, x: p[0] + rad * Math.cos(ang), y: p[1] + rad * Math.sin(ang), ll: c, rad: 3.3 * ms, fresh: freshAtk(r), a: attackAlpha(r), ph: hash(r.victim + r.date + r.url) });
        });
      }
    }
    // Thermal anomalies: a small square per detection, weighted by radiative power; novel cells larger.
    const F = [];
    if (opt.fires) {
      for (const f of P.fires()) {
        const p = H.proj([f.lon, f.lat]);
        if (p) F.push({ f, x: p[0], y: p[1], r: ms * (f.novel ? 2.4 : Math.min(2.2, 1.1 + Math.sqrt(f.frp || 1) / 9)), a: f.conf === 'l' ? 0.45 : f.conf === 'h' ? 0.95 : 0.75 });
      }
    }
    G = { nodes: N, arcs: A, outs: O, attrib: R, atks: K, fires: F, grid, cell };
  }

  // ------------------------------------------------------------------ drawing
  const sx = (x) => x * T.k + T.x, sy = (y) => y * T.k + T.y;
  function linePath(ctx, pts, from, to) {
    const n = pts.length / 2 - 1, i0 = Math.max(0, Math.floor(from * n)), i1 = Math.min(n, Math.ceil(to * n));
    ctx.moveTo(sx(pts[i0 * 2]), sy(pts[i0 * 2 + 1]));
    for (let i = i0 + 1; i <= i1; i++) ctx.lineTo(sx(pts[i * 2]), sy(pts[i * 2 + 1]));
  }
  function pointAt(pts, u) {
    const n = pts.length / 2 - 1, f = Math.max(0, Math.min(n, u * n)), i = Math.min(n - 1, Math.floor(f)), t = f - i;
    return [sx(pts[i * 2] + (pts[i * 2 + 2] - pts[i * 2]) * t), sy(pts[i * 2 + 1] + (pts[i * 2 + 3] - pts[i * 2 + 1]) * t)];
  }
  function clear(ctx) { ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height); ctx.setTransform(dpr * scale, 0, 0, dpr * scale, 0, 0); }
  const replayOn = () => !!replay;
  const visibleAt = (n, c) => !replay || !n.first_seen || Date.parse(n.first_seen) <= c || Date.parse(n.first_seen) < replay.from;

  function drawStatic() {
    if (!cs) return;
    clear(cs);
    const dim = PAL.dark ? 1 : 0.9;
    // Outage halos.
    for (const o of G.outs) {
      const on = o.o.ongoing, x = sx(o.x), y = sy(o.y), r = on ? 15 : 10;
      const g = cs.createRadialGradient(x, y, 0, x, y, r);
      g.addColorStop(0, rgba(PAL.out, on ? 0.38 : 0.16)); g.addColorStop(1, rgba(PAL.out, 0));
      cs.fillStyle = g; cs.beginPath(); cs.arc(x, y, r, 0, Math.PI * 2); cs.fill();
      cs.strokeStyle = rgba(PAL.out, on ? 0.9 : 0.4); cs.lineWidth = on ? 1.4 : 0.8; cs.setLineDash(on ? [] : [2, 2]);
      cs.beginPath(); cs.arc(x, y, on ? 6 : 4.5, 0, Math.PI * 2); cs.stroke(); cs.setLineDash([]);
    }
    // Attribution arcs: dashed, faint.
    cs.lineCap = 'round';
    for (const a of G.attrib) {
      cs.strokeStyle = rgba(a.c, PAL.dark ? 0.32 : 0.26); cs.lineWidth = a.w; cs.setLineDash([3, 4]);
      cs.beginPath(); linePath(cs, a.pts, 0, 1); cs.stroke();
    }
    cs.setLineDash([]);
    // Conflict arcs: base line, then an arrowhead at the action end.
    for (const a of G.arcs) {
      if (replay && !a.fired) continue;
      cs.strokeStyle = rgba(a.c, (PAL.dark ? 0.42 : 0.34) * dim); cs.lineWidth = a.w;
      cs.beginPath(); linePath(cs, a.pts, 0, 1); cs.stroke();
      const [ex, ey] = pointAt(a.pts, 1), [px, py] = pointAt(a.pts, 0.94), ang = Math.atan2(ey - py, ex - px);
      cs.fillStyle = rgba(a.c, 0.85); cs.beginPath();
      cs.moveTo(ex, ey); cs.lineTo(ex - 6 * Math.cos(ang - 0.45), ey - 6 * Math.sin(ang - 0.45)); cs.lineTo(ex - 6 * Math.cos(ang + 0.45), ey - 6 * Math.sin(ang + 0.45)); cs.closePath(); cs.fill();
    }
    drawFires(cs);
    if (!replay) drawNodes(cs, Infinity); // nodes are drawn per frame while replaying
    drawAttacks(cs);
  }
  // Reported attacks sit above the infrastructure and stay in view through a replay: their dates are days, not times.
  function drawAttacks(ctx) {
    for (const o of G.atks) {
      const s = gem(PAL.atk, o.rad, !!o.row.claimed_by);
      ctx.globalAlpha = o.a * (opt.family ? 0.3 : 1);
      ctx.drawImage(s.cv, sx(o.x) - s.R, sy(o.y) - s.R, s.R * 2, s.R * 2);
    }
    ctx.globalAlpha = 1;
  }
  function drawFires(ctx) {
    for (const o of G.fires || []) {
      const x = sx(o.x), y = sy(o.y), r = o.r;
      ctx.fillStyle = rgba(PAL.fire, o.a * (opt.family ? 0.3 : 1));
      ctx.fillRect(x - r, y - r, r * 2, r * 2);
      if (o.f.novel) { ctx.strokeStyle = rgba(PAL.fire, 0.95); ctx.lineWidth = 1.2; ctx.beginPath(); ctx.arc(x, y, r + 3, 0, Math.PI * 2); ctx.stroke(); }
    }
  }
  function drawNodes(ctx, cursor) {
    const fam = opt.family;
    for (const o of G.nodes) {
      if (cursor !== Infinity && !visibleAt(o.n, cursor)) continue;
      const c = PAL[o.n.layer], s = sprite(c, o.r, o.n.layer === 'c2' || o.n.layer === 'src');
      ctx.globalAlpha = (fam && !o.hit ? 0.08 : 1) * (o.n.stale ? 0.4 : 1);
      ctx.drawImage(s.cv, sx(o.x) - s.R, sy(o.y) - s.R, s.R * 2, s.R * 2);
    }
    ctx.globalAlpha = 1;
  }

  let replay = null, bursts = [], sel = null;
  function frame(now) {
    raf = 0;
    if (!cd || !running) return;
    const t = now / 1000;
    clear(cd);
    let cursor = Infinity;
    if (replay) {
      const p = Math.min(1, (now - replay.start) / replay.dur);
      cursor = replay.from + (replay.to - replay.from) * p;
      replay.cursor = cursor;
      for (const a of G.arcs) if (!a.fired && cursor >= Date.now() - (a.f.h + 0.5) * 3600e3) { a.fired = true; staticDirty = true; burst(a.pts, a.c); }
      for (const o of G.nodes) if (o.n.first_seen && !o.shown && Date.parse(o.n.first_seen) <= cursor && Date.parse(o.n.first_seen) >= replay.from) { o.shown = true; bursts.push({ x: o.x, y: o.y, c: PAL[o.n.layer], t0: now, big: o.n.layer === 'c2' }); }
      // Nodes composite normally, as on the static canvas; only the effects below add light.
      drawNodes(cd, cursor);
      if (p >= 1) { stopReplay(true); }
      replayHud(cursor, p);
    }
    if (PAL.dark) cd.globalCompositeOperation = 'lighter';
    if (opt.motion) {
      // Comets along conflict arcs, with an impact ring as each reaches the action end.
      for (const a of G.arcs) {
        if (replay && !a.fired) continue;
        const u = ((t / a.per) + a.ph) % 1, tail = 0.24;
        const grad = cd.createLinearGradient(...pointAt(a.pts, Math.max(0, u - tail)), ...pointAt(a.pts, u));
        grad.addColorStop(0, rgba(a.c, 0)); grad.addColorStop(1, rgba(a.c, 0.95));
        cd.strokeStyle = grad; cd.lineWidth = a.w + 1.2; cd.lineCap = 'round';
        cd.beginPath(); linePath(cd, a.pts, Math.max(0, u - tail), u); cd.stroke();
        const [hx, hy] = pointAt(a.pts, u), s = sprite(a.c, 2.2, true);
        cd.drawImage(s.cv, hx - s.R, hy - s.R, s.R * 2, s.R * 2);
        if (u > 0.9) {
          const q = (u - 0.9) / 0.1, [ex, ey] = pointAt(a.pts, 1);
          cd.strokeStyle = rgba(a.c, 0.9 * (1 - q)); cd.lineWidth = 1.4; cd.beginPath(); cd.arc(ex, ey, 3 + q * 13, 0, Math.PI * 2); cd.stroke();
        }
      }
      // Attribution comets: slower and smaller.
      for (const a of G.attrib) {
        const u = ((t / a.per) + a.ph) % 1, [hx, hy] = pointAt(a.pts, u), s = sprite(a.c, 1.6, true);
        cd.globalAlpha = 0.85; cd.drawImage(s.cv, hx - s.R, hy - s.R, s.R * 2, s.R * 2); cd.globalAlpha = 1;
      }
      // Rings on records new in the last 24 hours, and on online C2.
      let pulses = 0;
      for (const o of G.nodes) {
        if (!(o.n.new || (o.n.layer === 'c2' && o.n.status === 'online')) || (opt.family && !o.hit) || pulses > 400) continue;
        if (replay && !visibleAt(o.n, cursor)) continue;
        pulses++;
        const per = o.n.layer === 'c2' ? 2.6 : 3.4, q = ((t / per) + o.ph) % 1, c = PAL[o.n.layer];
        cd.strokeStyle = rgba(c, 0.75 * (1 - q)); cd.lineWidth = 1.1;
        cd.beginPath(); cd.arc(sx(o.x), sy(o.y), o.r + 2 + q * (o.n.layer === 'c2' ? 14 : 9), 0, Math.PI * 2); cd.stroke();
      }
      // Rings on reported attacks added since yesterday.
      for (const o of G.atks) {
        if (!o.fresh) continue;
        const q = ((t / 3) + o.ph) % 1;
        cd.strokeStyle = rgba(PAL.atk, 0.75 * (1 - q)); cd.lineWidth = 1.1;
        cd.beginPath(); cd.arc(sx(o.x), sy(o.y), o.rad * 1.3 + 2 + q * 11, 0, Math.PI * 2); cd.stroke();
      }
      // Ongoing outages breathe.
      for (const o of G.outs) {
        if (!o.o.ongoing) continue;
        const q = ((t / 3.2) + o.ph) % 1;
        cd.strokeStyle = rgba(PAL.out, 0.7 * (1 - q)); cd.lineWidth = 1.6;
        cd.beginPath(); cd.arc(sx(o.x), sy(o.y), 6 + q * 22, 0, Math.PI * 2); cd.stroke();
      }
    }
    // One-time bursts: records new since this page loaded, and replay arrivals.
    bursts = bursts.filter((b) => now - b.t0 < 1400);
    for (const b of bursts) {
      const q = (now - b.t0) / 1400;
      cd.strokeStyle = rgba(b.c, 0.95 * (1 - q)); cd.lineWidth = b.big ? 2 : 1.4;
      cd.beginPath(); cd.arc(sx(b.x), sy(b.y), 3 + q * (b.big ? 30 : 18), 0, Math.PI * 2); cd.stroke();
    }
    cd.globalCompositeOperation = 'source-over';
    // Selection marker.
    if (sel && sel.x != null) {
      const x = sx(sel.x), y = sy(sel.y), q = (t % 1.6) / 1.6;
      cd.strokeStyle = rgba(PAL.fg, 0.9); cd.lineWidth = 1.5; cd.setLineDash([3, 3]);
      cd.beginPath(); cd.arc(x, y, 9 + q * 3, 0, Math.PI * 2); cd.stroke(); cd.setLineDash([]);
    }
    if (staticDirty) { staticDirty = false; drawStatic(); }
    if (opt.motion || replay || bursts.length || sel) schedule();
  }
  function burst(pts, c) { const n = pts.length / 2 - 1; bursts.push({ x: pts[n * 2], y: pts[n * 2 + 1], c, t0: performance.now(), big: true }); }
  let raf = 0, running = false, staticDirty = false, visible = true;
  function schedule() { if (!raf && running && visible && !document.hidden) raf = requestAnimationFrame(frame); }
  function kick() { running = true; schedule(); }

  // ------------------------------------------------------------------ attach to the map
  // Called by map.js after it rebuilds the SVG: same box, projection and zoom transform.
  P.attach = (host) => {
    H = host;
    // Colours resolve inside the map box so wall mode's dark tokens apply; re-resolved when the theme or mode changes.
    const mode = (TI.root.getAttribute('data-theme') || 'auto') + (P.wall() ? ':wall' : '');
    if (!PAL || P._theme !== mode) { palette(host.box); P._theme = mode; }
    dpr = Math.min(2, window.devicePixelRatio || 1);
    const cssW = host.box.clientWidth || host.W;
    scale = Math.min(1, cssW / host.W);
    // Below the map's minimum width the SVG letterboxes vertically; the canvases follow it.
    offY = (host.H - host.H * scale) / 2;
    const mk = (cls) => {
      const c = document.createElement('canvas');
      c.className = 'ti-pew-canvas ' + cls; c.setAttribute('aria-hidden', 'true');
      c.width = Math.round(host.W * scale * dpr); c.height = Math.round(host.H * scale * dpr);
      c.style.width = host.W * scale + 'px'; c.style.height = host.H * scale + 'px'; c.style.top = offY + 'px';
      host.box.append(c);
      return c;
    };
    canS = mk('ti-pew-static'); canD = mk('ti-pew-dyn');
    cs = canS.getContext('2d'); cd = canD.getContext('2d');
    T = host.transform || { k: 1, x: 0, y: 0 };
    prepare();
    noteArrivals();
    drawStatic();
    bind(host.box);
    kick();
    P.hud(); P.ticker(); P.legend(); syncControls();
  };
  P.transform = (t) => { T = { k: t.k, x: t.x, y: t.y }; staticDirty = true; if (!opt.motion && !replay) { drawStatic(); } kick(); };
  P.redraw = () => {
    if (TI.globe && TI.globe.on()) { TI.globe.refresh(); P.hud(); P.legend(); return; }
    if (!H || !cs) return;
    prepare(); drawStatic(); kick(); P.hud(); P.legend();
  };
  P.refreshTheme = () => { PAL = null; };

  // Records that were not in the previous answer during this visit get a one-time burst and a ticker entry.
  // Compared across every listed node, whatever layers are switched on, so toggling a layer is not an arrival.
  let seen = null;
  const nid = (n) => n.layer + n.ip + ':' + n.port;
  function noteArrivals() {
    const all = P.nodes();
    if (!all.length) return;
    if (seen) {
      const now = performance.now(), drawn = new Map(G.nodes.map((o) => [nid(o.n), o]));
      for (const n of all) {
        if (seen.has(nid(n))) continue;
        arrivals.unshift({ at: Date.now(), o: n });
        const o = drawn.get(nid(n));
        if (o) bursts.push({ x: o.x, y: o.y, c: PAL[n.layer], t0: now, big: n.layer === 'c2' });
      }
      arrivals = arrivals.slice(0, 30);
    }
    seen = new Set(all.map(nid));
  }
  let arrivals = [];

  // ------------------------------------------------------------------ pause when nobody can see it
  document.addEventListener('visibilitychange', () => { if (!document.hidden) schedule(); });
  let io = null;
  function observe(box) {
    if (io || !('IntersectionObserver' in window)) return;
    io = new IntersectionObserver((es) => { for (const e of es) visible = e.isIntersecting; if (visible) schedule(); });
    io.observe(box);
  }

  // ------------------------------------------------------------------ hit testing, tooltips, selection
  function toMap(ev) {
    const r = H.box.getBoundingClientRect();
    const vx = (ev.clientX - r.left) / scale, vy = (ev.clientY - r.top - offY) / scale;
    return { vx, vy, mx: ev.clientX - r.left, my: ev.clientY - r.top };
  }
  function hitAt(vx, vy) {
    const px = (vx - T.x) / T.k, py = (vy - T.y) / T.k, cell = G.cell;
    let best = null, bd = Infinity;
    // Attack diamonds are drawn on top, so they answer first.
    for (const o of G.atks) { const d = Math.hypot(sx(o.x) - vx, sy(o.y) - vy); if (d < Math.max(5, o.rad * 1.3 + 3) && d < bd) { bd = d; best = { kind: 'attack', o, x: o.x, y: o.y }; } }
    if (best) return best;
    const rad = 7 / T.k, c0 = Math.floor((px - rad) / cell), c1 = Math.floor((px + rad) / cell), r0 = Math.floor((py - rad) / cell), r1 = Math.floor((py + rad) / cell);
    for (let i = c0; i <= c1; i++) for (let j = r0; j <= r1; j++) {
      const b = G.grid.get(i + ',' + j);
      if (!b) continue;
      for (const o of b) {
        if (opt.family && !o.hit) continue;
        const d = Math.hypot((o.x - px) * T.k, (o.y - py) * T.k);
        if (d < Math.max(5, o.r + 3) && d < bd) { bd = d; best = { kind: 'node', o, x: o.x, y: o.y }; }
      }
    }
    if (best) return best;
    for (const o of G.fires || []) { const d = Math.hypot(sx(o.x) - vx, sy(o.y) - vy); if (d < Math.max(4, o.r + 2) && d < bd) { bd = d; best = { kind: 'fire', o, x: o.x, y: o.y }; } }
    if (best) return best;
    for (const o of G.outs) { const d = Math.hypot(sx(o.x) - vx, sy(o.y) - vy); if (d < 9 && d < bd) { bd = d; best = { kind: 'outage', o, x: o.x, y: o.y }; } }
    if (best) return best;
    const near = (list, kind) => {
      for (const a of list) {
        if (replay && kind === 'flow' && !a.fired) continue;
        for (let i = 0; i < a.pts.length; i += 4) {
          const d = Math.hypot(sx(a.pts[i]) - vx, sy(a.pts[i + 1]) - vy);
          if (d < 5 && d < bd) { bd = d; const n = a.pts.length / 2 - 1; best = { kind, a, x: a.pts[n * 2], y: a.pts[n * 2 + 1] }; }
        }
      }
    };
    near(G.arcs, 'flow');
    if (!best) near(G.attrib, 'attrib');
    return best;
  }
  const defang = (ip) => String(ip || '').replace(/\.(?=[^.]*$)/, '[.]');
  const ago = (iso) => {
    const t = Date.parse(iso || ''); if (!isFinite(t)) return '';
    const m = Math.round((Date.now() - t) / 60000);
    return m < 60 ? m + ' min ago' : m < 2880 ? Math.round(m / 60) + ' h ago' : Math.round(m / 1440) + ' days ago';
  };
  const cname = (cc) => (window.TI_ISONAME && window.TI_ISONAME[cc]) || cc || '';
  function describe(h) {
    if (h.kind === 'node') {
      const n = h.o.n, lines = [];
      lines.push({ text: `${defang(n.ip)}${n.port ? ':' + n.port : ''}${n.status ? ' (' + n.status + ')' : ''}`, color: rgba(PAL[n.layer], 1) });
      if (n.family && n.family !== 'scanning') lines.push({ text: `Family: ${n.family}${n.threat ? ', ' + n.threat.replace(/_/g, ' ') : ''}${n.confidence != null ? ', confidence ' + n.confidence + '%' : ''}` });
      if (n.layer === 'src' && n.count) lines.push({ text: `${TI.f.int(n.count)} reports${n.tags ? ', ' + n.tags : ''}` });
      // URLhaus tags carry placeholder values such as "None"; only real labels are shown.
      const tags = String(n.tags || '').split(',').map((t) => t.trim()).filter((t) => t && !/^(none|null|n\/a)$/i.test(t)).join(', ');
      if (n.layer === 'url') lines.push({ text: `${TI.f.int(n.count || 1)} online malware URL${(n.count || 1) > 1 ? 's' : ''}${tags ? ' · ' + tags : ''}` });
      lines.push({ text: [n.as_name, [n.city, cname(n.cc)].filter(Boolean).join(', ')].filter(Boolean).join(' · ') });
      // URLhaus dates are when each URL on the host was added, so they read as listing times there.
      const [firstL, lastL] = n.layer === 'url' ? ['first URL listed ', 'latest URL listed '] : ['first seen ', n.layer === 'c2' ? 'last online ' : 'last seen '];
      const times = [n.first_seen ? firstL + ago(n.first_seen) : '', n.last_seen ? lastL + ago(n.last_seen) : ''].filter(Boolean).join(', ');
      if (times) lines.push({ text: times[0].toUpperCase() + times.slice(1) });
      if (n.new) {
        const ref = Date.parse((P.tmMeta() || {}).generated || '') || Date.now(), fs = Date.parse(n.first_seen || '');
        lines.push({ text: isFinite(fs) && ref - fs < 864e5 ? 'Listed by the source in the last 24 hours' : 'First observed by the collector in the last 24 hours' });
      }
      if (n.stale) lines.push({ text: 'Feed unreachable at the last run; last listed state shown' });
      // Admiralty credibility from independent operators naming the host (38-lists.mjs), the lists that name it, and
      // the ENISA RSIT class.
      if (n.cred) {
        const lists = TI.list(n.lb);
        lines.push({ text: `Credibility ${n.cred} (${CRED[n.cred] || ''})${n.rel ? ', source reliability ' + n.rel : ''}: ${lists.length ? 'also named by ' + lists.join(', ') : 'named by the map source alone'}${n.ipsum ? `; IPsum counts it on ${n.ipsum} lists` : ''}${n.tor ? '; a Tor exit' : ''}` });
      }
      if (n.rsit) lines.push({ text: 'RSIT: ' + n.rsit });
      lines.push({ text: 'Source: ' + SOURCES[n.layer] + ' · click for the record' });
      return { head: NAMES[n.layer].replace(/s$/, '') + (n.family && n.family !== 'scanning' ? ' · ' + n.family : ''), lines };
    }
    if (h.kind === 'fire') {
      const f = h.o.f, ao = P.fireAois().find((x) => x.id === f.aoi);
      return { head: 'Thermal anomaly (NASA FIRMS VIIRS)', lines: [
        { text: `${cname(f.cc)}${ao ? ' · ' + (ao.name || f.aoi) : ''}`, color: rgba(PAL.fire, 1) },
        { text: `${d3.format('.1f')(f.frp || 0)} MW radiative power, ${f.conf === 'h' ? 'high' : f.conf === 'l' ? 'low' : 'nominal'} confidence, ${f.dn === 'N' ? 'night' : 'day'} pass` },
        { text: `Detected ${ago(f.at)} at ${d3.format('.3f')(f.lat)}, ${d3.format('.3f')(f.lon)}` },
        f.novel ? { text: 'In a 0.1-degree cell with no detection in the 30 days before' } : null,
        { text: 'A fire or hot spot of any cause; only corroboration ties one to a strike' },
        { text: 'NASA FIRMS (VIIRS NRT) via the threat-feeds collector · click for the FIRMS map' },
      ].filter(Boolean) };
    }
    if (h.kind === 'flow') {
      const f = h.a.f;
      return { head: `${ROOT[f.root] || 'CAMEO ' + f.root} (CAMEO ${f.code || f.root})`, lines: [
        { text: [f.actor1, f.actor2].filter(Boolean).join(' → ') || 'Actors not named', color: rgba(h.a.c, 1) },
        { text: `${f.src_place || cname(f.src_iso2)} → ${f.dst_place || cname(f.dst_iso2)}` },
        { text: `${TI.f.int(f.n)} events, ${TI.f.int(f.m)} mentions, ${TI.f.int(f.articles || 1)} article${(f.articles || 1) > 1 ? 's' : ''}` },
        { text: `Latest ${f.h === 0 ? 'in the last hour' : f.h + ' h ago'}, seen in ${f.hours_seen || 1} hour${(f.hours_seen || 1) > 1 ? 's' : ''} of 24` },
        (f.src_type === 1 || f.dst_type === 1) ? { text: 'One end is a country-level geocode (centroid), so its position is approximate' } : null,
        { text: 'GDELT machine coding of press reports · click for the article' },
      ].filter(Boolean) };
    }
    if (h.kind === 'attack') {
      const r = h.o.row;
      return { head: 'Reported cyberattack: ' + r.victim, lines: [
        { text: `${cname(r.cc)} (${basisText(r)})`, color: rgba(PAL.atk, 1) },
        r.title ? { text: r.title.length > 150 ? r.title.slice(0, 149) + '…' : r.title } : null,
        { text: [r.outlet, r.date ? 'attack dated ' + r.date : '', r.added ? 'listed ' + r.added : ''].filter(Boolean).join(' · ') },
        r.claimed_by ? { text: `ransomware.live matched it to a leak-site claim by ${r.claimed_by}` } : null,
        { text: 'Press report collected by ransomware.live · click for the article' },
      ].filter(Boolean) };
    }
    if (h.kind === 'outage') {
      const o = h.o.o;
      return { head: `Internet disruption: ${o.name || cname(o.cc)}`, lines: [
        { text: `${o.datasource || 'signal'}${o.score ? ', score ' + TI.f.int(o.score) : ''}${o.level ? ' (' + o.level + ')' : ''}`, color: rgba(PAL.out, 1) },
        { text: `Started ${ago(o.start_at)}${o.ongoing ? ', ongoing' : o.end_at ? ', ended ' + ago(o.end_at) : ''}` },
        { text: 'IODA, Georgia Tech Internet Intelligence Lab · click for the country view' },
      ] };
    }
    const pr = h.a.pr;
    return { head: `Reported state-nexus targeting: ${cname(pr.o)} → ${cname(pr.t)}`, lines: [
      { text: `${pr.n} attributed actor${pr.n > 1 ? 's' : ''}: ${TI.list(pr.actors, ', ').slice(0, 6).join(', ')}${TI.list(pr.actors, ', ').length > 6 ? ' …' : ''}`, color: rgba(h.a.c, 1) },
      { text: 'Historical attribution from public reporting (MISP galaxy, CFR tracker fields); not observed traffic' },
    ] };
  }
  function linkFor(h) {
    if (h.kind === 'node') return h.o.n.ref;
    if (h.kind === 'flow') return h.a.f.url;
    if (h.kind === 'outage') return 'https://ioda.inetintel.cc.gatech.edu/country/' + h.o.o.cc;
    if (h.kind === 'fire') return 'https://firms.modaps.eosdis.nasa.gov/map/';
    if (h.kind === 'attack') return h.o.row.url;
    const act = P.actors().find((a) => TI.list(h.a.pr.actors, ', ').includes(a.name));
    return act ? act.ref : '';
  }
  function bind(box) {
    observe(box);
    if (box._pewBound) return;
    box._pewBound = true;
    const onMove = (ev) => {
      if (!H || !G || (TI.globe && TI.globe.on())) return;
      if (ev.target.closest && ev.target.closest('.ti-map-marker, .ti-chokes')) return;
      const { vx, vy, mx, my } = toMap(ev);
      const h = hitAt(vx, vy);
      if (!h) { box.style.cursor = ''; return; }
      ev.stopPropagation();
      box.style.cursor = 'pointer';
      const d = describe(h);
      H.tip().show(d.head, d.lines, mx, my);
    };
    box.addEventListener('mousemove', onMove, true);
    box.addEventListener('click', (ev) => {
      if (!H || (TI.globe && TI.globe.on()) || (ev.target.closest && ev.target.closest('.ti-map-marker, .ti-chokes'))) return;
      const { vx, vy } = toMap(ev);
      const h = hitAt(vx, vy);
      if (!h) { if (sel) P.select(null); return; }
      ev.stopPropagation();
      P.select(h);
    }, true);
  }

  // ------------------------------------------------------------------ selection panel
  P.select = (h) => {
    sel = h;
    const el = document.getElementById('pew-sel');
    if (!el) return;
    TI.clear(el);
    el.hidden = !h;
    if (!h) return;
    const d = describe(h), url = linkFor(h);
    el.append(TI.h('div', { class: 'ti-pew-sel-h' }, TI.h('span', { text: d.head }), TI.h('button', { type: 'button', class: 'ti-pew-x', 'aria-label': 'Close details', text: '×', onclick: () => P.select(null) })));
    for (const l of d.lines.slice(0, -1)) el.append(TI.h('div', { class: 'ti-pew-sel-l', text: l.text }));
    const act = TI.h('div', { class: 'ti-pew-sel-a' });
    if (url) act.append(TI.h('a', { href: url, target: '_blank', rel: 'noopener noreferrer', text: h.kind === 'flow' || h.kind === 'attack' ? 'Open the article' : h.kind === 'outage' ? 'Open IODA' : h.kind === 'fire' ? 'Open the FIRMS map' : h.kind === 'attrib' ? 'Open a cited report' : 'Open the source record' }));
    if (h.kind === 'attack' && h.o.row.link) act.append(TI.h('a', { href: h.o.row.link, target: '_blank', rel: 'noopener noreferrer', text: 'ransomware.live record' }));
    // Pivots (context.js): a country profile for a reported attack or an outage.
    const prof = TI.pivot && (h.kind === 'attack' || h.kind === 'outage') ? TI.pivot.country(h.kind === 'attack' ? h.o.row.cc : h.o.o.cc) : null;
    if (prof) act.append(TI.h('a', { href: prof.href, target: '_blank', rel: 'noopener noreferrer', title: prof.title, text: 'Country profile' }));
    if (h.kind === 'node') {
      const v = h.o.n.ip + (h.o.n.port ? ':' + h.o.n.port : '');
      act.append(TI.h('button', { type: 'button', class: 'ti-chip', text: 'Copy indicator', onclick: (ev) => {
        try { navigator.clipboard.writeText(v).then(() => { ev.target.textContent = 'Copied'; }, () => { ev.target.textContent = v; }); } catch { ev.target.textContent = v; }
      } }));
      // Pivots on the address and its autonomous system (context.js); each opens the third-party record in a new tab.
      for (const p of TI.pivot ? TI.pivot.node(h.o.n) : []) act.append(TI.h('a', { href: p.href, target: '_blank', rel: 'noopener noreferrer', title: p.title, text: p.label }));
      // On-demand enrichment (intel.js): the address, or its network when the address is not public IPv4.
      if (TI.intel) act.append(TI.h('button', { type: 'button', class: 'ti-chip', text: 'Enrich', title: 'Read the free public analyzers for this address (results in the enrichment card below the map)', onclick: () => {
        TI.intel.enrich('ip', h.o.n.ip);
        const c = document.getElementById('map-enrich-card'); if (c) c.scrollIntoView({ block: 'nearest' });
      } }));
    }
    el.append(act);
    // The analyzers' answers for the selected address, once read.
    if (h.kind === 'node' && TI.intel) { const res = TI.intel.enrichResults('ip', h.o.n.ip); if (res) el.append(res); }
    kick();
  };

  // ------------------------------------------------------------------ HUD, legend, ticker
  P.counts = () => {
    const st = P.layerStats(), nodes = P.nodes(), out = {};
    for (const l of LAYERS) {
      const s = st[l] || {};
      out[l] = { listed: s.listed ?? nodes.filter((n) => n.layer === l).length, drawn: nodes.filter((n) => n.layer === l).length, fresh: s.new_24h ?? nodes.filter((n) => n.layer === l && n.new).length, ok: s.ok !== false };
    }
    const fl = P.flows();
    out.flows = { all: fl.length, corroborated: fl.filter((f) => (f.articles || 1) >= 2).length };
    const ou = P.outages();
    out.outages = { all: ou.length, ongoing: ou.filter((o) => o.ongoing).length };
    out.attrib = { pairs: P.pairs().length, actors: P.actors().length };
    const ao = P.fireAois();
    out.fires = { drawn: P.fires().length, all: ao.reduce((s, x) => s + (+x.detections || 0), 0), aois: ao.filter((x) => +x.detections > 0).length, novel: ao.reduce((s, x) => s + (+x.novel_cells || 0), 0), judged: ao.some((x) => x.novelty_judged) };
    const at = P.attacksAll();
    out.attacks = { all: at.length, placed: at.filter((r) => r.cc).length, fresh: at.filter((r) => r.cc && freshAtk(r)).length };
    return out;
  };
  P.hud = () => {
    const el = document.getElementById('pew-hud');
    if (!el) return;
    TI.clear(el);
    const c = P.counts(), meta = P.tmMeta(), gm = TI.ready('live_gdelt_meta') ? TI.rows('live_gdelt_meta')[0] : null;
    const health = TI.ready('live_health') ? TI.rows('live_health') : [];
    const info = (health.find((r) => r.kind === 'meta') || {}).infocon;
    const live = TI.ready('live_threatmap') || TI.ready('live_gdelt');
    // Folded until asked when the map is short; the viewer's own choice is remembered.
    const folded = opt.folded == null ? !!(H && H.H * scale < 440 && window.innerWidth > 700) : !!opt.folded;
    el.classList.toggle('ti-pew-folded', folded);
    const fold = TI.h('button', { type: 'button', class: 'ti-pew-fold', 'aria-expanded': String(!folded), 'aria-label': folded ? 'Show layer counts' : 'Hide layer counts', text: folded ? '+' : '−' });
    fold.addEventListener('click', (ev) => { ev.stopPropagation(); opt.folded = !folded; save(); P.hud(); });
    el.append(TI.h('div', { class: 'ti-pew-title' }, TI.h('span', { class: 'ti-pew-live', 'data-on': live ? '1' : '0' }), live ? 'Live picture' : 'Waiting for live feeds',
      info ? TI.h('span', { class: 'ti-pew-infocon', 'data-level': String(info).toLowerCase(), title: 'SANS ISC DShield Infocon' }, 'Infocon ' + info) : null, fold));
    const row = (key, color, label, val, sub, onOff) => {
      const b = TI.h('button', { type: 'button', class: 'ti-pew-row', 'aria-pressed': String(!!opt[key]), 'data-layer': key, title: (opt[key] ? 'Hide ' : 'Show ') + label });
      const sw = TI.h('span', { class: 'ti-pew-sw' }); sw.style.background = color; b.append(sw);
      b.append(TI.h('span', { class: 'ti-pew-lbl', text: label }), TI.h('span', { class: 'ti-pew-val', text: val }));
      if (sub) b.append(TI.h('span', { class: 'ti-pew-sub', text: sub }));
      if (onOff === false) b.classList.add('ti-pew-down');
      el.append(b);
    };
    for (const l of LAYERS) {
      const x = c[l];
      // Listed count, then how many are new in 24 hours and, when the map draws a sample, how many it draws.
      const sub = [x.fresh ? `${TI.f.int(x.fresh)} new` : '', x.drawn < x.listed ? `${TI.f.int(x.drawn)} mapped` : ''].filter(Boolean).join(' · ');
      row(l, rgba(PAL[l], 1), NAMES[l], TI.f.int(x.listed), sub, x.ok);
    }
    row('attacks', rgba(PAL.atk, 1), 'Reported attacks', TI.f.int(c.attacks.placed), [c.attacks.fresh ? `${TI.f.int(c.attacks.fresh)} added since yesterday` : '',
      c.attacks.all > c.attacks.placed ? `${TI.f.int(c.attacks.all - c.attacks.placed)} unplaced` : ''].filter(Boolean).join(' · '), !TI.failed('live_cyberattacks'));
    row('flows', rgba(PAL.r19, 1), 'Conflict arcs', TI.f.int(opt.singles ? c.flows.all : c.flows.corroborated), opt.singles ? `${TI.f.int(c.flows.corroborated)} multi-source` : `${TI.f.int(c.flows.all - c.flows.corroborated)} single-source hidden`);
    row('outages', rgba(PAL.out, 1), 'Internet outages', TI.f.int(c.outages.ongoing), `${TI.f.int(c.outages.all)} in 7 days`);
    row('fires', rgba(PAL.fire, 1), 'Thermal anomalies', TI.f.int(c.fires.all), [`${TI.f.int(c.fires.aois)} theaters`, c.fires.drawn < c.fires.all ? `${TI.f.int(c.fires.drawn)} mapped` : '', c.fires.judged ? `${TI.f.int(c.fires.novel)} novel cells` : 'novelty after 7 days'].filter(Boolean).join(' · '), !TI.failed('live_fires'));
    row('attrib', rgba(PAL.origin.CN, 1), 'Attribution arcs', TI.f.int(c.attrib.pairs), `${TI.f.int(c.attrib.actors)} actors`);
    const ages = [];
    if (meta && meta.generated) ages.push('infrastructure ' + ago(meta.generated) + (meta.served_from && meta.served_from !== 'store' ? ' (' + meta.served_from + ')' : ''));
    if (gm && gm.latest) ages.push('GDELT export ' + String(gm.latest).slice(11, 16) + 'Z');
    if (ages.length) el.append(TI.h('div', { class: 'ti-pew-age', text: 'Updated: ' + ages.join(' · ') }));
    // Until the collector has a day of its own observations, "new" rests on the sources' listing times alone.
    if (meta && meta.new_basis === 'source') {
      const since = Date.parse(meta.observing_since || ''), full = isFinite(since) ? new Date(since + 864e5) : null;
      const when = full && `${full.toISOString().slice(11, 16)}Z, ${full.getUTCDate()} ${'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(' ')[full.getUTCMonth()]}`;
      el.append(TI.h('div', { class: 'ti-pew-age', text: full ? `New = listed by the source in the last 24 h, until the collector completes a day of observation (${when})`
        : 'New = listed by the source in the last 24 h (live fallback, no collector history)' }));
    }
    if (replay) el.append(TI.h('div', { class: 'ti-pew-replay', id: 'pew-replay-clock' }));
    placeHud(el);
  };
  // Bottom-left of the drawn map (over open ocean), above the legend row that sits inside the map box.
  function placeHud(el) {
    if (!H || getComputedStyle(el).position !== 'absolute') { el.style.top = ''; return; }
    el.style.bottom = 'auto';
    el.style.top = Math.max(8, offY + H.H * scale - el.offsetHeight - 8) + 'px';
  }
  function replayHud(cursor, p) {
    const el = document.getElementById('pew-replay-clock');
    if (el) el.textContent = `Replay ${new Date(cursor).toISOString().slice(11, 16)}Z · ${Math.round(p * 100)}%`;
  }
  P.legend = () => {
    const el = document.getElementById('pew-legend');
    if (!el) return;
    TI.clear(el);
    const sw = (c, txt, shape) => { const s = TI.h('span', { class: 'ti-sw' + (shape ? ' ti-sw-' + shape : '') }); s.style.background = c; return TI.h('span', {}, s, txt); };
    if (opt.attacks) {
      el.append(sw(rgba(PAL.atk, 1), 'Press-reported attack (victim country)', 'diamond'));
      el.append(sw(`radial-gradient(circle, ${rgba(PAL.bg, 1)} 0 32%, ${rgba(PAL.atk, 1)} 36%)`, 'also claimed on a leak site', 'diamond'));
    }
    if (opt.flows) for (const r of [15, 17, 18, 19, 20]) el.append(sw(rgba(rootColor(r), 1), ROOT[r], 'line'));
    if (opt.fires) el.append(sw(rgba(PAL.fire, 1), 'Thermal anomaly, 24 h (NASA FIRMS; ringed: novel cell)', 'square'));
    if (opt.attrib) for (const [cc, nm] of [['CN', 'China'], ['RU', 'Russia'], ['IR', 'Iran'], ['KP', 'North Korea'], ['*', 'Other origin']]) el.append(sw(rgba(PAL.origin[cc], 1), nm + '-attributed', 'dash'));
    el.append(TI.h('span', {}, 'Rings mark records new in 24 h (attacks: added since yesterday); arrows point to the action end'));
  };
  P.ticker = () => {
    const el = document.getElementById('pew-ticker');
    if (!el) return;
    const items = [];
    for (const a of arrivals.slice(0, 8)) items.push({ at: a.at, layer: a.o.layer, text: `Newly listed ${NAMES[a.o.layer].replace(/s$/, '').toLowerCase()}: ${a.o.family || ''} ${defang(a.o.ip)}${a.o.port ? ':' + a.o.port : ''} (${a.o.cc || '??'})`, node: a.o });
    const fresh = P.nodes().filter((n) => n.new && n.first_seen).sort((a, b) => String(b.first_seen).localeCompare(String(a.first_seen))).slice(0, 14);
    for (const n of fresh) items.push({ at: Date.parse(n.first_seen), layer: n.layer, text: `${NAMES[n.layer].replace(/s$/, '')}: ${n.family && n.family !== 'scanning' ? n.family + ' ' : ''}${defang(n.ip)}${n.port ? ':' + n.port : ''}, ${cname(n.cc) || 'location unknown'}`, node: n });
    for (const o of P.outages().filter((o) => o.ongoing || Date.now() - Date.parse(o.start_at) < 86400e3).slice(0, 6)) items.push({ at: Date.parse(o.start_at), layer: 'out', text: `Internet disruption: ${o.name || cname(o.cc)} (${o.datasource || 'signal'}${o.ongoing ? ', ongoing' : ''})`, outage: o });
    for (const f of P.flows().filter((f) => f.h <= 2 && (f.articles || 1) >= 2).slice(0, 6)) items.push({ at: Date.now() - f.h * 3600e3, layer: 'flow', text: `${ROOT[f.root] || 'Conflict'}: ${f.src_place || cname(f.src_iso2)} → ${f.dst_place || cname(f.dst_iso2)}`, flow: f });
    items.sort((a, b) => b.at - a.at);
    // Reported attacks carry a day, not a time, so they would sort below every timed record of that day; up to three
    // added since yesterday keep a place, listed after the timed entries under their date.
    const atk = P.attacks().filter(freshAtk).slice(0, 3).map((r) => ({ at: Date.parse(r.added + 'T00:00:00Z'), day: true, layer: 'atk', text: `Reported attack: ${r.victim}, ${cname(r.cc)}${r.outlet ? ' (' + r.outlet + ')' : ''}`, attack: r }));
    const list = items.slice(0, 16 - atk.length).concat(atk);
    TI.clear(el);
    if (!list.length) { el.append(TI.h('li', { class: 'ti-muted', text: 'Nothing new in the last 24 hours across the live layers.' })); return; }
    for (const it of list) {
      const li = TI.h('li');
      const dot = TI.h('span', { class: 'ti-pew-sw' });
      dot.style.background = it.layer === 'out' ? rgba(PAL.out, 1) : it.layer === 'flow' ? rgba(rootColor(+it.flow.root), 1) : it.layer === 'atk' ? rgba(PAL.atk, 1) : rgba(PAL[it.layer], 1);
      const d = new Date(it.at), when = it.day ? `${d.getUTCDate()} ${'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(' ')[d.getUTCMonth()]}` : d.toISOString().slice(11, 16) + 'Z';
      const b = TI.h('button', { type: 'button', class: 'ti-pew-tick' }, dot, TI.h('span', { class: 'ti-pew-when', text: when }), TI.h('span', { text: it.text }));
      b.addEventListener('click', () => P.focus(it));
      li.append(b);
      el.append(li);
    }
  };
  P.focus = (it) => {
    // A table row or ticker entry for a reported attack switches the layer on before locating it.
    if (it.attack && !opt.attacks) { opt.attacks = true; save(); syncControls(); P.redraw(); }
    if (TI.globe && TI.globe.on()) { TI.globe.focus(it); return; }
    if (!H) return;
    let lon, lat, h = null;
    if (it.node) { lon = it.node.lon; lat = it.node.lat; const o = G.nodes.find((x) => x.n === it.node || (x.n.ip === it.node.ip && x.n.port === it.node.port && x.n.layer === it.node.layer)); if (o) h = { kind: 'node', o, x: o.x, y: o.y }; }
    else if (it.outage) { const c = P.countryPoint(it.outage.cc); if (c) { [lon, lat] = c; const o = G.outs.find((x) => x.o === it.outage); if (o) h = { kind: 'outage', o, x: o.x, y: o.y }; } }
    else if (it.flow) { lon = it.flow.dst_lon; lat = it.flow.dst_lat; const a = G.arcs.find((x) => x.f === it.flow); if (a) { const n = a.pts.length / 2 - 1; h = { kind: 'flow', a, x: a.pts[n * 2], y: a.pts[n * 2 + 1] }; } }
    else if (it.attack) { const o = G.atks.find((x) => sameAtk(x.row, it.attack)), c = o ? o.ll : P.countryPoint(it.attack.cc); if (c) [lon, lat] = c; if (o) h = { kind: 'attack', o, x: o.x, y: o.y }; }
    if (lon == null) return;
    if (H.flyTo) H.flyTo(lon, lat, 4);
    if (h) P.select(h);
  };

  // ------------------------------------------------------------------ replay
  P.replay = () => {
    clearTimeout(loopTimer);
    if (replay) { stopReplay(false); return; }
    if (TI.globe && TI.globe.on()) return;
    const to = Date.now();
    replay = { start: performance.now(), dur: 24000, from: to - 86400e3, to };
    for (const a of G.arcs) a.fired = false;
    for (const o of G.nodes) o.shown = false;
    P.hud(); drawStatic(); kick();
    syncReplay(true);
  };
  // A replay that runs to the end in wall mode starts again after a pause, so the wall shows the last 24 hours on a
  // loop; one stopped by hand stays stopped.
  let loopTimer = 0;
  function stopReplay(finished) {
    replay = null;
    for (const a of G.arcs) a.fired = true;
    syncReplay(false);
    P.hud(); drawStatic(); kick();
    clearTimeout(loopTimer);
    if (finished && P.wall() && !(TI.globe && TI.globe.on())) loopTimer = setTimeout(() => { if (P.wall() && !replay) P.replay(); }, 4000);
  }
  function syncReplay(on) {
    for (const b of document.querySelectorAll('#map-replay, [data-pew-act="replay"]')) { b.textContent = on ? 'Stop replay' : 'Replay 24h'; b.setAttribute('aria-pressed', String(on)); }
  }

  // ------------------------------------------------------------------ wall mode
  P.wall = () => !!(document.fullscreenElement && document.fullscreenElement.classList.contains('ti-pew-card')) || !!document.querySelector('.ti-pew-card.ti-wall');
  function toggleWall() {
    const card = document.querySelector('.ti-pew-card');
    if (!card) return;
    if (P.wall()) {
      if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
      card.classList.remove('ti-wall');
    } else {
      card.classList.add('ti-wall');
      if (card.requestFullscreen) card.requestFullscreen().catch(() => { /* frame disallows fullscreen: the CSS wall view still applies */ });
    }
    setTimeout(() => TI.draw('map'), 60);
    const b = document.getElementById('map-wall'); if (b) b.setAttribute('aria-pressed', String(P.wall()));
    if (!P.wall()) clearTimeout(loopTimer);
  }
  document.addEventListener('fullscreenchange', () => {
    const card = document.querySelector('.ti-pew-card');
    if (card && !document.fullscreenElement) card.classList.remove('ti-wall');
    const b = document.getElementById('map-wall'); if (b) b.setAttribute('aria-pressed', String(P.wall()));
    setTimeout(() => TI.draw('map'), 60);
  });
  document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape' && document.querySelector('.ti-pew-card.ti-wall') && !document.fullscreenElement) toggleWall(); });

  // ------------------------------------------------------------------ controls
  function syncControls() {
    for (const k of ['c2', 'ioc', 'src', 'url', 'attacks', 'flows', 'outages', 'fires', 'attrib', 'singles', 'motion']) {
      const b = document.getElementById('map-' + k);
      if (b) b.setAttribute('aria-pressed', String(!!opt[k]));
    }
    const fam = document.getElementById('map-family');
    if (fam) fillFamilies(fam);
  }
  function fillFamilies(sel) {
    const fams = new Map();
    for (const n of P.nodes()) if (n.family && n.family !== 'unattributed' && n.family !== 'scanning') fams.set(n.family, (fams.get(n.family) || 0) + 1);
    const list = [...fams.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40);
    const sig = list.map((x) => x[0] + x[1]).join('|');
    if (sel._sig === sig) { sel.value = opt.family; return; }
    sel._sig = sig;
    TI.clear(sel);
    sel.append(TI.h('option', { value: '', text: 'All families' }));
    for (const [f, n] of list) sel.append(TI.h('option', { value: f, text: `${f} (${TI.f.int(n)})` }));
    if (opt.family && !fams.has(opt.family)) opt.family = '';
    sel.value = opt.family;
  }
  P.sync = syncControls;
  TI.root.addEventListener('click', (ev) => {
    const act = ev.target.closest && ev.target.closest('[data-pew-act]');
    if (act) {
      const a = act.getAttribute('data-pew-act');
      if (a === 'replay') P.replay();
      else if (a === 'wall') toggleWall();
      else if (a === 'globe' && TI.globe) TI.globe.toggle();
      else if (a === 'reset') { const box = document.getElementById('ti-map'); if (box && box._resetZoom) box._resetZoom(); }
      return;
    }
    const t = ev.target.closest && ev.target.closest('#map-c2, #map-ioc, #map-src, #map-url, #map-attacks, #map-flows, #map-outages, #map-fires, #map-attrib, #map-singles, #map-motion, #map-replay, #map-wall, .ti-pew-row');
    if (!t) return;
    if (t.id === 'map-replay') { P.replay(); return; }
    if (t.id === 'map-wall') { toggleWall(); return; }
    const key = t.classList.contains('ti-pew-row') ? t.getAttribute('data-layer') : t.id.slice(4);
    opt[key] = !opt[key];
    save();
    syncControls();
    if (key === 'motion') { if (TI.globe && TI.globe.on()) { TI.globe.refresh(); return; } if (!opt.motion) { drawStatic(); } kick(); return; }
    P.redraw(); P.ticker();
  });
  TI.root.addEventListener('change', (ev) => {
    if (ev.target.id !== 'map-family') return;
    opt.family = ev.target.value;
    save();
    P.redraw();
  });

  // ------------------------------------------------------------------ shared with globe.js
  P.ensurePalette = (within) => palette(within);
  P.pal = () => PAL;
  Object.assign(P, { sprite, gem, rgba, rootColor, originColor, describe, linkFor, hash, ROOT, NAMES, GEO, basisText, attackAlpha, freshAtk, sameAtk });
  P.selected = () => sel;
  // The globe view replaces the flat canvases; stop drawing on them.
  P.detach = () => { running = false; if (raf) { cancelAnimationFrame(raf); raf = 0; } cs = cd = null; canS = canD = null; };
  P.useHost = (host) => { H = host; scale = Math.min(1, (host.box.clientWidth || host.W) / host.W); offY = (host.H - host.H * scale) / 2; };
})();
