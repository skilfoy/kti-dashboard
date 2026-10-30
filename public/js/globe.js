/* Globe view of the world map: the same country shading, theaters and live layers on an orthographic projection drawn
   to one canvas. Drag to turn it, scroll or pinch to zoom, arrow keys and +/- from the keyboard; while Motion is on it
   turns slowly on its own after a few seconds without input. Arcs follow great circles lifted off the surface (exact
   under this projection: a point raised by a factor h projects h times further from the centre), so the far ends of
   long arcs show over the horizon. Tooltips, the selection panel, the HUD and the ticker are shared with pew.js. */
(() => {
  const P = TI.pew;
  const GL = (TI.globe = {});
  const reduced = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  const store = {
    get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage unavailable */ } },
  };
  let on = !!store.get('ti-globe', false);
  let rot = store.get('ti-globe-rot', [-25, -22, 0]);
  let zoom = 1;
  GL.on = () => on;
  function sync() {
    for (const b of document.querySelectorAll('#map-globe, [data-pew-act="globe"]')) b.setAttribute('aria-pressed', String(on));
    for (const r of document.querySelectorAll('#map-replay, [data-pew-act="replay"]')) { r.disabled = on; r.title = on ? 'Replay runs on the flat map' : ''; }
    for (const id of ['map-cells', 'map-chokes', 'map-labels']) { const el = document.getElementById(id); if (el) el.disabled = on; }
  }
  GL.toggle = () => { on = !on; store.set('ti-globe', on); sync(); TI.draw('map'); };
  TI.root.addEventListener('click', (ev) => { if (ev.target.closest && ev.target.closest('#map-globe')) GL.toggle(); });

  let S = null, raf = 0, last = 0, lastInput = 0, tween = null, drag = null, visible = true, hover = false;
  const pointers = new Map();
  const deg = Math.PI / 180;
  const clampLat = (v) => Math.max(-85, Math.min(85, v));

  // ------------------------------------------------------------------ render entry, called by map.js
  GL.render = (box, host) => {
    P.detach();
    stop();
    sync();
    hover = false; // a replaced canvas never reports the pointer leaving
    const W = host.W, H = host.H, dpr = Math.min(2, window.devicePixelRatio || 1);
    const cv = document.createElement('canvas');
    cv.className = 'ti-globe-canvas';
    cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr);
    // CSS keeps the drawing's aspect ratio if the box is narrower than the drawing; local() maps pointer positions back.
    cv.style.width = '100%'; cv.style.maxWidth = W + 'px'; cv.style.aspectRatio = W + ' / ' + H; cv.style.height = 'auto';
    cv.tabIndex = 0;
    cv.setAttribute('role', 'img');
    cv.setAttribute('aria-label', 'Globe of theaters and live cyber and conflict layers. Drag or use the arrow keys to turn it, plus and minus to zoom.');
    box.append(cv);
    P.ensurePalette(box);
    const PAL = P.pal(), d3g = window.d3geo;
    const R0 = Math.min(W, H) / 2 - 14;
    const proj = d3g.geoOrthographic().translate([W / 2, H / 2]).clipAngle(90).precision(0.4);
    const ctx = cv.getContext('2d');
    const path = d3g.geoPath(proj, ctx);
    const cache = new Map();
    const col = (c) => { let v = cache.get(c); if (!v) { v = TI.resolve(c, box); cache.set(c, v); } return v; };
    for (const f of host.features) f._fill = col(host.fillFor(f));
    S = { box, cv, ctx, W, H, dpr, proj, path, host, col, PAL, R0, grat: d3g.geoGraticule10(), vis: null };
    prepare();
    bind(cv);
    P.useHost({ box, W, H });
    P.hud(); P.legend(); P.ticker(); if (P.sync) P.sync();
    schedule();
  };
  GL.refresh = () => { if (!S) return; P.ensurePalette(S.box); S.PAL = P.pal(); prepare(); schedule(); };

  // Lon/lat samples for every arc, computed once per data change; the projection changes every frame.
  function prepare() {
    const opt = P.opt, d3g = window.d3geo;
    const N = [];
    for (const n of P.nodes()) {
      if (!opt[n.layer]) continue;
      const r = n.layer === 'c2' ? 3.4 : n.layer === 'src' ? Math.min(6, 2.4 + Math.sqrt(n.count || 1) / 9) : n.layer === 'url' ? Math.min(5.2, 2.1 + Math.sqrt(n.count || 1) / 3) : 2.2;
      N.push({ n, ll: [n.lon, n.lat], r, hit: !opt.family || n.family === opt.family, ph: P.hash(n.ip + n.port) });
    }
    const arc = (a, b, steps) => {
      const ip = d3g.geoInterpolate(a, b), pts = [];
      for (let i = 0; i <= steps; i++) pts.push(ip(i / steps));
      const dist = d3g.geoDistance(a, b);
      return { pts, lift: Math.min(0.32, 0.04 + dist * 0.11), dist };
    };
    const A = [];
    if (opt.flows) for (const f of P.flows()) {
      if (!opt.singles && (f.articles || 1) < 2) continue;
      A.push({ f, ...arc([f.src_lon, f.src_lat], [f.dst_lon, f.dst_lat], 40), c: P.rootColor(+f.root), w: Math.min(3, 0.8 + Math.log2(1 + (f.m || 1)) / 3), ph: P.hash(f.key || f.url || ''), per: 2.4 });
    }
    const R = [];
    if (opt.attrib) for (const pr of P.pairs()) {
      const a = P.countryPoint(pr.o), b = P.countryPoint(pr.t);
      if (a && b) R.push({ pr, ...arc(a, b, 36), c: P.originColor(pr.o), w: Math.min(2.6, 0.6 + Math.sqrt(pr.n) / 2), ph: P.hash(pr.o + pr.t), per: 7 });
    }
    const O = [];
    if (opt.outages) for (const o of P.outages()) { const c = P.countryPoint(o.cc); if (c) O.push({ o, ll: c, ph: P.hash(o.cc + o.start_at) }); }
    for (const a of A) a.per = 2.2 + Math.min(3.4, a.dist * 1.6);
    // Reported attacks: the flat map's spiral in degrees around the victim country's point (longitude widened by
    // 1/cos(latitude) so the spacing stays even on the sphere).
    const K = [];
    if (opt.attacks) {
      const by = new Map();
      for (const r of P.attacks()) { const a = by.get(r.cc) || []; a.push(r); by.set(r.cc, a); }
      for (const [cc, list] of by) {
        const c = P.countryPoint(cc);
        if (!c) continue;
        list.forEach((r, k) => {
          const rad = 0.85 * Math.sqrt(k), ang = k * 2.399963;
          const ll = [c[0] + (rad * Math.cos(ang)) / Math.max(0.2, Math.cos(c[1] * deg)), clampLat(c[1] + rad * Math.sin(ang))];
          K.push({ row: r, ll, rad: 3.3, fresh: P.freshAtk(r), a: P.attackAlpha(r), ph: P.hash(r.victim + r.date + r.url) });
        });
      }
    }
    // NASA FIRMS thermal anomalies, as on the flat map.
    const F = [];
    if (opt.fires) for (const f of P.fires()) F.push({ f, ll: [f.lon, f.lat], r: f.novel ? 2.4 : Math.min(2.2, 1.1 + Math.sqrt(f.frp || 1) / 9), a: f.conf === 'l' ? 0.45 : f.conf === 'h' ? 0.95 : 0.75 });
    S.nodes = N; S.arcs = A; S.attrib = R; S.outs = O; S.atks = K; S.fires = F;
  }

  // ------------------------------------------------------------------ frame
  function schedule() { if (!raf && S && visible && !document.hidden) raf = requestAnimationFrame(frame); }
  function stop() { if (raf) cancelAnimationFrame(raf); raf = 0; }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) schedule(); });

  let drawn = 0;
  function frame(now) {
    raf = 0;
    if (!S || !S.cv.isConnected) { S = null; return; }
    // Idle turning and pulses redraw at about 30 frames a second; drags and fly-tos run at the display rate.
    if (!tween && !drag && now - drawn < 30) { schedule(); return; }
    drawn = now;
    const dt = last ? Math.min(64, now - last) : 16;
    last = now;
    const motion = P.opt.motion;
    if (tween) {
      // A frame's timestamp can precede the moment the tween was set within that frame, so q is clamped at 0.
      const q = Math.max(0, Math.min(1, (now - tween.t0) / tween.dur)), e = q < 0.5 ? 2 * q * q : 1 - Math.pow(-2 * q + 2, 2) / 2;
      rot = [tween.r0[0] + (tween.r1[0] - tween.r0[0]) * e, tween.r0[1] + (tween.r1[1] - tween.r0[1]) * e, 0];
      zoom = tween.k0 + (tween.k1 - tween.k0) * e;
      if (q >= 1) tween = null;
    // Idle turning waits while the pointer is over the globe or a record is selected, so what is read stays put.
    } else if (motion && !drag && !hover && !P.selected() && now - lastInput > 3000) rot = [rot[0] + dt * 0.0045, rot[1], 0];
    draw(now / 1000);
    if (motion || tween || drag || P.selected()) schedule();
  }

  function draw(t) {
    const { ctx, W, H, dpr, proj, path, PAL } = S, rgba = P.rgba, opt = P.opt;
    zoom = Math.max(0.7, Math.min(8, zoom));
    proj.rotate(rot).scale(S.R0 * zoom);
    const [cx, cy] = proj.translate(), R = proj.scale(), center = [-rot[0], -rot[1]];
    const d3g = window.d3geo;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    // Atmosphere and ocean.
    const halo = ctx.createRadialGradient(cx, cy, R * 0.96, cx, cy, R * 1.14);
    halo.addColorStop(0, rgba(PAL.dark ? [90, 150, 255] : PAL.fg, PAL.dark ? 0.22 : 0.07)); halo.addColorStop(1, rgba(PAL.bg, 0));
    ctx.fillStyle = halo; ctx.beginPath(); ctx.arc(cx, cy, R * 1.14, 0, Math.PI * 2); ctx.fill();
    const sea = ctx.createRadialGradient(cx - R * 0.35, cy - R * 0.35, R * 0.1, cx, cy, R);
    const panel = P.rgba(parseRgb(S.col('var(--color-panel)')), 1), bgc = S.col('var(--color-bg)');
    sea.addColorStop(0, PAL.dark ? 'rgba(22,36,52,1)' : panel); sea.addColorStop(1, PAL.dark ? 'rgba(6,12,20,1)' : bgc);
    ctx.beginPath(); path({ type: 'Sphere' }); ctx.fillStyle = sea; ctx.fill();
    ctx.beginPath(); path(S.grat); ctx.strokeStyle = S.col('var(--cds-chart-grid)'); ctx.lineWidth = 0.5; ctx.stroke();
    // Countries, shaded like the flat map.
    for (const f of S.host.features) { ctx.beginPath(); path(f); ctx.fillStyle = f._fill; ctx.fill(); }
    ctx.beginPath(); path(S.host.borders); ctx.strokeStyle = S.col('var(--color-border-line)'); ctx.lineWidth = 0.5; ctx.stroke();
    ctx.beginPath(); path({ type: 'Sphere' }); ctx.strokeStyle = S.col('var(--color-border-line)'); ctx.lineWidth = 1; ctx.stroke();

    const vis = { nodes: [], outs: [], arcs: [], theaters: [], atks: [], fires: [] };
    // z of a lon/lat on the unit sphere facing the viewer: cos of its angular distance from the centre.
    const zOf = (ll) => Math.cos(d3g.geoDistance(ll, center));
    const lifted = (ll, h) => { const p = proj(ll); return [cx + (p[0] - cx) * (1 + h), cy + (p[1] - cy) * (1 + h)]; };
    const showLifted = (z, h) => z > 0 || (1 + h) * Math.sqrt(Math.max(0, 1 - z * z)) > 1.002;
    const arcScreen = (a) => {
      const n = a.pts.length - 1, out = [];
      for (let i = 0; i <= n; i++) {
        const h = Math.sin(Math.PI * i / n) * a.lift, ll = a.pts[i], z = zOf(ll);
        out.push(showLifted(z, h) ? lifted(ll, h) : null);
      }
      return out;
    };
    const stroke = (pts, from, to) => {
      const n = pts.length - 1, i0 = Math.max(0, Math.floor(from * n)), i1 = Math.min(n, Math.ceil(to * n));
      let pen = false;
      for (let i = i0; i <= i1; i++) { const p = pts[i]; if (!p) { pen = false; continue; } if (pen) ctx.lineTo(p[0], p[1]); else { ctx.moveTo(p[0], p[1]); pen = true; } }
    };
    const at = (pts, u) => { const n = pts.length - 1, i = Math.max(0, Math.min(n, Math.round(u * n))); return pts[i]; };
    if (PAL.dark) ctx.globalCompositeOperation = 'lighter';
    // Outages.
    for (const o of S.outs) {
      if (zOf(o.ll) <= 0.02) continue;
      const [x, y] = proj(o.ll), on2 = o.o.ongoing;
      const g = ctx.createRadialGradient(x, y, 0, x, y, on2 ? 16 : 10);
      g.addColorStop(0, rgba(PAL.out, on2 ? 0.4 : 0.16)); g.addColorStop(1, rgba(PAL.out, 0));
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(x, y, on2 ? 16 : 10, 0, Math.PI * 2); ctx.fill();
      if (on2 && opt.motion) { const q = ((t / 3.2) + o.ph) % 1; ctx.strokeStyle = rgba(PAL.out, 0.7 * (1 - q)); ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(x, y, 6 + q * 22, 0, Math.PI * 2); ctx.stroke(); }
      vis.outs.push({ x, y, o });
    }
    // Thermal anomalies.
    for (const o of S.fires || []) {
      const z = zOf(o.ll);
      if (z <= 0.02) continue;
      const [x, y] = proj(o.ll);
      ctx.fillStyle = rgba(PAL.fire, o.a * Math.min(1, 0.35 + z));
      ctx.fillRect(x - o.r, y - o.r, o.r * 2, o.r * 2);
      if (o.f.novel) { ctx.strokeStyle = rgba(PAL.fire, 0.9); ctx.lineWidth = 1.1; ctx.beginPath(); ctx.arc(x, y, o.r + 3, 0, Math.PI * 2); ctx.stroke(); }
      vis.fires.push({ x, y, r: o.r, o });
    }
    // Attribution arcs (dashed) and conflict arcs (solid with comets).
    ctx.lineCap = 'round';
    for (const a of S.attrib) {
      const pts = arcScreen(a);
      ctx.setLineDash([3, 4]); ctx.strokeStyle = rgba(a.c, PAL.dark ? 0.34 : 0.28); ctx.lineWidth = a.w;
      ctx.beginPath(); stroke(pts, 0, 1); ctx.stroke(); ctx.setLineDash([]);
      if (opt.motion) { const p = at(pts, ((t / a.per) + a.ph) % 1); if (p) { const s = P.sprite(a.c, 1.6, true); ctx.drawImage(s.cv, p[0] - s.R, p[1] - s.R, s.R * 2, s.R * 2); } }
      vis.arcs.push({ pts, a, kind: 'attrib' });
    }
    for (const a of S.arcs) {
      const pts = arcScreen(a);
      ctx.strokeStyle = rgba(a.c, PAL.dark ? 0.45 : 0.36); ctx.lineWidth = a.w;
      ctx.beginPath(); stroke(pts, 0, 1); ctx.stroke();
      if (opt.motion) {
        const u = ((t / a.per) + a.ph) % 1, tail = 0.24;
        ctx.strokeStyle = rgba(a.c, 0.95); ctx.lineWidth = a.w + 1.2;
        const steps = 6;
        for (let k = 0; k < steps; k++) {
          const f0 = Math.max(0, u - tail + (tail * k) / steps), f1 = Math.max(0, u - tail + (tail * (k + 1)) / steps);
          ctx.globalAlpha = (k + 1) / steps; ctx.beginPath(); stroke(pts, f0, f1); ctx.stroke();
        }
        ctx.globalAlpha = 1;
        const p = at(pts, u);
        if (p) { const s = P.sprite(a.c, 2.2, true); ctx.drawImage(s.cv, p[0] - s.R, p[1] - s.R, s.R * 2, s.R * 2); }
        const end = pts[pts.length - 1];
        if (u > 0.9 && end) { const q = (u - 0.9) / 0.1; ctx.strokeStyle = rgba(a.c, 0.9 * (1 - q)); ctx.lineWidth = 1.4; ctx.beginPath(); ctx.arc(end[0], end[1], 3 + q * 13, 0, Math.PI * 2); ctx.stroke(); }
      }
      vis.arcs.push({ pts, a, kind: 'flow' });
    }
    // Infrastructure.
    for (const o of S.nodes) {
      const z = zOf(o.ll);
      if (z <= 0.02) continue;
      const [x, y] = proj(o.ll), c = PAL[o.n.layer], s = P.sprite(c, o.r, o.n.layer === 'c2' || o.n.layer === 'src');
      ctx.globalAlpha = (opt.family && !o.hit ? 0.08 : 1) * (o.n.stale ? 0.4 : 1) * Math.min(1, 0.35 + z);
      ctx.drawImage(s.cv, x - s.R, y - s.R, s.R * 2, s.R * 2);
      ctx.globalAlpha = 1;
      if (opt.motion && (o.n.new || (o.n.layer === 'c2' && o.n.status === 'online')) && (!opt.family || o.hit)) {
        const per = o.n.layer === 'c2' ? 2.6 : 3.4, q = ((t / per) + o.ph) % 1;
        ctx.strokeStyle = rgba(c, 0.75 * (1 - q)); ctx.lineWidth = 1.1; ctx.beginPath(); ctx.arc(x, y, o.r + 2 + q * (o.n.layer === 'c2' ? 14 : 9), 0, Math.PI * 2); ctx.stroke();
      }
      if (!opt.family || o.hit) vis.nodes.push({ x, y, r: o.r, o });
    }
    ctx.globalCompositeOperation = 'source-over';
    // Press-reported attacks, above the infrastructure and drawn without additive light so the hollow centre of a
    // leak-site match stays visible on dark ground.
    for (const o of S.atks) {
      const z = zOf(o.ll);
      if (z <= 0.02) continue;
      const [x, y] = proj(o.ll), s = P.gem(PAL.atk, o.rad, !!o.row.claimed_by);
      ctx.globalAlpha = o.a * (opt.family ? 0.3 : 1) * Math.min(1, 0.35 + z);
      ctx.drawImage(s.cv, x - s.R, y - s.R, s.R * 2, s.R * 2);
      ctx.globalAlpha = 1;
      if (opt.motion && o.fresh) { const q = ((t / 3) + o.ph) % 1; ctx.strokeStyle = rgba(PAL.atk, 0.75 * (1 - q)); ctx.lineWidth = 1.1; ctx.beginPath(); ctx.arc(x, y, o.rad * 1.3 + 2 + q * 11, 0, Math.PI * 2); ctx.stroke(); }
      vis.atks.push({ x, y, r: o.rad * 1.3, o });
    }
    // Theaters, with labels on the near side only.
    ctx.font = '12px ' + (getComputedStyle(S.box).fontFamily || 'sans-serif');
    ctx.textBaseline = 'middle';
    for (const m of S.host.theaters) {
      const z = zOf([m.lon, m.lat]);
      if (z <= 0.05) continue;
      const [x, y] = proj([m.lon, m.lat]), c = S.col(m.color), r = 4 + m.lv * 1.7;
      ctx.globalAlpha = Math.min(1, 0.3 + z);
      ctx.fillStyle = c; ctx.globalAlpha *= 0.3; ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fill();
      ctx.globalAlpha = Math.min(1, 0.3 + z); ctx.strokeStyle = c; ctx.lineWidth = 1.5; ctx.stroke();
      ctx.beginPath(); ctx.arc(x, y, 2.4, 0, Math.PI * 2); ctx.fill();
      ctx.globalAlpha = 1;
      vis.theaters.push({ x, y, r, z, m });
    }
    // Labels on the near side, highest level first, each placed right, left, above or below its marker where it
    // clears the labels already drawn; a label with no clear slot is left off (hover still names the theater).
    const boxes = [], hh = 14;
    for (const p of vis.theaters.slice().sort((a, b) => b.m.lv - a.m.lv)) {
      if (p.z <= 0.35) continue;
      const w = ctx.measureText(p.m.label).width;
      const slots = [[p.x + p.r + 4, p.y, 'left'], [p.x - p.r - 4 - w, p.y, 'left'], [p.x - w / 2, p.y - p.r - 9, 'left'], [p.x - w / 2, p.y + p.r + 10, 'left']];
      const s = slots.find(([lx, ly]) => !boxes.some((b) => lx < b[2] && lx + w > b[0] && ly - hh / 2 < b[3] && ly + hh / 2 > b[1]) && lx > 2 && lx + w < W - 2);
      if (!s) continue;
      const [lx, ly] = s;
      boxes.push([lx - 2, ly - hh / 2, lx + w + 2, ly + hh / 2]);
      ctx.globalAlpha = Math.min(1, 0.3 + p.z);
      ctx.lineWidth = 3; ctx.strokeStyle = S.col('var(--color-bg)'); ctx.strokeText(p.m.label, lx, ly);
      ctx.fillStyle = S.col('var(--color-fg)'); ctx.fillText(p.m.label, lx, ly);
      ctx.globalAlpha = 1;
    }
    // Selection.
    const sel = P.selected();
    if (sel && sel.ll && zOf(sel.ll) > 0) {
      const [x, y] = proj(sel.ll), q = (t % 1.6) / 1.6;
      ctx.strokeStyle = rgba(PAL.fg, 0.9); ctx.lineWidth = 1.5; ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.arc(x, y, 9 + q * 3, 0, Math.PI * 2); ctx.stroke(); ctx.setLineDash([]);
    }
    S.vis = vis;
  }
  const parseRgb = (c) => { const m = String(c).match(/rgba?\(([^)]+)\)/); return m ? m[1].split(/[\s,/]+/).filter(Boolean).slice(0, 3).map(Number) : [255, 255, 255]; };

  // ------------------------------------------------------------------ interaction
  function hit(x, y) {
    const v = S && S.vis;
    if (!v) return null;
    let best = null, bd = Infinity;
    for (const p of v.atks) { const d = Math.hypot(p.x - x, p.y - y); if (d < Math.max(5, p.r + 3) && d < bd) { bd = d; best = { kind: 'attack', o: p.o, ll: p.o.ll }; } }
    if (best) return best;
    for (const p of v.nodes) { const d = Math.hypot(p.x - x, p.y - y); if (d < Math.max(5, p.r + 3) && d < bd) { bd = d; best = { kind: 'node', o: p.o, ll: p.o.ll }; } }
    if (best) return best;
    for (const p of v.fires || []) { const d = Math.hypot(p.x - x, p.y - y); if (d < Math.max(4, p.r + 2) && d < bd) { bd = d; best = { kind: 'fire', o: p.o, ll: p.o.ll }; } }
    if (best) return best;
    for (const p of v.outs) { const d = Math.hypot(p.x - x, p.y - y); if (d < 10 && d < bd) { bd = d; best = { kind: 'outage', o: p.o, ll: p.o.ll }; } }
    if (best) return best;
    for (const p of v.theaters) { const d = Math.hypot(p.x - x, p.y - y); if (d < p.r + 4 && d < bd) { bd = d; best = { kind: 'theater', m: p.m }; } }
    if (best) return best;
    for (const g of v.arcs) for (let i = 0; i < g.pts.length; i += 2) {
      const p = g.pts[i]; if (!p) continue;
      const d = Math.hypot(p[0] - x, p[1] - y);
      if (d < 5 && d < bd) { bd = d; const a = g.a; best = { kind: g.kind, a, ll: g.kind === 'flow' ? [a.f.dst_lon, a.f.dst_lat] : P.countryPoint(a.pr.t) }; }
    }
    return best;
  }
  function country(x, y) {
    const ll = S.proj.invert([x, y]);
    if (!ll || window.d3geo.geoDistance(ll, [-rot[0], -rot[1]]) > Math.PI / 2) return null;
    return S.host.features.find((f) => window.d3geo.geoContains(f, ll)) || null;
  }
  function local(ev) { const r = S.cv.getBoundingClientRect(), k = r.width ? S.W / r.width : 1; return [(ev.clientX - r.left) * k, (ev.clientY - r.top) * k]; }
  function bind(cv) {
    if ('IntersectionObserver' in window) new IntersectionObserver((es) => { for (const e of es) visible = e.isIntersecting; if (visible) schedule(); }).observe(cv);
    cv.addEventListener('pointerdown', (ev) => {
      pointers.set(ev.pointerId, local(ev));
      cv.setPointerCapture(ev.pointerId);
      if (pointers.size === 2) { const [a, b] = [...pointers.values()]; drag = { pinch: Math.hypot(a[0] - b[0], a[1] - b[1]), k0: zoom }; return; }
      const [x, y] = local(ev);
      drag = { x, y, r0: rot.slice(), moved: 0 };
      tween = null; lastInput = performance.now(); schedule();
    });
    cv.addEventListener('pointermove', (ev) => {
      if (!S) return;
      const [x, y] = local(ev);
      if (pointers.has(ev.pointerId)) pointers.set(ev.pointerId, [x, y]);
      if (drag && drag.pinch && pointers.size === 2) {
        const [a, b] = [...pointers.values()];
        zoom = Math.max(0.7, Math.min(8, drag.k0 * Math.hypot(a[0] - b[0], a[1] - b[1]) / drag.pinch));
        lastInput = performance.now(); schedule(); return;
      }
      if (drag && !drag.pinch) {
        const sens = 0.28 / zoom, dx = x - drag.x, dy = y - drag.y;
        drag.moved = Math.max(drag.moved, Math.hypot(dx, dy));
        rot = [drag.r0[0] + dx * sens, clampLat(drag.r0[1] - dy * sens), 0];
        lastInput = performance.now(); S.host.tip().hide(); schedule(); return;
      }
      hover = true;
      const h = hit(x, y);
      if (h) {
        cv.style.cursor = 'pointer';
        const d = h.kind === 'theater' ? S.host.theaterTip(h.m.t) : P.describe(h);
        S.host.tip().show(d.head, d.lines, x, y);
        return;
      }
      cv.style.cursor = 'grab';
      const f = country(x, y);
      if (f) { const d = S.host.countryTip(f); S.host.tip().show(d.head, d.lines, x, y); } else S.host.tip().hide();
    });
    const end = (ev) => {
      pointers.delete(ev.pointerId);
      if (!drag) return;
      const wasClick = !drag.pinch && drag.moved < 4;
      drag = null;
      store.set('ti-globe-rot', rot.map((v) => Math.round(v * 10) / 10));
      if (!wasClick) return;
      const [x, y] = local(ev), h = hit(x, y);
      if (!h) { if (P.selected()) P.select(null); return; }
      if (h.kind === 'theater') { S.host.onTheater(h.m.t); return; }
      P.select(h); schedule();
    };
    cv.addEventListener('pointerup', end);
    cv.addEventListener('pointercancel', (ev) => { pointers.delete(ev.pointerId); drag = null; });
    cv.addEventListener('pointerleave', () => { hover = false; if (!drag && S) S.host.tip().hide(); schedule(); });
    cv.addEventListener('wheel', (ev) => {
      ev.preventDefault();
      zoom = Math.max(0.7, Math.min(8, zoom * Math.exp(-ev.deltaY * 0.0015)));
      lastInput = performance.now(); schedule();
    }, { passive: false });
    cv.addEventListener('keydown', (ev) => {
      const step = 8 / zoom;
      if (ev.key === 'ArrowLeft') rot = [rot[0] + step, rot[1], 0];
      else if (ev.key === 'ArrowRight') rot = [rot[0] - step, rot[1], 0];
      else if (ev.key === 'ArrowUp') rot = [rot[0], clampLat(rot[1] - step), 0];
      else if (ev.key === 'ArrowDown') rot = [rot[0], clampLat(rot[1] + step), 0];
      else if (ev.key === '+' || ev.key === '=') zoom = Math.min(8, zoom * 1.25);
      else if (ev.key === '-' || ev.key === '_') zoom = Math.max(0.7, zoom / 1.25);
      else return;
      ev.preventDefault(); lastInput = performance.now(); schedule();
    });
  }

  // Turn to a point and zoom in: the ticker, the tables and the reset button land here.
  GL.flyTo = (lon, lat, k = 2.2) => {
    if (!S) return;
    const r1 = [-lon, clampLat(-lat), 0];
    let dl = r1[0] - rot[0];
    while (dl > 180) dl -= 360;
    while (dl < -180) dl += 360;
    tween = { t0: performance.now(), dur: reduced ? 1 : 900, r0: rot.slice(), r1: [rot[0] + dl, r1[1], 0], k0: zoom, k1: Math.max(zoom, k) };
    lastInput = performance.now();
    schedule();
  };
  GL.reset = () => { if (!S) return; tween = { t0: performance.now(), dur: reduced ? 1 : 700, r0: rot.slice(), r1: [rot[0], -22, 0], k0: zoom, k1: 1 }; schedule(); };
  GL.focus = (it) => {
    if (!S) return;
    let h = null;
    if (it.node) { const o = S.nodes.find((x) => x.n === it.node || (x.n.ip === it.node.ip && x.n.port === it.node.port && x.n.layer === it.node.layer)); if (o) h = { kind: 'node', o, ll: o.ll }; else h = null; GL.flyTo(it.node.lon, it.node.lat); }
    else if (it.outage) { const c = P.countryPoint(it.outage.cc); if (c) { GL.flyTo(c[0], c[1], 1.8); const o = S.outs.find((x) => x.o === it.outage); if (o) h = { kind: 'outage', o, ll: o.ll }; } }
    else if (it.flow) { GL.flyTo(it.flow.dst_lon, it.flow.dst_lat, 1.8); const a = S.arcs.find((x) => x.f === it.flow); if (a) h = { kind: 'flow', a, ll: [it.flow.dst_lon, it.flow.dst_lat] }; }
    else if (it.attack) { const o = (S.atks || []).find((x) => P.sameAtk(x.row, it.attack)), c = o ? o.ll : P.countryPoint(it.attack.cc); if (c) GL.flyTo(c[0], c[1], 2.4); if (o) h = { kind: 'attack', o, ll: o.ll }; }
    if (h) P.select(h);
  };
  sync();
})();
