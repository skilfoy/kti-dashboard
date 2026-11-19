/* Entity graph (3.4.0). The overview (rising and new entities, the most named per type, the strongest co-mentions)
   comes from /api/graph; an entity's card, the entries two entities share and name lookup are /api/graph queries the
   collector answers from Postgres. The address holds the open entity: #graph?id=actor:G0007 opens the same card on
   any device. Co-mention is association in reporting; curated relationships are shown apart from it. */
(() => {
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const safeUrl = (u) => (/^https?:\/\//i.test(String(u || '')) ? String(u) : '#');
  const day = (s) => (s ? String(s).slice(0, 10) : '');
  const TYPE = { actor: ['Actor', '--h-c1'], extortion: ['Extortion group', '--h-c2'], malware: ['Malware', '--h-c3'], tool: ['Tool', '--h-c4'], campaign: ['Campaign', '--h-c5'],
    cve: ['CVE', '--color-bad'], vendor: ['Vendor', '--h-c6'], product: ['Product', '--color-warn'], country: ['Country', '--cds-chart-muted'] };
  const tname = (t) => (TYPE[t] || [t])[0];
  const tcol = (t) => `var(${(TYPE[t] || [0, '--cds-chart-muted'])[1]})`;
  const chip = (id, n, t, extra = '') => `<li><a class="ti-gchip" href="#graph?id=${encodeURIComponent(id)}" data-eid="${esc(id)}"><span class="ti-gdot" style="background:${tcol(t)}"></span>${esc(n)}${extra ? ` <span class="ti-dim">${extra}</span>` : ''}</a></li>`;
  const api = (qs) => fetch('/api/graph' + (qs ? '?' + qs : '')).then((r) => r.json().then((j) => ({ ok: r.ok, status: r.status, j }))).catch((e) => ({ ok: false, status: 0, j: { error: String(e) } }));
  const setHash = (id) => history.replaceState(null, '', '#graph' + (id ? '?id=' + encodeURIComponent(id) : ''));
  const state = { doc: null, open: null, types: new Set(['actor', 'extortion', 'malware', 'tool', 'campaign', 'cve', 'vendor', 'product', 'country']), edges: 150 };

  // ------------------------------------------------------------ overview
  const overview = async () => {
    const r = await api('');
    if (!r.ok) { $('graph-sum').textContent = 'The graph is not available yet: ' + (r.j.error || 'HTTP ' + r.status) + '.'; return; }
    const d = state.doc = r.j, rows = d.rows || [];
    const ents = rows.filter((x) => x.kind === 'entity'), byId = new Map(ents.map((e) => [e.id, e]));
    state.byId = byId;
    $('graph-sum').textContent = `${(d.entries_30d || 0).toLocaleString()} entries named at least one entity in the last 30 days; ${(d.entities || 0).toLocaleString()} entities named, ${d.edges || 0} co-mention edges shown, ${d.rising || 0} rising and ${d.new || 0} new this week. Gazetteer of ${(d.gazetteer && d.gazetteer.date) || 'unknown date'}; updated ${day(d.generated)} ${String(d.generated || '').slice(11, 16)} UTC.`;
    const risers = ents.filter((e) => e.rising).sort((a, b) => b.z - a.z);
    const wait = d.baseline_ready === false ? `<li class="ti-card-note">The rising and new lists start on ${esc(day(d.baseline_ready_at))}, once the collection (running since ${esc(day(d.collecting_since))}) gives each entity 14 days to compare against.</li>` : '';
    $('graph-rising-list').innerHTML = wait ? wait : risers.length ? risers.slice(0, 30).map((e) => chip(e.id, e.n, e.t, `${e.n7} entries, ${e.p7} publishers, z ${e.z}`)).join('') : '<li class="ti-card-note">Nothing rising past the threshold this week.</li>';
    const fresh = ents.filter((e) => e.new).sort((a, b) => b.n7 - a.n7);
    $('graph-new-list').innerHTML = wait ? '' : fresh.length ? fresh.slice(0, 30).map((e) => chip(e.id, e.n, e.t, `first ${day(e.first)}, ${e.n7} entries`)).join('') : '<li class="ti-card-note">No entity first named this week.</li>';
    const order = ['actor', 'extortion', 'malware', 'tool', 'cve', 'vendor', 'product', 'campaign'];
    $('graph-top-list').innerHTML = order.map((t) => {
      const list = ents.filter((e) => e.t === t && e.top_rank).sort((a, b) => a.top_rank - b.top_rank).slice(0, 10);
      return list.length ? `<div><h4 class="ti-h4">${esc(tname(t))}</h4><ul class="ti-gchips">${list.map((e) => chip(e.id, e.n, e.t, `${e.n7} / ${e.n30}`)).join('')}</ul></div>` : '';
    }).join('') + '<p class="ti-card-note">Entries in 7 days / 30 days.</p>';
    filters();
    network();
  };
  const filters = () => {
    $('graph-filters').innerHTML = Object.keys(TYPE).map((t) => `<button type="button" class="ti-chip" data-gt="${t}" aria-pressed="${state.types.has(t)}"><span class="ti-gdot" style="background:${tcol(t)}"></span>${esc(tname(t))}</button>`).join(' ')
      + ` <label class="ti-card-note">Edges <select id="graph-edges">${[60, 150, 300, 600].map((n) => `<option value="${n}"${n === state.edges ? ' selected' : ''}>${n}</option>`).join('')}</select></label>`;
    $('graph-edges').addEventListener('change', (e) => { state.edges = +e.target.value; network(); });
  };

  // A force layout of the strongest edges among the selected types. Nodes are sized by entries in 30 days.
  let sim = null;
  const forceGraph = (el, nodes, links, { height = 560, labels = 40, focus = null } = {}) => {
    el.innerHTML = '';
    if (!nodes.length) { el.innerHTML = '<p class="ti-card-note">No edges for the selected types.</p>'; return null; }
    const w = el.clientWidth || 900, h = height;
    const svg = d3.select(el).append('svg').attr('viewBox', [0, 0, w, h]).attr('width', '100%').attr('height', h).attr('role', 'img').attr('aria-label', `Graph of ${nodes.length} entities and ${links.length} links`);
    const g = svg.append('g');
    const zoom = d3.zoom().scaleExtent([0.2, 6]).on('zoom', (ev) => g.attr('transform', ev.transform));
    svg.call(zoom);
    const maxN = d3.max(nodes, (n) => n.size) || 1, r = d3.scaleSqrt().domain([0, maxN]).range([3, focus ? 16 : 22]);
    const maxE = d3.max(links, (l) => l.w) || 1;
    const s = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id((d) => d.id).distance((l) => 40 + 80 * (1 - Math.min(1, l.w / maxE))).strength(0.4))
      .force('charge', d3.forceManyBody().strength(focus ? -260 : -120))
      .force('collide', d3.forceCollide().radius((d) => r(d.size) + 3))
      .force('center', d3.forceCenter(w / 2, h / 2))
      .force('x', d3.forceX(w / 2).strength(0.06)).force('y', d3.forceY(h / 2).strength(0.09));
    const link = g.append('g').attr('class', 'ti-glinks').selectAll('line').data(links).join('line')
      .attr('stroke-width', (l) => 0.6 + 3 * (l.w / maxE)).attr('stroke-dasharray', (l) => (l.curated ? '4 3' : null));
    link.append('title').text((l) => l.title);
    const node = g.append('g').selectAll('g').data(nodes).join('g').attr('class', 'ti-gnode').attr('tabindex', 0).attr('role', 'button')
      .attr('aria-label', (d) => `${d.n}, ${tname(d.t)}`)
      .on('click', (ev, d) => openEntity(d.id)).on('keydown', (ev, d) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); openEntity(d.id); } })
      .call(d3.drag().on('start', (ev, d) => { if (!ev.active) s.alphaTarget(0.2).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (ev, d) => { d.fx = ev.x; d.fy = ev.y; }).on('end', (ev, d) => { if (!ev.active) s.alphaTarget(0); d.fx = null; d.fy = null; }));
    node.append('circle').attr('r', (d) => r(d.size)).attr('fill', (d) => tcol(d.t)).attr('stroke', (d) => (d.id === focus ? 'var(--color-fg)' : 'var(--color-panel)')).attr('stroke-width', (d) => (d.id === focus ? 2.5 : 1));
    node.append('title').text((d) => `${d.n} (${tname(d.t)}): ${d.size} entries`);
    const lab = new Set(nodes.slice().sort((a, b) => b.size - a.size).slice(0, labels).map((n) => n.id));
    if (focus) lab.add(focus);
    node.filter((d) => lab.has(d.id)).append('text').attr('dx', (d) => r(d.size) + 3).attr('dy', 4).text((d) => (d.n.length > 28 ? d.n.slice(0, 27) + '…' : d.n));
    s.on('tick', () => {
      link.attr('x1', (l) => l.source.x).attr('y1', (l) => l.source.y).attr('x2', (l) => l.target.x).attr('y2', (l) => l.target.y);
      node.attr('transform', (d) => `translate(${d.x},${d.y})`);
    });
    // Once the layout settles, fit every node in the frame (with room for labels on the right).
    s.on('end', () => {
      const xs = nodes.map((d) => d.x), ys = nodes.map((d) => d.y);
      const x0 = Math.min(...xs) - 30, x1 = Math.max(...xs) + 140, y0 = Math.min(...ys) - 30, y1 = Math.max(...ys) + 30;
      const k = Math.min(2, 0.95 * Math.min(w / (x1 - x0), h / (y1 - y0)));
      svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity.translate(w / 2 - k * (x0 + x1) / 2, h / 2 - k * (y0 + y1) / 2).scale(k));
    });
    return s;
  };
  const network = () => {
    const d = state.doc;
    if (!d) return;
    const byId = state.byId, edges = (d.rows || []).filter((x) => x.kind === 'edge' && state.types.has(x.at) && state.types.has(x.bt)).slice(0, state.edges);
    const ids = new Set(edges.flatMap((e) => [e.a, e.b]));
    const nodes = [...ids].map((id) => { const e = byId.get(id) || {}; return { id, n: e.n || id, t: e.t || id.split(':')[0], size: e.n30 || 1 }; });
    const links = edges.map((e) => ({ source: e.a, target: e.b, w: e.n * Math.max(0.05, e.npmi), title: `${e.an} and ${e.bn}: ${e.n} entries, ${e.p} publishers, NPMI ${e.npmi}` }));
    if (sim) sim.stop();
    sim = forceGraph($('graph-svg'), nodes, links);
    $('graph-legend').innerHTML = `${nodes.length} entities, ${links.length} edges. ` + Object.keys(TYPE).filter((t) => nodes.some((n) => n.t === t)).map((t) => `<span class="ti-gdot" style="background:${tcol(t)}"></span>${esc(tname(t))}`).join(' ');
  };

  // ------------------------------------------------------------ one entity
  let egoSim = null;
  const openEntity = async (id) => {
    if (!id) return;
    state.open = id;
    setHash(id);
    const card = $('graph-card');
    card.hidden = false;
    $('gc-title').textContent = 'Loading…';
    $('gc-meta').textContent = ''; $('gc-pair').hidden = true;
    card.scrollIntoView({ behavior: 'smooth', block: 'start' });
    const r = await api('id=' + encodeURIComponent(id));
    if (state.open !== id) return;
    if (!r.ok) { $('gc-title').textContent = id; $('gc-meta').textContent = r.status === 404 ? 'The collection has not named this entity yet.' : 'Not available: ' + (r.j.error || 'HTTP ' + r.status); for (const x of ['gc-series', 'gc-rel', 'gc-recent', 'gc-ego']) $(x).innerHTML = ''; $('gc-nb').tBodies[0].innerHTML = ''; return; }
    const c = r.j, e = c.entity, m = e.m || {};
    state.openName = e.n;
    $('gc-watch').setAttribute('aria-pressed', String(watched(e.id))); $('gc-watch').textContent = watched(e.id) ? 'Watching' : 'Watch';
    $('gc-title').innerHTML = `<span class="ti-gdot" style="background:${tcol(e.t)}"></span>${esc(e.n)} <span class="ti-pir">${esc(tname(e.t))}</span>`;
    const links = [m.url && `<a href="${esc(safeUrl(m.url))}" rel="noopener" target="_blank">ATT&amp;CK ${esc(m.attack || '')}</a>`, m.malpedia && `<a href="${esc(safeUrl(m.malpedia))}" rel="noopener" target="_blank">Malpedia</a>`,
      e.t === 'cve' && `<a href="https://www.cve.org/CVERecord?id=${encodeURIComponent(e.n)}" rel="noopener" target="_blank">CVE record</a>`, m.kev && `in CISA KEV since ${esc(m.kev)}`,
      m.leak && `leak-site group (${esc(m.status || 'listed')}, last claim ${esc(m.last || 'unknown')})`, m.cc && `attributed country ${esc(m.cc)}`].filter(Boolean);
    const aliases = (e.names || []).filter((n) => n !== e.n);
    $('gc-meta').innerHTML = [m.d ? esc(m.d) : '', `${c.entries} entries in ${c.days} days; first named ${esc(day(c.first_seen)) || 'not yet'}.`, links.join(' · '),
      aliases.length ? 'Also reported as: ' + esc(aliases.slice(0, 24).join(', ')) + (aliases.length > 24 ? '…' : '') : ''].filter(Boolean).join('<br>');
    const ser = c.series || [], max = Math.max(1, ...ser.map((x) => x.n));
    $('gc-series').innerHTML = ser.map((x) => `<span class="ti-sbar" style="height:${Math.max(4, Math.round((x.n / max) * 48))}px" title="${esc(x.day)}: ${x.n} entries, ${x.p} publishers"></span>`).join('');
    const nb = (c.co_mentioned || []).filter((x) => x.npmi > -0.2);
    $('gc-nb').tBodies[0].innerHTML = nb.length ? nb.slice(0, 40).map((x) => `<tr data-pair="${esc(x.id)}" tabindex="0"><td><a href="#graph?id=${encodeURIComponent(x.id)}" data-eid="${esc(x.id)}">${esc(x.n)}</a></td><td>${esc(tname(x.t))}</td><td>${x.entries}</td><td>${x.p}</td><td>${x.npmi}</td><td>${esc(day(x.last))}</td></tr>`).join('')
      : '<tr><td colspan="6" class="ti-card-note">No co-mentions in the window.</td></tr>';
    const rels = c.curated || [], REL = { uses: ['uses', 'used by'], 'attributed-to': ['attributed to', 'attributed from'], affects: ['affects', 'affected by'], 'made-by': ['made by', 'makes'] };
    $('gc-rel').innerHTML = rels.length ? rels.slice(0, 80).map((x) => `<li>${esc((REL[x.rel] || [x.rel, x.rel])[x.dir === 'out' ? 0 : 1])} ${x.id.startsWith('country:') ? esc(x.n) : `<a href="#graph?id=${encodeURIComponent(x.id)}" data-eid="${esc(x.id)}">${esc(x.n)}</a>`} <span class="ti-dim">${esc(tname(x.t))}, ${esc(x.basis.toUpperCase() === 'NAME' ? 'by name' : x.basis.toUpperCase())}</span></li>`).join('')
      : '<li class="ti-card-note">No curated relationship in the sources.</li>';
    $('gc-recent').innerHTML = (c.recent || []).map(hit).join('') || '<li class="ti-card-note">No entries kept.</li>';
    // The entity's neighbourhood: its 24 strongest co-mentions and its curated relationships.
    const top = nb.slice(0, 24), cur = rels.filter((x) => !top.some((t) => t.id === x.id)).slice(0, 16);
    const nodes = [{ id: e.id, n: e.n, t: e.t, size: Math.max(1, c.entries) }, ...top.map((x) => ({ id: x.id, n: x.n, t: x.t, size: x.entries })), ...cur.map((x) => ({ id: x.id, n: x.n, t: x.t, size: 1 }))];
    const lks = [...top.map((x) => ({ source: e.id, target: x.id, w: x.entries * Math.max(0.05, x.npmi), title: `${x.entries} entries, ${x.p} publishers, NPMI ${x.npmi}` })),
      ...cur.map((x) => ({ source: e.id, target: x.id, w: 1, curated: true, title: `${x.rel} (${x.basis})` }))];
    if (egoSim) egoSim.stop();
    egoSim = forceGraph($('gc-ego'), nodes, lks, { height: 380, labels: 30, focus: e.id });
  };
  const hit = (x) => `<li><a href="${esc(safeUrl(x.link))}" rel="noopener" target="_blank">${esc(x.title)}</a> <span class="ti-dim">${esc(x.host || '')} · ${esc(day(x.published))}${x.via ? ' · named as “' + esc(x.via) + '”' : ''}${x.via_a ? ' · “' + esc(x.via_a) + '” and “' + esc(x.via_b) + '”' : ''}</span></li>`;
  const openPair = async (b) => {
    const a = state.open;
    if (!a || !b) return;
    const r = await api(`a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`);
    $('gc-pair').hidden = false;
    $('gc-pair-h').textContent = r.ok ? `Entries naming both, 90 days: ${r.j.shared}${r.j.curated && r.j.curated.length ? ' (also linked by ' + r.j.curated.map((x) => x.rel + ', ' + x.basis).join('; ') + ')' : ''}` : 'Not available';
    $('gc-pair-list').innerHTML = r.ok ? (r.j.entries || []).map(hit).join('') : '';
    $('gc-pair').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  };

  // ------------------------------------------------------------ the visitor's watchlist (this browser only)
  const WKEY = 'kti.watchlist';
  const wl = {
    mem: null,
    get() {
      let o = wl.mem;
      try { const raw = localStorage.getItem(WKEY); if (raw) o = JSON.parse(raw); } catch { /* storage refused: the in-page copy */ }
      o = o || {};
      return { ids: Array.isArray(o.ids) ? o.ids.slice(0, 25) : [], names: o.names || {}, seen: o.seen || null };
    },
    set(o) { try { localStorage.setItem(WKEY, JSON.stringify(o)); } catch { /* storage refused: the list lasts this page view */ } wl.mem = o; },
  };
  const watched = (id) => wl.get().ids.includes(id);
  const toggleWatch = (id, name) => {
    const o = wl.get();
    if (o.ids.includes(id)) { o.ids = o.ids.filter((x) => x !== id); delete o.names[id]; } else if (o.ids.length < 25) { o.ids.push(id); o.names[id] = name; if (!o.seen) o.seen = new Date(Date.now() - 7 * 864e5).toISOString(); }
    wl.set(o);
    drawWatch();
  };
  const drawWatch = async () => {
    const o = wl.get(), card = $('graph-watch');
    card.hidden = !o.ids.length;
    if (state.open) { $('gc-watch').setAttribute('aria-pressed', String(watched(state.open))); $('gc-watch').textContent = watched(state.open) ? 'Watching' : 'Watch'; }
    if (!o.ids.length) return;
    $('gw-list').innerHTML = o.ids.map((id) => `<li><a class="ti-gchip" href="#graph?id=${encodeURIComponent(id)}" data-eid="${esc(id)}"><span class="ti-gdot" style="background:${tcol(id.split(':')[0])}"></span>${esc(o.names[id] || id)}</a></li>`).join('');
    const ids = encodeURIComponent(o.ids.join(','));
    $('gw-atom').href = `/api/watch?ids=${ids}&format=atom`;
    $('gw-sum').textContent = 'Checking…';
    const r = await fetch(`/api/watch?ids=${ids}${o.seen ? '&since=' + encodeURIComponent(o.seen) : ''}`).then((x) => x.json().then((j) => ({ ok: x.ok, j }))).catch((e) => ({ ok: false, j: { error: String(e) } }));
    if (!r.ok) { $('gw-sum').textContent = 'The watchlist is not available: ' + (r.j.error || 'no answer'); $('gw-events').innerHTML = ''; return; }
    const ev = r.j.events || [], kinds = { entry: 0, new_partner: 0, kev: 0, alert: 0 };
    for (const e of ev) kinds[e.kind] = (kinds[e.kind] || 0) + 1;
    $('gw-sum').textContent = ev.length ? `Since ${day(r.j.since)}: ${kinds.entry} entries, ${kinds.new_partner} first co-mentions, ${kinds.kev} KEV additions, ${kinds.alert} change alerts.` : `Nothing new since ${day(r.j.since)}.`;
    $('gw-events').innerHTML = ev.slice(0, 40).map((e) => e.kind === 'entry'
      ? `<li><a href="${esc(safeUrl(e.link))}" rel="noopener" target="_blank">${esc(e.title)}</a> <span class="ti-dim">${esc(e.entity_name)} · ${esc(e.host || '')} · ${esc(day(e.at))}</span></li>`
      : `<li><strong>${esc({ new_partner: 'New link', kev: 'KEV', alert: 'Alert' }[e.kind] || e.kind)}:</strong> ${e.partner ? `<a href="#graph?id=${encodeURIComponent(e.partner)}" data-eid="${esc(e.partner)}">${esc(e.title)}</a>` : esc(e.title)} <span class="ti-dim">${esc(day(e.at))}</span></li>`).join('');
  };

  // ------------------------------------------------------------ lookup
  let timer = null;
  const lookup = async (q, open) => {
    const t = $('graph-t').value;
    if (String(q).trim().length < 2) return;
    const r = await api(`q=${encodeURIComponent(q)}&t=${encodeURIComponent(t)}`);
    const hits = (r.ok && r.j.hits) || [];
    $('graph-suggest').innerHTML = hits.map((h) => `<option value="${esc(h.n)}">${esc(tname(h.t))}${h.n30 ? ', ' + h.n30 + ' entries in 30 days' : ''}</option>`).join('');
    if (!open) return;
    const exact = hits.find((h) => h.n.toLowerCase() === String(q).trim().toLowerCase());
    if (exact || hits.length === 1) { $('graph-hits').hidden = true; openEntity((exact || hits[0]).id); return; }
    $('graph-hits').hidden = false;
    $('graph-hits').innerHTML = hits.length ? hits.map((h) => chip(h.id, h.n, h.t, `${tname(h.t)}, ${h.n30} entries in 30 days`)).join('') : '<li class="ti-card-note">No entity by that name.</li>';
  };

  let wired = false;
  const wire = () => {
    if (wired) return;
    wired = true;
    $('graph-form').addEventListener('submit', (e) => { e.preventDefault(); lookup($('graph-q').value, true); });
    $('graph-q').addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => lookup($('graph-q').value, false), 250); });
    $('gc-watch').addEventListener('click', () => { if (state.open) toggleWatch(state.open, state.openName || state.open); });
    $('gw-seen').addEventListener('click', () => { const o = wl.get(); o.seen = new Date().toISOString(); wl.set(o); drawWatch(); });
    $('gc-close').addEventListener('click', () => { $('graph-card').hidden = true; state.open = null; setHash(null); });
    $('gc-copy').addEventListener('click', () => { const u = location.origin + '/#graph?id=' + encodeURIComponent(state.open || ''); (navigator.clipboard ? navigator.clipboard.writeText(u) : Promise.reject()).then(() => { $('gc-copy').textContent = 'Link copied'; setTimeout(() => ($('gc-copy').textContent = 'Copy link'), 2000); }).catch(() => prompt('Entity link', u)); });
    const page = $('graph');
    page.addEventListener('click', (e) => {
      const a = e.target.closest('[data-eid]');
      if (a) { e.preventDefault(); openEntity(a.getAttribute('data-eid')); return; }
      const f = e.target.closest('[data-gt]');
      if (f) { const t = f.getAttribute('data-gt'); if (state.types.has(t)) state.types.delete(t); else state.types.add(t); f.setAttribute('aria-pressed', String(state.types.has(t))); network(); return; }
      const p = e.target.closest('tr[data-pair]');
      if (p) openPair(p.getAttribute('data-pair'));
    });
    page.addEventListener('keydown', (e) => { const p = e.target.closest && e.target.closest('tr[data-pair]'); if (p && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); openPair(p.getAttribute('data-pair')); } });
    overview();
    drawWatch();
  };
  const fromHash = () => { const m = /^#graph\?id=([^&]+)/.exec(location.hash); if (m) openEntity(decodeURIComponent(m[1])); };
  TI.page('graph', () => { wire(); fromHash(); });
  // Links such as /#graph?id=actor:G0007, from search results or another page, open the page with the card.
  TI.openEntity = (id) => { TI.show('graph', false); setHash(id); fromHash(); };
  const openFromLink = () => { if (/^#graph\?/.test(location.hash)) TI.show('graph', false); };
  window.addEventListener('hashchange', openFromLink);
  setTimeout(openFromLink, 0);
})();
