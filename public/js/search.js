/* Search and reports (3.0). One search across the platform's own analysis (authored judgments, evidence items,
   theaters, actors, indicators, read from /data) and the source network's collected entries (/api/search), and the
   agentic report generator (/api/report). The page state lives in the address: #search?q=...&days=... and
   #search?report=R-... open the same view on any device. */
(() => {
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const safeUrl = (u) => (/^https?:\/\//i.test(String(u || '')) ? String(u) : '#');
  const day = (s) => (s ? String(s).slice(0, 10) : '');
  const ago = (s) => { const m = (Date.now() - Date.parse(s)) / 60000; return !isFinite(m) ? '' : m < 90 ? Math.round(m) + ' min ago' : m < 2880 ? Math.round(m / 60) + ' h ago' : Math.round(m / 1440) + ' days ago'; };
  const TYPES = [['brief', 'Intelligence brief', 'BLUF, key judgments with likelihood and confidence, analysis, implications, indicators'],
    ['exec', 'Executive summary', 'One page for leadership: exposure, decisions, actions'],
    ['technical', 'Technical deep-dive', 'Attack chain, ATT&CK mapping, IOCs, detection and mitigation'],
    ['summary', 'Technical summary', 'Half a page: what, how, who, what to do'],
    ['practitioner', 'Practitioner report', 'Exposure checks, hunting leads, detection notes, response steps']];
  const CATS = { 'cyber-news': 'Security news', research: 'Research and CTI blogs', government: 'CERTs and agencies', vulnerability: 'Vulnerability sources', community: 'Community',
    geopolitics: 'Regional and world news', 'think-tank': 'Think tanks', maritime: 'Maritime', defense: 'Defense', 'topic-cyber': 'News search: cyber', 'topic-theater': 'News search: theaters', advisory: 'Advisories' };
  const state = { q: '', days: 30, cat: '', theater: '', offset: 0, hits: [], report: null, poll: null };
  const params = () => new URLSearchParams((location.hash.split('?')[1] || ''));
  const setHash = (p) => { const s = new URLSearchParams(p).toString(); history.replaceState(null, '', '#search' + (s ? '?' + s : '')); };

  // ------------------------------------------------------------ authored analysis, matched in the browser
  let AUTH = null;
  const loadAuthored = async () => {
    if (AUTH) return AUTH;
    const get = (n) => fetch('/data/' + n + '.json').then((r) => (r.ok ? r.json() : [])).catch(() => []);
    const [judgments, items, theaters, actors, indicators] = await Promise.all(['judgments', 'items', 'theaters', 'attack_groups', 'theater_indicators'].map(get));
    const rows = (x) => (Array.isArray(x) ? x : (x && x.rows) || []);
    AUTH = { judgments: rows(judgments), items: rows(items), theaters: rows(theaters), actors: rows(actors), indicators: rows(indicators) };
    return AUTH;
  };
  const terms = (q) => {
    const out = [];
    String(q).replace(/"([^"]+)"|(\S+)/g, (m, ph, w) => { const t = (ph || w || '').toLowerCase(); if (t && t !== 'or' && !t.startsWith('-')) out.push(t); return m; });
    return out;
  };
  const matches = (text, ts) => { const s = String(text || '').toLowerCase(); return ts.length && ts.every((t) => s.includes(t)); };
  const hl = (text, ts, max = 260) => {
    let s = String(text || '');
    if (s.length > max) { const i = Math.max(0, ts.map((t) => s.toLowerCase().indexOf(t)).filter((i) => i >= 0).sort((a, b) => a - b)[0] - 60 || 0); s = (i > 0 ? '…' : '') + s.slice(i, i + max) + (i + max < s.length ? '…' : ''); }
    let h = esc(s);
    for (const t of ts) h = h.replace(new RegExp('(' + esc(t).replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi'), '<mark>$1</mark>');
    return h;
  };
  const searchAuthored = async (q) => {
    const A = await loadAuthored(), ts = terms(q), out = [];
    for (const j of A.judgments) { const text = [j.judgment_id, j.title, j.situation, j.assessment, j.stakeholder, j.action, j.theater_id, j.vector, j.attribution_judgment].join(' '); if (matches(text, ts)) out.push({ kind: 'Key judgment', id: j.judgment_id, title: j.title, text: j.situation || j.assessment || '', go: ['theaters', null], meta: [j.likelihood, j.probability, j.theater_id].filter(Boolean).join(' · ') }); }
    for (const t of A.theaters) { const text = [t.theater_id, t.name, t.short, t.key_judgment, t.basis, t.cyber_nexus, t.so_what, t.outlook, t.countries].join(' '); if (matches(text, ts)) out.push({ kind: 'Theater', id: t.theater_id, title: t.name || t.short, text: t.key_judgment || t.so_what || '', go: ['theaters', null], meta: [t.threatcon, t.trend].filter(Boolean).join(' · ') }); }
    for (const a of A.actors) { const text = [a.name, a.aliases, a.summary, a.group_id, a.software, a.nexus].join(' '); if (matches(text, ts)) out.push({ kind: 'Actor (MITRE ATT&CK)', id: a.group_id || '', title: a.name, text: a.summary || '', go: ['actors', null], meta: [a.nexus, String(a.aliases || '').slice(0, 120)].filter(Boolean).join(' · ') }); }
    for (const i of A.indicators) { const text = [i.ind_id, i.indicator, i.note, i.theater_id, i.theater_name].join(' '); if (matches(text, ts)) out.push({ kind: 'Warning indicator', id: i.ind_id || '', title: i.indicator, text: i.note || '', go: ['theaters', null], meta: [i.theater_name, i.state, i.direction].filter(Boolean).join(' · ') }); }
    const items = A.items.filter((i) => matches([i.item_id, i.title, i.source_name, i.theater_id, i.theater_name, i.vector].join(' '), ts)).sort((a, b) => String(b.date).localeCompare(String(a.date)));
    for (const i of items.slice(0, 40)) out.push({ kind: 'Evidence item', id: i.item_id, title: i.title, text: '', url: i.url, meta: [day(i.date), i.source_name, i.theater_name, i.grade ? 'grade ' + i.grade : ''].filter(Boolean).join(' · ') });
    return { rows: out, ts, items: items.length };
  };
  const drawAuthored = (res) => {
    const box = $('search-intel'), list = $('search-intel-list');
    box.hidden = false;
    $('search-intel-n').textContent = res.rows.length ? res.rows.length + ' matches' : '';
    if (!res.rows.length) { list.innerHTML = '<p class="ti-card-note">Nothing in the platform\'s own analysis names this yet. The collected reporting below is unreviewed; a report generated from it is the fastest way to an assessment.</p>'; return; }
    list.innerHTML = '<ul class="ti-hits">' + res.rows.slice(0, 60).map((r) => `<li class="ti-hit"><div class="ti-hit-k">${esc(r.kind)}${r.id ? ' · <span class="ti-mono">' + esc(r.id) + '</span>' : ''}</div>
      <div class="ti-hit-t">${r.url ? `<a href="${esc(safeUrl(r.url))}" target="_blank" rel="noopener noreferrer">${hl(r.title, res.ts, 300)}</a>` : r.go ? `<a href="#${esc(r.go[0])}" data-go="${esc(r.go[0])}">${hl(r.title, res.ts, 300)}</a>` : hl(r.title, res.ts, 300)}</div>
      ${r.text ? `<div class="ti-hit-s">${hl(r.text, res.ts)}</div>` : ''}${r.meta ? `<div class="ti-hit-m">${esc(r.meta)}</div>` : ''}</li>`).join('') + '</ul>';
  };

  // ------------------------------------------------------------ collected reporting (server)
  const relLabel = (r) => (r == null ? '' : ['not relevant', 'low', 'relevant', 'high'][r] || '');
  const drawHits = (data, append) => {
    const ol = $('search-hits'), ts = terms(state.q);
    const groups = new Map();
    for (const h of data.hits) { const k = h.story || h.link; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(h); }
    const html = [...groups.values()].map((g) => {
      const h = g[0], also = [...new Set(g.slice(1).map((x) => x.source || x.host))].filter(Boolean);
      const chips = [CATS[h.category] || h.category, h.theater && h.theater !== 'T-GLB' ? h.theater : '', h.vector || '', h.relevance != null ? 'triage: ' + relLabel(h.relevance) : ''].filter(Boolean);
      const snip = String(h.snippet || '').replace(/«/g, '\u0001').replace(/»/g, '\u0002');
      return `<li class="ti-hit${h.relevance >= 2 ? ' ti-hit-hot' : ''}"><div class="ti-hit-t"><a href="${esc(safeUrl(h.link))}" target="_blank" rel="noopener noreferrer">${hl(h.title, ts, 400)}</a></div>
        <div class="ti-hit-m">${esc(h.source || h.host || '')} · ${esc(day(h.published))} <span class="ti-dim">(${esc(ago(h.published))})</span>${also.length ? ` · also carried by ${esc(also.slice(0, 5).join(', '))}${also.length > 5 ? ' and ' + (also.length - 5) + ' more' : ''}` : ''}</div>
        ${snip.trim() ? `<div class="ti-hit-s">${esc(snip).replace(/\u0001/g, '<mark>').replace(/\u0002/g, '</mark>')}</div>` : ''}
        <div class="ti-hit-c">${chips.map((c) => `<span class="ti-tag">${esc(c)}</span>`).join('')}${h.why ? ` <span class="ti-dim">${esc(h.why)}</span>` : ''}</div></li>`;
    }).join('');
    ol.innerHTML = (append ? ol.innerHTML : '') + html;
    $('search-results').hidden = false;
    $('search-more').hidden = data.hits.length < data.limit;
    $('search-hits-n').textContent = `${data.total} entries from ${data.publishers} publishers`;
  };
  const drawTimeline = (data) => {
    const el = $('search-timeline'), d = data.by_day || [];
    if (!d.length) { el.innerHTML = ''; return; }
    const max = Math.max(...d.map((x) => x.n));
    el.innerHTML = d.map((x) => `<span class="ti-sbar" style="height:${Math.max(4, Math.round((x.n / max) * 48))}px" title="${esc(x.day)}: ${x.n} entries, ${x.publishers} publishers"></span>`).join('');
  };
  const drawAdv = (data) => {
    const a = data.advisories || [];
    $('search-adv').hidden = !a.length;
    $('search-adv-list').innerHTML = a.map((x) => `<li class="ti-hit"><div class="ti-hit-t"><a href="${esc(safeUrl(x.link))}" target="_blank" rel="noopener noreferrer">${hl(x.title, terms(state.q), 300)}</a></div>
      <div class="ti-hit-m">${esc(x.source)} · ${esc(day(x.published))}${(TI.list(x.cves) || []).length ? ' · ' + esc(TI.list(x.cves).slice(0, 5).join(', ')) : ''}</div></li>`).join('');
  };
  const run = async (more) => {
    const q = state.q;
    if (!q || q.trim().length < 2) return;
    if (!more) { state.offset = 0; $('search-sum').textContent = 'Searching…'; }
    const u = `/api/search?${new URLSearchParams({ q, days: state.days, category: state.cat, region: state.theater, limit: 50, offset: state.offset })}`;
    const [res, auth] = await Promise.all([fetch(u).then((r) => r.json().catch(() => ({ error: 'unreadable answer' }))).catch((e) => ({ error: String(e) })), more ? null : searchAuthored(q)]);
    if (q !== state.q) return;
    if (auth) drawAuthored(auth);
    $('search-report').hidden = false;
    if (res.error) { $('search-sum').textContent = 'The collected-reporting search did not answer (' + res.error + '). The platform analysis above is unaffected.'; return; }
    drawHits(res, more);
    if (!more) {
      drawTimeline(res); drawAdv(res);
      const cats = Object.entries(res.by_category || {}).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${v} ${CATS[k] || k}`).join(', ');
      $('search-sum').textContent = res.total
        ? `${res.relaxed ? 'No entry carries every word; closest matches on the distinctive words. ' : ''}${res.total} collected entries from ${res.publishers} publishers in the last ${res.days} days, first seen ${day(res.first_seen)}, latest ${ago(res.last_seen)} (${cats}). ${auth && auth.rows.length ? auth.rows.length + ' matches in the platform\'s own analysis.' : ''}`
        : `Nothing collected in the last ${res.days} days matches. ${auth && auth.rows.length ? auth.rows.length + ' matches in the platform\'s own analysis.' : ''} A generated report also searches the live web and news.`;
    }
  };
  const submit = (q) => {
    state.q = String(q || '').trim().slice(0, 200);
    $('search-q').value = state.q;
    setHash({ q: state.q, ...(state.days !== 30 ? { days: state.days } : {}), ...(state.cat ? { cat: state.cat } : {}), ...(state.theater ? { theater: state.theater } : {}) });
    run(false);
  };

  // ------------------------------------------------------------ reports
  const inline = (s) => esc(s)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[^*])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, (m, t, u) => `<a href="${u}" target="_blank" rel="noopener noreferrer">${t}</a>`)
    .replace(/\[(\d{1,3})\]/g, '<a class="ti-cite" href="#rsrc-$1" data-cite="$1">[$1]</a>');
  // Markdown subset for model output: headings, paragraphs, lists, tables, quotes, code blocks. Everything is escaped
  // first; links are http(s) only.
  const md = (src) => {
    const L = String(src || '').replace(/\r/g, '').split('\n'), out = [];
    let i = 0;
    while (i < L.length) {
      const l = L[i];
      if (/^```/.test(l)) { const buf = []; i++; while (i < L.length && !/^```/.test(L[i])) buf.push(L[i++]); i++; out.push('<pre><code>' + esc(buf.join('\n')) + '</code></pre>'); continue; }
      const h = l.match(/^(#{1,6})\s+(.*)/);
      if (h) { const n = Math.min(6, h[1].length + 1); out.push(`<h${n}>${inline(h[2])}</h${n}>`); i++; continue; }
      if (/^\s*\|.*\|\s*$/.test(l) && i + 1 < L.length && /^\s*\|[\s:|-]+\|\s*$/.test(L[i + 1])) {
        const row = (x) => x.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
        const head = row(l); i += 2; const body = [];
        while (i < L.length && /^\s*\|.*\|\s*$/.test(L[i])) body.push(row(L[i++]));
        out.push('<div class="ti-tbox"><table class="ti-table"><thead><tr>' + head.map((c) => '<th>' + inline(c) + '</th>').join('') + '</tr></thead><tbody>' + body.map((r) => '<tr>' + r.map((c) => '<td>' + inline(c) + '</td>').join('') + '</tr>').join('') + '</tbody></table></div>');
        continue;
      }
      if (/^\s*([-*+]|\d+[.)])\s+/.test(l)) {
        const ordered = /^\s*\d+[.)]/.test(l), items = [];
        while (i < L.length && /^\s*([-*+]|\d+[.)])\s+/.test(L[i])) { let t = L[i].replace(/^\s*([-*+]|\d+[.)])\s+/, ''); i++; while (i < L.length && /^\s{2,}\S/.test(L[i]) && !/^\s*([-*+]|\d+[.)])\s+/.test(L[i])) t += ' ' + L[i++].trim(); items.push('<li>' + inline(t) + '</li>'); }
        out.push((ordered ? '<ol>' : '<ul>') + items.join('') + (ordered ? '</ol>' : '</ul>'));
        continue;
      }
      if (/^>\s?/.test(l)) { const buf = []; while (i < L.length && /^>\s?/.test(L[i])) buf.push(L[i++].replace(/^>\s?/, '')); out.push('<blockquote>' + inline(buf.join(' ')) + '</blockquote>'); continue; }
      if (/^\s*(---|\*\*\*)\s*$/.test(l)) { out.push('<hr>'); i++; continue; }
      if (!l.trim()) { i++; continue; }
      const buf = [l]; i++;
      while (i < L.length && L[i].trim() && !/^(#{1,6}\s|```|>|\s*([-*+]|\d+[.)])\s+|\s*\|)/.test(L[i])) buf.push(L[i++]);
      out.push('<p>' + inline(buf.join(' ')) + '</p>');
    }
    return out.join('\n');
  };
  const typeName = (t) => (TYPES.find((x) => x[0] === t) || [t, t])[1];
  const drawReport = (r) => {
    const v = $('report-view');
    v.hidden = false;
    $('report-title').textContent = `${typeName(r.type)}: ${r.q}`;
    const c = TI.obj(r.corpus) || {};
    const meta = [`Report ${r.id}`, 'requested ' + day(r.created_at)];
    if (r.status === 'done') meta.push(`written by ${r.model} in ${Math.round((Date.parse(r.done_at) - Date.parse(r.started_at || r.created_at)) / 1000)} s`, `${c.cited || 0} sources cited from ${c.cited_publishers || 0} publishers${c.further ? `, ${c.further} further publishers listed` : ''}; ${c.total || 0} platform entries from ${c.publishers || 0} publishers on the subject`);
    else if (r.status === 'failed') meta.push('failed: ' + (r.error || 'unknown error') + '. Use Retry to queue it again; the free models are sometimes saturated');
    else meta.push(r.status === 'queued' ? 'queued' : 'in progress');
    if (r.prompt) meta.push('direction: ' + r.prompt);
    $('report-meta').textContent = meta.join(' · ') + (r.status === 'done' ? '. Machine-written from the cited sources; unreviewed by an analyst.' : '');
    const steps = TI.list(r.steps) || [];
    $('report-steps').innerHTML = r.status === 'done' ? '' : steps.map((s) => `<li>${esc(String(s.at || '').slice(11, 19))} ${esc(s.text)}</li>`).join('') + (r.status === 'queued' || r.status === 'running' ? '<li class="ti-dim">Working…</li>' : '');
    $('report-body').innerHTML = r.body ? md(r.body) : '';
    const rb = $('report-retry');
    if (rb) rb.hidden = r.status !== 'failed';
    const src = TI.list(r.sources) || [];
    $('report-sources-h').hidden = !src.length;
    $('report-sources').innerHTML = src.map((s) => `<li id="rsrc-${s.n}" value="${s.n}"><a href="${esc(safeUrl(s.url_resolved || s.url))}" target="_blank" rel="noopener noreferrer">${esc(s.title)}</a> <span class="ti-dim">${esc(s.publisher || '')}${s.published ? ' · ' + esc(day(s.published)) : ''} · ${esc(s.role === 'further' ? 'further reporting' : String(s.via || '').replace(/^corpus(:subject)?$/, 'platform'))}</span></li>`).join('');
    state.report = r;
  };
  const openReport = async (id) => {
    clearTimeout(state.poll);
    setHash({ report: id });
    const tick = async () => {
      const r = await fetch('/api/report?id=' + encodeURIComponent(id)).then((x) => x.json()).catch((e) => ({ error: String(e) }));
      if (r.error) { $('report-view').hidden = false; $('report-meta').textContent = 'The report could not be read: ' + r.error; return; }
      drawReport(r);
      if (r.status === 'queued' || r.status === 'running') state.poll = setTimeout(tick, 4000);
      else loadLibrary();
    };
    await tick();
    $('report-view').scrollIntoView({ block: 'start' });
  };
  const generate = async () => {
    const type = (document.querySelector('input[name="report-type"]:checked') || {}).value || 'brief';
    const btn = $('report-go');
    btn.disabled = true; $('report-msg').textContent = 'Queuing…';
    const r = await fetch('/api/report', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ q: state.q, type, prompt: $('report-prompt').value }) })
      .then((x) => x.json()).catch((e) => ({ error: String(e) }));
    btn.disabled = false;
    if (r.error || !r.id) { $('report-msg').textContent = 'Not queued: ' + (r.error || 'no answer'); return; }
    $('report-msg').textContent = r.reused ? 'The same report was requested recently; opening it.' : 'Queued as ' + r.id + '.';
    openReport(r.id);
  };
  const loadLibrary = async () => {
    const r = await fetch('/api/report?list=1').then((x) => x.json()).catch(() => ({}));
    const list = (r.reports || []);
    $('report-list').innerHTML = list.length ? list.map((x) => `<li><a href="#search?report=${esc(x.id)}" data-report="${esc(x.id)}">${esc(typeName(x.type))}: ${esc(x.q)}</a> <span class="ti-dim">${esc(day(x.done_at))} · ${esc(x.model || '')}</span></li>`).join('')
      : '<li class="ti-card-note">No reports yet. Search for a subject and generate one.</li>';
  };

  // ------------------------------------------------------------ wiring
  let wired = false;
  const wire = async () => {
    if (wired) return;
    wired = true;
    $('report-types').innerHTML = TYPES.map(([v, n, d], i) => `<label class="ti-rtype"><input type="radio" name="report-type" value="${v}"${i ? '' : ' checked'}><span><strong>${esc(n)}</strong><br><span class="ti-dim">${esc(d)}</span></span></label>`).join('');
    $('search-cat').innerHTML = '<option value="">All</option>' + Object.entries(CATS).filter(([k]) => k !== 'advisory').map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join('');
    loadAuthored().then((A) => { $('search-theater').innerHTML = '<option value="">All</option>' + A.theaters.map((t) => `<option value="${esc(t.theater_id)}">${esc(t.short || t.name)} (${esc(t.theater_id)})</option>`).join(''); if (state.theater) $('search-theater').value = state.theater; });
    $('search-form').addEventListener('submit', (e) => { e.preventDefault(); state.days = +$('search-days').value; state.cat = $('search-cat').value; state.theater = $('search-theater').value; submit($('search-q').value); });
    for (const id of ['search-days', 'search-cat', 'search-theater']) $(id).addEventListener('change', () => { state.days = +$('search-days').value; state.cat = $('search-cat').value; state.theater = $('search-theater').value; if (state.q) submit(state.q); });
    $('search-more').addEventListener('click', () => { state.offset += 50; run(true); });
    $('report-go').addEventListener('click', generate);
    $('report-retry').addEventListener('click', async () => {
      const r = state.report; if (!r) return;
      $('report-retry').disabled = true;
      const x = await fetch('/api/report', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ q: r.q, type: r.type, prompt: r.prompt || '' }) }).then((y) => y.json()).catch((e) => ({ error: String(e) }));
      $('report-retry').disabled = false;
      if (x.id) openReport(x.id); else $('report-meta').textContent = 'Not queued: ' + (x.error || 'no answer');
    });
    $('report-close').addEventListener('click', () => { clearTimeout(state.poll); $('report-view').hidden = true; setHash(state.q ? { q: state.q } : {}); });
    $('report-copy').addEventListener('click', () => { const u = location.origin + '/#search?report=' + (state.report && state.report.id); (navigator.clipboard ? navigator.clipboard.writeText(u) : Promise.reject()).then(() => { $('report-copy').textContent = 'Link copied'; setTimeout(() => ($('report-copy').textContent = 'Copy link'), 2000); }).catch(() => prompt('Report link', u)); });
    $('report-md').addEventListener('click', () => {
      const r = state.report; if (!r) return;
      const src = (TI.list(r.sources) || []).map((s) => `${s.n}. [${s.title}](${s.url_resolved || s.url}) ${s.publisher || ''} ${day(s.published)}`).join('\n');
      const blob = new Blob([`# ${typeName(r.type)}: ${r.q}\n\n${r.body || ''}\n\n## Sources\n\n${src}\n\n_KTI report ${r.id}, machine-written by ${r.model}; unreviewed._\n`], { type: 'text/markdown' });
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = r.id + '.md'; document.body.append(a); a.click(); a.remove();
    });
    document.getElementById('search').addEventListener('click', (e) => {
      const g = e.target.closest('[data-go]'); if (g) { e.preventDefault(); TI.show(g.getAttribute('data-go')); return; }
      const r = e.target.closest('[data-report]'); if (r) { e.preventDefault(); openReport(r.getAttribute('data-report')); }
    });
    loadLibrary();
  };
  const fromHash = () => {
    const p = params();
    state.days = +(p.get('days') || 30); state.cat = p.get('cat') || ''; state.theater = p.get('theater') || '';
    $('search-days').value = String(state.days); $('search-cat').value = state.cat;
    if (p.get('report')) openReport(p.get('report'));
    if (p.get('q') && p.get('q') !== state.q) submit(p.get('q'));
  };
  TI.page('search', () => { wire().then(fromHash); });
  const hdr = $('hdr-search');
  if (hdr) hdr.addEventListener('submit', (e) => { e.preventDefault(); const q = $('hdr-q').value; TI.show('search'); wire().then(() => submit(q)); });
  // A link such as /#search?q=optimizely opens the page with the search run (boot.js opens tabs by plain id only).
  const openFromLink = () => { if (/^#search\?/.test(location.hash)) { TI.show('search', false); } };
  window.addEventListener('hashchange', openFromLink);
  setTimeout(openFromLink, 0);
})();
