/* Core runtime shared by every page script: formatting, marking, navigation, tables and chart helpers. */
(() => {
  const TI = (window.TI = {});
  const root = document.getElementById('ti');
  TI.root = root;

  // ---------------------------------------------------------------- formatting
  const fInt = d3.format(',');
  const fPct = d3.format('.0%');
  const fSigned = d3.format('+.0%');
  const bad = (v) => v == null || v === '' || (typeof v === 'number' && !isFinite(v));
  TI.f = {
    int: (v) => (bad(v) || isNaN(+v) ? '—' : fInt(+v)),
    pct: (v) => (bad(v) || isNaN(+v) ? '—' : fPct(+v)),
    signedPct: (v) => (bad(v) || isNaN(+v) ? '—' : fSigned(+v)),
    signedInt: (v) => (bad(v) || isNaN(+v) ? '—' : (+v > 0 ? '+' : '') + fInt(+v)),
    dec1: (v) => (bad(v) || isNaN(+v) ? '—' : d3.format('.1f')(+v)),
    dec2: (v) => (bad(v) || isNaN(+v) ? '—' : d3.format('.2f')(+v)),
    epss: (v) => (bad(v) || isNaN(+v) ? '—' : d3.format('.3f')(+v)),
    text: (v) => (bad(v) ? '—' : String(v)),
    date: (v) => (bad(v) ? '—' : String(v).slice(0, 10)),
  };
  TI.fmt = (name, v) => (TI.f[name] || TI.f.text)(v);
  TI.parseDay = (s) => (s ? new Date(String(s).slice(0, 10) + 'T00:00:00Z') : null);
  TI.dayLabel = d3.utcFormat('%b %-d');
  TI.monthLabel = d3.utcFormat('%b %Y');

  // ---------------------------------------------------------------- data access
  const BAD = ['error', 'connect', 'declined', 'missing'];
  TI.status = (id) => dash.data(id).status;
  TI.rows = (id) => {
    const d = dash.data(id);
    if (d.status !== 'ok') return null;
    const x = d.data;
    if (Array.isArray(x)) return x;
    if (x && Array.isArray(x.rows)) return x.rows;
    return [];
  };
  TI.ready = (...ids) => ids.every((id) => dash.data(id).status === 'ok');
  TI.failed = (...ids) => ids.some((id) => BAD.includes(dash.data(id).status));
  TI.index = (rows, key) => new Map((rows || []).map((r) => [r[key], r]));
  // The dashboard stores every row cell as a primitive: a list or a record in a loader's or a file's rows arrives as
  // its JSON text. These read a cell back as a list or a record whichever way it came: an array or object as is, JSON
  // text parsed, any other text split on the separator. Nothing here throws.
  TI.list = (v, sep = ',') => {
    if (v == null || v === '') return [];
    if (Array.isArray(v)) return v;
    if (typeof v === 'string') {
      const s = v.trim();
      if (s[0] === '[') { try { const a = JSON.parse(s); if (Array.isArray(a)) return a; } catch { /* plain text */ } }
      return s.split(sep).map((x) => x.trim()).filter(Boolean);
    }
    if (typeof v === 'object' && typeof v.length === 'number') return Array.from(v);
    return [v];
  };
  TI.obj = (v) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) return v;
    if (typeof v === 'string' && v.trim()[0] === '{') { try { const o = JSON.parse(v); if (o && typeof o === 'object' && !Array.isArray(o)) return o; } catch { /* not JSON */ } }
    return {};
  };

  // ---------------------------------------------------------------- DOM and marks
  TI.h = (tag, props = {}, ...kids) => {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const c of kids.flat()) {
      if (c == null || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  };
  const enc = (s) => String(s).replace(/%/g, '%25').replace(/&/g, '%26').replace(/=/g, '%3D');
  TI.where = (obj) => Object.entries(obj).map(([k, v]) => `${enc(k)}=${enc(v)}`).join('&');
  // A marked value: the smallest element that shows one cell of one source.
  TI.v = (tag, source, field, whereObj, text, cls) => {
    const el = TI.h(tag, { class: cls || null, text: text });
    el.setAttribute('data-source', source);
    if (field) el.setAttribute('data-field', field);
    if (whereObj) el.setAttribute('data-where', TI.where(whereObj));
    return el;
  };
  TI.clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
  TI.failLine = (el) => { TI.clear(el); el.append(TI.h('div', { class: 'ti-failed', text: 'Failed to load' })); };

  // Fill static placeholders: [data-source][data-field] with data-row or data-where, formatted by data-fmt.
  const decode = (s) => decodeURIComponent(s);
  TI.fillMarks = (scope) => {
    for (const el of scope.querySelectorAll('[data-source][data-field][data-fill]')) {
      const id = el.getAttribute('data-source');
      const st = dash.data(id).status;
      if (BAD.includes(st)) { el.classList.remove('dash-skeleton'); el.textContent = '—'; continue; }
      const rows = TI.rows(id);
      if (!rows) { el.classList.add('dash-skeleton'); continue; }
      el.classList.remove('dash-skeleton');
      let row = null;
      if (el.hasAttribute('data-row')) row = rows[+el.getAttribute('data-row')];
      else if (el.hasAttribute('data-where')) {
        const conds = el.getAttribute('data-where').split('&').map((p) => p.split('=').map(decode));
        row = rows.find((r) => conds.every(([k, v]) => String(r[k]) === v));
      }
      el.textContent = row ? TI.fmt(el.getAttribute('data-fmt') || 'text', row[el.getAttribute('data-field')]) : '—';
    }
  };

  // ---------------------------------------------------------------- pages and navigation
  const pages = {};
  TI.page = (id, draw) => { pages[id] = draw; };
  TI.visible = (id) => { const s = document.getElementById(id); return !!s && !s.hidden; };
  TI.mount = (id) => {
    const sec = document.getElementById(id);
    if (!sec) return null;
    const tpl = sec.querySelector(':scope > template');
    if (tpl) { sec.append(tpl.content.cloneNode(true)); tpl.remove(); }
    return sec;
  };
  TI.draw = (id) => {
    if (!pages[id] || !TI.visible(id)) return;
    pages[id](document.getElementById(id));
  };
  TI.show = (id, setLink = true) => {
    for (const s of root.querySelectorAll('.ti-page')) s.hidden = s.id !== id;
    for (const t of root.querySelectorAll('.ti-tab')) t.setAttribute('aria-selected', String(t.dataset.page === id));
    TI.mount(id);
    if (setLink) dash.setLink(id);
    TI.draw(id);
  };
  TI.pageOf = (elId) => {
    for (const s of root.querySelectorAll('.ti-page')) {
      if (s.id === elId) return s.id;
      if (s.querySelector('#' + CSS.escape(elId))) return s.id;
      const tpl = s.querySelector(':scope > template');
      if (tpl && tpl.content.querySelector('#' + CSS.escape(elId))) return s.id;
    }
    return null;
  };
  for (const t of root.querySelectorAll('.ti-tab')) t.addEventListener('click', () => TI.show(t.dataset.page));
  TI.go = (pageId, elId) => {
    TI.show(pageId, !elId);
    if (elId) {
      const el = document.getElementById(elId);
      if (el) { el.scrollIntoView({ block: 'start' }); dash.setLink(elId); }
    }
  };

  // ---------------------------------------------------------------- tables
  // cols: [{field, label, fmt, num, cls, source (calc id for a computed column), get (row) => value, hideSm}]
  TI.table = (table, rows, cols, opts = {}) => {
    const state = table._ti || (table._ti = { sort: opts.sort || null, dir: opts.dir || 'desc' });
    table._args = [rows, cols, opts];
    if (!table.tHead) {
      const tr = table.createTHead().insertRow();
      for (const c of cols) {
        const th = TI.h('th', { scope: 'col', 'data-field': c.field, 'data-source': c.source || null, class: [c.num ? 'ti-num' : '', c.hideSm ? 'ti-hide-sm' : ''].join(' ').trim() || null });
        const b = TI.h('button', { type: 'button', text: c.label });
        b.addEventListener('click', () => {
          if (state.sort === c.field) state.dir = state.dir === 'asc' ? 'desc' : 'asc';
          else { state.sort = c.field; state.dir = c.num ? 'desc' : 'asc'; }
          TI.table(table, ...table._args);
        });
        th.append(b);
        tr.append(th);
      }
    }
    for (const th of table.tHead.rows[0].cells) {
      th.setAttribute('aria-sort', th.getAttribute('data-field') === state.sort ? (state.dir === 'asc' ? 'ascending' : 'descending') : 'none');
    }
    const getv = (c, r) => (c.get ? c.get(r) : r[c.field]);
    let list = (rows || []).slice();
    if (opts.filter) list = list.filter(opts.filter);
    if (state.sort) {
      const c = cols.find((x) => x.field === state.sort);
      if (c) {
        const sgn = state.dir === 'asc' ? 1 : -1;
        list.sort((a, b) => {
          const x = getv(c, a), y = getv(c, b);
          if (x == null || x === '') return 1;
          if (y == null || y === '') return -1;
          return (c.num ? (+x - +y) : String(x).localeCompare(String(y))) * sgn;
        });
      }
    }
    const total = list.length;
    if (opts.limit && list.length > opts.limit) list = list.slice(0, opts.limit);
    const tb = document.createElement('tbody');
    const key = table.getAttribute('data-row-key');
    const keys = key ? key.split(',') : [];
    for (const r of list) {
      const tr = document.createElement('tr');
      if (keys.length) tr.setAttribute('data-key', keys.map((k) => (keys.length > 1 ? enc(r[k]) : String(r[k]))).join(','));
      if (opts.selected != null && keys.length && String(r[keys[0]]) === String(opts.selected)) tr.className = 'ti-sel';
      for (const c of cols) {
        const td = document.createElement('td');
        const cls = [c.num ? 'ti-num' : '', c.cls || '', c.hideSm ? 'ti-hide-sm' : ''].join(' ').trim();
        if (cls) td.className = cls;
        const v = getv(c, r);
        if (c.link && r[c.link]) {
          td.append(TI.h('a', { href: r[c.link], target: '_blank', rel: 'noopener noreferrer', text: TI.fmt(c.fmt, v) }));
        } else {
          td.textContent = TI.fmt(c.fmt, v);
        }
        if (c.attr) for (const [k, fn] of Object.entries(c.attr)) td.setAttribute(k, fn(r));
        tr.append(td);
      }
      if (opts.onClick) tr.addEventListener('click', () => opts.onClick(r));
      tb.append(tr);
    }
    if (!list.length) {
      const tr = document.createElement('tr');
      const td = TI.h('td', { colspan: String(cols.length), class: 'ti-empty', text: opts.empty || 'No rows match.' });
      tr.append(td);
      tb.append(tr);
    }
    if (table.tBodies[0]) table.replaceChild(tb, table.tBodies[0]); else table.append(tb);
    if (opts.countEl) opts.countEl.textContent = opts.limit && total > opts.limit ? `Showing ${fInt(opts.limit)} of ${fInt(total)}` : `${fInt(total)} rows`;
    return total;
  };
  // A table whose source failed or is loading
  TI.tableState = (table, ids) => {
    const box = table.closest('.ti-tbox') || table.parentElement;
    if (TI.failed(...ids)) {
      table.hidden = true;
      if (!box.querySelector('.ti-failed')) box.append(TI.h('div', { class: 'ti-failed', text: 'Failed to load' }));
      return false;
    }
    table.hidden = false;
    const f = box.querySelector('.ti-failed');
    if (f) f.remove();
    if (!TI.ready(...ids)) { box.classList.add('dash-skeleton'); return false; }
    box.classList.remove('dash-skeleton');
    return true;
  };
  TI.search = (input) => {
    const q = (input && input.value || '').trim().toLowerCase();
    return (r, fields) => !q || fields.some((f) => String(r[f] ?? '').toLowerCase().includes(q));
  };

  // ---------------------------------------------------------------- charts
  TI.svg = (box, height) => {
    TI.clear(box);
    box.classList.remove('dash-skeleton');
    const w = Math.max(280, box.clientWidth || 600);
    const svg = d3.select(box).append('svg').attr('width', '100%').attr('viewBox', `0 0 ${w} ${height}`).attr('height', height).attr('role', 'img');
    return { svg, w, h: height };
  };
  TI.textWidth = (svg, strings) => {
    const t = svg.append('text').attr('class', 'ti-measure');
    let m = 0;
    for (const s of strings) { t.text(s); m = Math.max(m, t.node().getComputedTextLength()); }
    t.remove();
    return Math.ceil(m);
  };
  TI.tip = (box) => {
    let tip = box.querySelector(':scope > .ti-tip');
    if (!tip) { tip = TI.h('div', { class: 'ti-tip', hidden: true }); box.append(tip); }
    return {
      show(head, lines, x, y) {
        TI.clear(tip);
        tip.append(TI.h('div', { class: 'ti-tip-h', text: head }));
        for (const l of lines) {
          const row = TI.h('div');
          if (l.color) { const sw = TI.h('span', { class: 'ti-sw' }); sw.style.background = l.color; row.append(sw); }
          row.append(l.text);
          tip.append(row);
        }
        tip.hidden = false;
        const bw = box.clientWidth, tw = tip.offsetWidth, th = tip.offsetHeight;
        tip.style.left = Math.max(0, Math.min(bw - tw, x + 12)) + 'px';
        tip.style.top = Math.max(0, y - th - 8) + 'px';
      },
      hide() { tip.hidden = true; },
    };
  };
  TI.chartState = (box, ids) => {
    if (TI.failed(...ids)) { TI.failLine(box); return false; }
    if (!TI.ready(...ids)) { TI.clear(box); box.classList.add('dash-skeleton'); return false; }
    box.classList.remove('dash-skeleton');
    return true;
  };
  TI.color = (i) => dash.colors[i % dash.colors.length];
  // Resolve a CSS color token to rgb() so d3 can interpolate it; `within` resolves it where a subtree overrides tokens.
  TI.resolve = (c, within) => {
    const probe = TI.h('span');
    probe.style.color = c;
    (within || root).append(probe);
    const v = getComputedStyle(probe).color;
    probe.remove();
    return v;
  };
  TI.lvClass = (lv) => 'ti-badge ti-lv' + lv;
  TI.LEVEL_VAR = { 5: 'var(--ti-crit)', 4: 'var(--ti-high)', 3: 'var(--ti-elev)', 2: 'var(--ti-guard)', 1: 'var(--ti-norm)' };
})();
