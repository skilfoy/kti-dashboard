/* Threatcasting on the Theaters page: the selected theater's three futures over six months, each a threatcast
   (person, place, activity, adversary's view, enabling conditions, effects) backcast to present milestones and
   preparedness actions, with signposts read against the analyst's current indicator states and, where the warning
   rules can measure an indicator now, the measured proposal beside it. The futures are drafts by a free hosted model
   accepted by deterministic checks (neon/parts/37p-foresight.mjs); the reading is a count of signposts met, never a
   forecast, and a match never confirms a future. */
(() => {
  const { h } = TI;
  const SRC = 'live_foresight';
  const KIND = { escalation: 'Escalation', continuation: 'Continuation', 'de-escalation': 'De-escalation' };
  const CAST = [['person', 'Who'], ['place', 'Where'], ['activity', 'Doing'], ['adversary', "Adversary's view"], ['enablers', 'Enabled by'], ['effects', 'Effects']];

  function signpost(s, measured) {
    const met = s.met === 1 ? 'met' : s.met === 0.5 ? 'half met' : s.met === 0 ? 'not met' : 'unknown';
    const m = measured.get(s.ind_id);
    return h('li', { class: 'ti-fs-sp' },
      h('span', { class: 'ti-mono', text: s.ind_id }), ' ',
      h('span', { text: s.indicator || '' }), ' ',
      h('span', { class: 'ti-muted', text: `expects ${s.expect}; now ` }),
      h('span', { class: 'ti-state', 'data-state': s.state || '', text: s.state || 'unknown' }),
      h('span', { class: `ti-fs-met ti-fs-${met.replace(' ', '-')}`, text: ` (${met})` }),
      m && m.proposal && !['No change', 'Cannot measure now'].includes(m.proposal) ? h('span', { class: 'ti-muted', text: `; measured: proposes ${m.proposal}` }) : null,
      s.url ? h('a', { href: s.url, target: '_blank', rel: 'noopener noreferrer', class: 'ti-fs-src', text: ' item' }) : null);
  }

  function future(r, measured) {
    const where = { set: r.set, future: r.future };
    const sps = TI.list(r.signposts), prop = TI.list(r.proposed), back = TI.list(r.backcast), acts = TI.list(r.actions), ev = TI.list(r.evidence), cast = TI.obj(r.threatcast);
    const lean = String(r.leans) === 'true';
    return h('article', { class: `ti-fs-col${lean ? ' ti-fs-lean' : ''}` },
      h('div', { class: 'ti-fs-kind' }, KIND[r.future] || r.future, r.of != null && +r.of ? h('span', { class: 'ti-muted', text: ` · ${r.met} of ${r.of} signposts met` }) : null, lean ? h('span', { class: 'ti-pir', text: 'indicators lean here' }) : null),
      TI.v('h4', SRC, 'name', where, r.name, 'ti-fs-name'),
      TI.v('p', SRC, 'narrative', where, r.narrative, 'ti-fs-text'),
      h('dl', { class: 'ti-fs-cast' }, ...CAST.filter(([k]) => cast[k]).flatMap(([k, l]) => [h('dt', { text: l }), h('dd', { text: cast[k] })])),
      h('div', { class: 'ti-fs-h', text: 'Signposts' }),
      h('ul', { class: 'ti-fs-list' }, ...sps.map((s) => signpost(s, measured)),
        ...prop.map((p) => h('li', { class: 'ti-fs-sp' }, h('span', { class: 'ti-pir', text: 'proposed' }), ' ', p.indicator, h('span', { class: 'ti-muted', text: ` (expects ${p.expect}; not yet an indicator)` })))),
      h('div', { class: 'ti-fs-h', text: 'Backcast, horizon to now' }),
      h('ol', { class: 'ti-fs-list' }, ...back.map((b) => h('li', {}, h('strong', { text: b.when + ': ' }), b.step))),
      h('div', { class: 'ti-fs-h', text: 'Preparedness now' }),
      h('ul', { class: 'ti-fs-list' }, ...acts.map((a) => h('li', { text: a }))),
      ev.length ? h('p', { class: 'ti-cap ti-muted' }, 'Builds on: ', ...ev.flatMap((e, i) => [i ? ', ' : '', e.url ? h('a', { href: e.url, target: '_blank', rel: 'noopener noreferrer', title: e.title || '', text: e.item_id }) : e.item_id])) : null);
  }

  TI.root.addEventListener('input', (ev) => { if (ev.target.id === 'fs-h') TI.draw('theaters'); });

  TI.foresight = {
    draw(sec, theaterId) {
      const box = sec.querySelector('#fs-body');
      if (!box) return;
      const note = sec.querySelector('#fs-note');
      if (TI.failed(SRC)) { TI.failLine(box); return; }
      if (!TI.ready(SRC)) { box.classList.add('dash-skeleton'); return; }
      box.classList.remove('dash-skeleton');
      TI.clear(box);
      const rows = TI.rows(SRC) || [];
      const hz = +((sec.querySelector('#fs-h') || {}).value || 6);
      // Rows from before 3.12.0 carry no horizon: they are six-month sets.
      const mine = rows.filter((r) => r.theater_id === theaterId && (+r.horizon_months || 6) === hz);
      const futs = mine.filter((r) => r.kind === 'future').sort((a, b) => ['escalation', 'continuation', 'de-escalation'].indexOf(a.future) - ['escalation', 'continuation', 'de-escalation'].indexOf(b.future));
      const reading = mine.find((r) => r.kind === 'reading');
      const tried = mine.filter((r) => r.kind === 'attempt');
      const sets = new Set(rows.filter((r) => r.kind === 'reading' && (+r.horizon_months || 6) === hz).map((r) => r.theater_id)).size;
      sec.querySelector('#fs-count').textContent = `${sets} ${sets === 1 ? 'theater' : 'theaters'} with ${hz}-month futures`;
      if (!futs.length) {
        const last = tried[0];
        box.append(h('p', { class: 'ti-muted', text: last ? `No accepted set yet. The last attempt (${TI.f.date(last.created_at)}) was ${last.outcome}${TI.list(last.failures).length ? ': ' + TI.list(last.failures).slice(0, 3).join('; ') : ''}.`
          : `Futures are drafted for theaters at ThreatCon 4 and above; this theater has no ${hz}-month set yet.` }));
        if (note) note.textContent = '';
        return;
      }
      let measured = new Map();
      try { const e = TI.warnEval && TI.warnEval(); if (e) measured = TI.index(e.inds, 'ind_id'); } catch { /* the warning rules are optional here */ }
      box.append(h('p', { class: 'ti-fs-reading' }, TI.v('span', SRC, 'text', { set: reading.set, kind: 'reading' }, reading.text),
        String(reading.current) === 'true' ? null : h('span', { class: 'ti-muted', text: ' The set was drafted before the latest change in this theater\'s level or indicator states; a new set follows within a day.' })));
      box.append(h('div', { class: 'ti-fs-grid' }, ...futs.map((r) => future(r, measured))));
      const rej = tried.filter((r) => r.outcome !== 'accepted').length;
      if (note) note.textContent = `Drafted ${TI.f.date(futs[0].drafted_at)} by ${futs[0].model || 'a free model'}, unreviewed; horizon ${futs[0].horizon_months} months.${rej ? ` ${rej} rejected ${rej === 1 ? 'attempt' : 'attempts'} for this theater in 60 days.` : ''}`;
    },
  };
})();
