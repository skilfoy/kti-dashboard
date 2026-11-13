/* Opens the place a link names (a tab or any element with an id), otherwise the Brief. In-page links (#method-changes)
   follow the same rule when the hash changes, so a link can point into a page that is not open yet. */
(() => {
  const open = (fallback) => {
    const name = decodeURIComponent((location.hash || '').slice(1));
    const page = name ? TI.pageOf(name) : null;
    if (!page) { if (fallback) TI.show('brief', false); return; }
    TI.show(page, false);
    if (page === name) return;
    const el = document.getElementById(name);
    if (el) el.scrollIntoView({ block: 'start' });
  };
  open(true);
  window.addEventListener('hashchange', () => open(false));
})();
