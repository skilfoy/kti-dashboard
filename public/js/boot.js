/* Opens the place a link names (a tab or any element with an id), otherwise the Brief. */
(() => {
  const name = decodeURIComponent((location.hash || '').slice(1));
  const page = name ? TI.pageOf(name) : null;
  if (!page) { TI.show('brief', false); return; }
  if (page === name) { TI.show(page, false); return; }
  TI.show(page, false);
  const el = document.getElementById(name);
  if (el) el.scrollIntoView({ block: 'start' });
})();
