/* Applies the viewer's saved theme before the page paints, so a dark choice never flashes light. */
try {
  const t = localStorage.getItem('ti-theme');
  if (t === 'dark' || t === 'light') document.documentElement.setAttribute('data-theme', t);
} catch (e) { /* storage blocked: follow the system setting */ }
