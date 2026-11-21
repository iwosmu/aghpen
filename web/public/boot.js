// Applies the saved theme and language before the first paint. It is a file,
// not an inline script, because the server CSP is default-src 'self'.
/* global localStorage, document */
try {
  var t = localStorage.getItem('czujka.theme');
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
  var l = localStorage.getItem('czujka.lang');
  if (l === 'en' || l === 'pl') document.documentElement.lang = l;
} catch { /* storage is blocked: keep the defaults */ }
