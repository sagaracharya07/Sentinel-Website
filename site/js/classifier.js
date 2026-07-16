/* ==========================================================================
   Sentinel display helpers.

   IMPORTANT: this file used to contain the client-side heuristic
   classifier (keyword lists, scoring). That logic has moved server-side
   into backend/ml/features.py + backend/ml/train.py, where a trained
   Random Forest model now does the actual classification (see
   SentinelAPI.scan() in js/api.js). What remains here is purely
   presentational: safely escaping text and wrapping the exact terms the
   backend flagged (`result.highlights`) in <mark> so the UI can show the
   user *why* an email was flagged, without duplicating detection logic
   in two places.
   ========================================================================== */
const Sentinel = (() => {

  function escapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  function escapeHtml(str) {
    return (str || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // Wraps each string in `terms` (as returned by the backend's /api/scan
  // response, field `highlights`) in <mark> for on-screen annotation.
  // Input is HTML-escaped first so pasted content can never inject markup.
  function highlight(rawText, terms) {
    let text = escapeHtml(rawText || '');
    (terms || []).forEach(t => {
      if (!t) return;
      const re = new RegExp('(' + escapeRegex(t) + ')', 'ig');
      text = text.replace(re, '<mark>$1</mark>');
    });
    return text;
  }

  return { highlight, escapeHtml };
})();
