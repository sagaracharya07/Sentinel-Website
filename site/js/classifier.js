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

  // Groups a finding's `type` (backend/ml/features.py's fixed set of
  // finding-type strings) into one of the three explanation sections the
  // scan/admin result views show. New finding types added later default
  // to "Content indicators" rather than silently vanishing from the UI.
  const FINDING_CATEGORIES = {
    'Sender / brand mismatch': 'Sender analysis',
    'Suspicious links': 'Link indicators',
    'Low-content message with link': 'Link indicators',
    'Urgency / pressure language': 'Content indicators',
    'Requests sensitive information': 'Content indicators',
    'Generic greeting': 'Content indicators',
    'Formatting anomalies': 'Content indicators',
  };

  function findingCategory(type) {
    return FINDING_CATEGORIES[type] || 'Content indicators';
  }

  // Single source of truth for the three-state verdict copy/color so
  // scan.js and admin.js never drift from each other.
  const VERDICT_COPY = {
    'Phishing': { title: 'Phishing detected', color: 'var(--threat)', chip: 'chip-threat',
      action: 'This message was automatically moved to the quarantine folder (live mailbox scans) or should not be trusted (manual scans). Do not click any links or reply.' },
    'Needs Review': { title: 'Needs review — uncertain', color: 'var(--warn)', chip: 'chip-warn',
      action: 'The model is not confident enough either way. It was flagged for analyst review, not quarantined. Treat with caution and verify the sender independently before acting on it.' },
    'Legitimate': { title: 'Looks legitimate', color: 'var(--safe)', chip: 'chip-safe',
      action: 'No action taken. As with any email, still verify unexpected requests for sensitive information or payments through a separate channel.' },
  };

  function verdictCopy(classification) {
    return VERDICT_COPY[classification] || VERDICT_COPY['Needs Review'];
  }

  return { highlight, escapeHtml, findingCategory, verdictCopy };
})();
