/* ==========================================================================
   PortalUI — shared helpers for the user portal (report/verdict badges,
   report lifecycle labels). Mirrors AdminUI's badge conventions so the same
   verdict always looks the same across both consoles.
   ========================================================================== */
(function () {
  'use strict';
  const esc = window.SentinelUI.esc;

  function verdictBadge(classification) {
    const map = {
      'Legitimate':   ['badge-legit', 'Legitimate'],
      'Needs Review': ['badge-review', 'Needs Review'],
      'Phishing':     ['badge-phish', 'Phishing'],
    };
    const [cls, label] = map[classification] || ['badge-muted', classification || 'Pending'];
    return '<span class="badge ' + cls + '"><span class="dot"></span>' + esc(label) + '</span>';
  }

  /* A report's user-facing lifecycle status, derived from EmailReport.status
     (pending|reviewed) + admin_verdict, matching the terminology guide:
     Submitted -> Awaiting Review -> Confirmed Phishing / Legitimate. */
  function reportStatusBadge(report) {
    if (report.status === 'reviewed') {
      if (report.admin_verdict === 'Phishing') return '<span class="badge badge-phish"><span class="dot"></span>Confirmed Phishing</span>';
      if (report.admin_verdict === 'Legitimate') return '<span class="badge badge-legit"><span class="dot"></span>Legitimate</span>';
      return '<span class="badge badge-muted">Closed</span>';
    }
    return '<span class="badge badge-review"><span class="dot"></span>Awaiting Review</span>';
  }

  function pct(x) {
    if (x === null || x === undefined || isNaN(x)) return '—';
    return Math.round(x * 100) + '%';
  }

  /* Same finding normalisation as AdminUI.findingHtml (kept independent so
     the portal never has to load admin/common.js) -- see admin/common.js for
     why evidence/detail are treated differently (one is pre-escaped, one isn't). */
  function findingHtml(f) {
    const title = f.summary || f.type || f.indicator || 'Signal';
    const severity = (f.severity || 'low').toLowerCase();
    let evidenceHtml = '';
    if (f.evidence != null && f.evidence !== '') evidenceHtml = f.evidence; // pre-escaped by the server
    else if (f.detail) evidenceHtml = esc(f.detail);
    return '<div class="finding"><span class="sev ' + esc(severity) + '"></span><div>' +
      '<div class="f-title">' + esc(title) + '</div>' +
      (evidenceHtml ? '<div class="f-evidence">' + evidenceHtml + '</div>' : '') +
      '</div></div>';
  }

  window.PortalUI = { verdictBadge, reportStatusBadge, pct, findingHtml };
})();
