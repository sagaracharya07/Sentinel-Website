/* Report Detail — /api/reports/<id> (ownership-enforced server-side: 403 if
   this isn't the reporter's own report and they aren't an admin). */
(function () {
  'use strict';
  const { esc, absTime, setState } = window.SentinelUI;
  const P = window.PortalUI;

  const root = document.getElementById('detailRoot');
  const reportId = root.getAttribute('data-report-id');

  function render(r) {
    const scan = r.scan || {};
    const findings = scan.findings || [];
    root.innerHTML =
      '<div class="card" style="margin-bottom:var(--sp-4)">' +
        '<div class="row-wrap" style="margin-bottom:var(--sp-3)">' + P.verdictBadge(scan.classification) + P.reportStatusBadge(r) +
          '<span class="badge badge-muted mono">Report #' + esc(r.id) + '</span></div>' +
        '<div class="kv" style="grid-template-columns:150px 1fr;gap:8px 16px">' +
          row('Submitted', esc(absTime(r.created_at))) +
          row('Filename', esc(r.filename || '—')) +
          row('Sender', esc(scan.from || '—')) +
          row('Subject', esc(scan.subject || '(no subject)')) +
          row('Phishing probability', P.pct(scan.phishing_probability)) +
          row('Prediction confidence', P.pct(scan.prediction_confidence)) +
          (r.reviewed_by ? row('Reviewed by', 'Administrator') : '') +
          (r.reviewed_at ? row('Reviewed at', esc(absTime(r.reviewed_at))) : '') +
        '</div>' +
      '</div>' +
      (r.status !== 'reviewed'
        ? '<div class="callout" style="margin-bottom:var(--sp-4)"><svg class="icon" aria-hidden="true"><use href="#i-alert"></use></svg>' +
          '<div>This report is awaiting administrator review. The final verdict will appear here once reviewed.</div></div>'
        : '') +
      '<section class="card">' +
        '<h3 style="margin-bottom:var(--sp-3)">Automated security findings</h3>' +
        (findings.length ? findings.map(P.findingHtml).join('') :
          '<div class="muted" style="font-size:.85rem">No specific risk signals detected.</div>') +
      '</section>';
  }
  function row(k, v) { return '<dt>' + esc(k) + '</dt><dd>' + v + '</dd>'; }

  async function load() {
    try {
      render(await SentinelAPI.reportDetail(reportId));
    } catch (e) {
      if (e.status === 403) setState(root, 'error', { title: 'Access denied', msg: "This isn't one of your reports." });
      else if (e.status === 404) setState(root, 'error', { title: 'Report not found', msg: 'It may have been removed.' });
      else setState(root, 'error', { title: 'Could not load report', msg: e.message });
    }
  }
  load();
})();
