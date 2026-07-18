/* User Overview — own-scoped data from /api/reports/mine. */
(function () {
  'use strict';
  const { esc, relTime, setState } = window.SentinelUI;
  const P = window.PortalUI;

  function metrics(reports) {
    const total = reports.length;
    const awaiting = reports.filter((r) => r.status !== 'reviewed').length;
    const phishing = reports.filter((r) => r.admin_verdict === 'Phishing').length;
    const legit = reports.filter((r) => r.admin_verdict === 'Legitimate').length;
    return [
      ['is-brand', total, 'Reports submitted'],
      ['is-review', awaiting, 'Awaiting review'],
      ['is-threat', phishing, 'Confirmed phishing'],
      ['is-safe', legit, 'Legitimate'],
    ];
  }

  function renderRecent(reports) {
    const el = document.getElementById('recentReports');
    if (!reports.length) {
      setState(el, 'empty', { title: 'No reports yet', msg: 'Reported emails will appear here.' });
      return;
    }
    const recent = reports.slice(0, 6);
    el.innerHTML = '<div class="table-wrap"><table class="data cards-on-mobile"><thead><tr>' +
      '<th>Submitted</th><th>Subject</th><th>Automated</th><th>Status</th></tr></thead><tbody>' +
      recent.map((r) => {
        const scan = r.scan || {};
        return '<tr class="clickable" data-href="/app/reports/' + r.id + '" tabindex="0">' +
          '<td data-label="Submitted" class="muted mono" style="font-size:.8rem">' + esc(relTime(r.created_at)) + '</td>' +
          '<td data-label="Subject">' + esc(scan.subject || r.filename || '(no subject)') + '</td>' +
          '<td data-label="Automated">' + P.verdictBadge(scan.classification) + '</td>' +
          '<td data-label="Status">' + P.reportStatusBadge(r) + '</td></tr>';
      }).join('') + '</tbody></table></div>';
    el.querySelectorAll('tr[data-href]').forEach((tr) => {
      const go = () => { window.location.href = tr.getAttribute('data-href'); };
      tr.addEventListener('click', go);
      tr.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
    });
  }

  async function load() {
    const grid = document.getElementById('metricGrid');
    try {
      const reports = await SentinelAPI.reportsMine();
      grid.innerHTML = metrics(reports).map(([cls, val, label]) =>
        '<div class="metric ' + cls + '"><div class="metric-label">' + esc(label) + '</div>' +
        '<div class="metric-value">' + val + '</div></div>'
      ).join('');
      renderRecent(reports);
    } catch (e) {
      setState(grid, 'error', { title: 'Could not load your reports', msg: e.message });
    }
  }
  load();
})();
