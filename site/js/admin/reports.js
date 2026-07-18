/* Admin Reported Emails — /api/admin/reports (+ /review). */
(function () {
  'use strict';
  const { esc, toast, relTime, setState } = window.SentinelUI;
  const A = window.AdminUI;
  const body = document.getElementById('listBody');
  const countEl = document.getElementById('resultCount');
  let status = '';

  function render(rows) {
    countEl.textContent = rows.length + (rows.length === 1 ? ' report' : ' reports');
    if (!rows.length) {
      setState(body, 'empty', { title: 'No reports', msg: 'No employee-submitted reports match this filter.' });
      return;
    }
    body.innerHTML = '<div class="table-wrap"><table class="data cards-on-mobile"><thead><tr>' +
      '<th>Submitted</th><th>User</th><th>Sender</th><th>Subject</th><th>Automated</th><th>Final</th><th>Actions</th>' +
      '</tr></thead><tbody>' +
      rows.map((r) => {
        const scan = r.scan || {};
        return '<tr>' +
          '<td data-label="Submitted" class="muted mono" style="font-size:.8rem">' + esc(relTime(r.created_at)) + '</td>' +
          '<td data-label="User">' + esc(r.reporter_username) + '</td>' +
          '<td data-label="Sender">' + esc(scan.from || '—') + '</td>' +
          '<td data-label="Subject">' + esc(scan.subject || r.filename || '(no subject)') + '</td>' +
          '<td data-label="Automated">' + A.verdictBadge(scan.classification) + '</td>' +
          '<td data-label="Final">' + (r.admin_verdict ? A.verdictBadge(r.admin_verdict) : '<span class="badge badge-review">Pending</span>') + '</td>' +
          '<td data-label="Actions"><div class="row" style="gap:6px">' +
            (scan.scan_id ? '<a class="btn btn-sm btn-ghost" href="/admin/detections/' + encodeURIComponent(scan.scan_id) + '">Open</a>' : '') +
            '<button class="btn btn-sm btn-danger" data-review="' + r.id + '" data-verdict="Phishing">Phishing</button>' +
            '<button class="btn btn-sm btn-success" data-review="' + r.id + '" data-verdict="Legitimate">Legitimate</button>' +
          '</div></td></tr>';
      }).join('') + '</tbody></table></div>';
    body.querySelectorAll('[data-review]').forEach((b) => b.addEventListener('click', () => review(b)));
  }

  async function review(btn) {
    btn.disabled = true;
    try {
      await SentinelAPI.reviewReport(btn.getAttribute('data-review'), btn.getAttribute('data-verdict'));
      toast('Report reviewed', 'ok');
      load();
    } catch (e) {
      toast('Review failed: ' + e.message, 'err');
      btn.disabled = false;
    }
  }

  async function load() {
    setState(body, 'loading');
    try { render(await SentinelAPI.adminReports(status || undefined)); }
    catch (e) { setState(body, 'error', { title: 'Could not load reports', msg: e.message }); }
  }

  document.querySelectorAll('[data-status]').forEach((chip) => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('[data-status]').forEach((c) => c.classList.remove('active'));
      chip.classList.add('active');
      status = chip.getAttribute('data-status');
      load();
    });
  });

  load();
})();
