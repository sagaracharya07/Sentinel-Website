/* Admin Failed Processing — reuses the existing /api/admin/detections
   mailbox_action filter (Gmail sync marks failed messages 'scan_failed';
   see models.py's Scan.mailbox_action docstring) rather than a new endpoint. */
(function () {
  'use strict';
  const { esc, relTime, setState } = window.SentinelUI;
  const A = window.AdminUI;
  const body = document.getElementById('listBody');

  function render(rows) {
    if (!rows.length) {
      setState(body, 'empty', { title: 'No processing failures', msg: 'Nothing has failed to process recently.' });
      return;
    }
    body.innerHTML = '<div class="table-wrap"><table class="data cards-on-mobile"><thead><tr>' +
      '<th>Time</th><th>Sender</th><th>Subject</th><th>Source</th><th>Error</th><th></th></tr></thead><tbody>' +
      rows.map((r) =>
        '<tr>' +
        '<td data-label="Time" class="muted mono" style="font-size:.8rem">' + esc(relTime(r.scan_timestamp)) + '</td>' +
        '<td data-label="Sender">' + esc(r.from || '—') + '</td>' +
        '<td data-label="Subject">' + esc(r.subject || '(no subject)') + '</td>' +
        '<td data-label="Source" class="muted">' + esc(A.sourceLabel(r.source)) + '</td>' +
        '<td data-label="Error" class="muted" style="font-size:.8rem;max-width:280px">' + esc(r.mailbox_action_error || 'Marked scan_failed') + '</td>' +
        '<td data-label=""><a class="btn btn-sm btn-ghost" href="/admin/detections/' + encodeURIComponent(r.scan_id) + '">Open</a></td></tr>'
      ).join('') + '</tbody></table></div>';
  }

  async function load() {
    setState(body, 'loading');
    try { render(await SentinelAPI.detectionList({ mailbox_action: 'scan_failed', limit: 200 })); }
    catch (e) { setState(body, 'error', { title: 'Could not load failures', msg: e.message }); }
  }
  load();
})();
