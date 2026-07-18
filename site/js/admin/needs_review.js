/* Admin Needs Review queue — /api/admin/detections/needs-review. */
(function () {
  'use strict';
  const { esc, toast, relTime, setState } = window.SentinelUI;
  const A = window.AdminUI;
  const body = document.getElementById('queueBody');

  function render(rows) {
    if (!rows.length) {
      setState(body, 'empty', { title: 'Queue clear', msg: 'Nothing is waiting for review.' });
      return;
    }
    body.innerHTML =
      '<div class="table-wrap"><table class="data cards-on-mobile"><thead><tr>' +
      '<th>Age</th><th>Sender</th><th>Subject</th><th>Phishing prob.</th><th>Risk</th><th>Source</th><th>Actions</th>' +
      '</tr></thead><tbody>' +
      rows.map((r) =>
        '<tr>' +
        '<td data-label="Age" class="muted mono" style="font-size:.8rem">' + esc(relTime(r.scan_timestamp)) + '</td>' +
        '<td data-label="Sender">' + esc(r.from || '—') + '</td>' +
        '<td data-label="Subject">' + esc(r.subject || '(no subject)') + '</td>' +
        '<td data-label="Phishing prob." class="mono">' + A.pct(r.phishing_probability) + '</td>' +
        '<td data-label="Risk">' + A.riskBadge(r.risk_level) + '</td>' +
        '<td data-label="Source" class="muted">' + esc(A.sourceLabel(r.source)) + '</td>' +
        '<td data-label="Actions"><div class="row" style="gap:6px">' +
          '<a class="btn btn-sm btn-ghost" href="/admin/detections/' + encodeURIComponent(r.scan_id) + '">Open</a>' +
          '<button class="btn btn-sm btn-danger" data-confirm="' + esc(r.scan_id) + '">Phishing</button>' +
          '<button class="btn btn-sm btn-success" data-legit="' + esc(r.scan_id) + '">Legit</button>' +
        '</div></td></tr>'
      ).join('') + '</tbody></table></div>';
    wire();
  }

  function wire() {
    body.querySelectorAll('[data-confirm]').forEach((b) =>
      b.addEventListener('click', () => act(b, () => SentinelAPI.adminAction(b.getAttribute('data-confirm'), 'confirm'), 'Confirmed as phishing')));
    body.querySelectorAll('[data-legit]').forEach((b) =>
      b.addEventListener('click', () => act(b, () => SentinelAPI.submitFeedback(b.getAttribute('data-legit'), 'Legitimate'), 'Marked legitimate')));
  }

  async function act(btn, fn, okMsg) {
    btn.disabled = true;
    try { await fn(); toast(okMsg, 'ok'); load(); A.refreshSidebarCounts(); }
    catch (e) { toast('Action failed: ' + e.message, 'err'); btn.disabled = false; }
  }

  async function load() {
    setState(body, 'loading');
    try { render(await SentinelAPI.needsReviewList()); }
    catch (e) { setState(body, 'error', { title: 'Could not load queue', msg: e.message }); }
  }
  load();
})();
