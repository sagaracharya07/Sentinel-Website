/* My Reports — client-side filter over /api/reports/mine (already
   ownership-scoped server-side; there's no server-side filtering endpoint,
   so filters apply to the fetched set). */
(function () {
  'use strict';
  const { esc, relTime, setState } = window.SentinelUI;
  const P = window.PortalUI;

  const els = {
    body: document.getElementById('listBody'),
    search: document.getElementById('qSearch'),
    status: document.getElementById('fStatus'),
    verdict: document.getElementById('fVerdict'),
    count: document.getElementById('resultCount'),
  };
  let all = [];

  function apply() {
    const q = els.search.value.trim().toLowerCase();
    const status = els.status.value;
    const verdict = els.verdict.value;
    const rows = all.filter((r) => {
      const scan = r.scan || {};
      if (status && r.status !== status) return false;
      if (verdict && scan.classification !== verdict) return false;
      if (q) {
        const hay = ((scan.subject || '') + ' ' + (scan.from || '') + ' ' + (r.filename || '')).toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    render(rows);
  }

  function render(rows) {
    els.count.textContent = rows.length + (rows.length === 1 ? ' report' : ' reports');
    if (!rows.length) {
      setState(els.body, 'empty', { title: 'No reports match', msg: 'Try adjusting your filters, or report a new email.' });
      return;
    }
    els.body.innerHTML = '<div class="table-wrap"><table class="data cards-on-mobile"><thead><tr>' +
      '<th>Submitted</th><th>Sender</th><th>Subject</th><th>Automated</th><th>Status</th></tr></thead><tbody>' +
      rows.map((r) => {
        const scan = r.scan || {};
        return '<tr class="clickable" data-href="/app/reports/' + r.id + '" tabindex="0">' +
          '<td data-label="Submitted" class="muted mono" style="font-size:.8rem">' + esc(relTime(r.created_at)) + '</td>' +
          '<td data-label="Sender">' + esc(scan.from || '—') + '</td>' +
          '<td data-label="Subject">' + esc(scan.subject || r.filename || '(no subject)') + '</td>' +
          '<td data-label="Automated">' + P.verdictBadge(scan.classification) + '</td>' +
          '<td data-label="Status">' + P.reportStatusBadge(r) + '</td></tr>';
      }).join('') + '</tbody></table></div>';
    els.body.querySelectorAll('tr[data-href]').forEach((tr) => {
      const go = () => { window.location.href = tr.getAttribute('data-href'); };
      tr.addEventListener('click', go);
      tr.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
    });
  }

  let timer = null;
  [els.status, els.verdict].forEach((s) => s.addEventListener('change', apply));
  els.search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(apply, 250); });

  async function load() {
    setState(els.body, 'loading');
    try {
      all = await SentinelAPI.reportsMine();
      apply();
    } catch (e) {
      setState(els.body, 'error', { title: 'Could not load your reports', msg: e.message });
    }
  }
  load();
})();
