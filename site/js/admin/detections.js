/* Admin Detections — filtered table from /api/admin/detections. */
(function () {
  'use strict';
  const { esc, relTime, setState } = window.SentinelUI;
  const A = window.AdminUI;

  const els = {
    body: document.getElementById('detBody'),
    sender: document.getElementById('senderSearch'),
    classification: document.getElementById('fClassification'),
    status: document.getElementById('fStatus'),
    source: document.getElementById('fSource'),
    risk: document.getElementById('fRisk'),
    count: document.getElementById('resultCount'),
  };

  function params() {
    const p = {};
    if (els.classification.value) p.classification = els.classification.value;
    if (els.status.value) p.status = els.status.value;
    if (els.source.value) p.source = els.source.value;
    if (els.risk.value) p.risk_level = els.risk.value;
    if (els.sender.value.trim()) p.sender = els.sender.value.trim();
    p.limit = 200;
    return p;
  }

  function render(rows) {
    els.count.textContent = rows.length + (rows.length === 1 ? ' detection' : ' detections');
    if (!rows.length) {
      setState(els.body, 'empty', { title: 'No detections match', msg: 'Try clearing the filters.' });
      return;
    }
    els.body.innerHTML =
      '<div class="table-wrap"><table class="data cards-on-mobile"><thead><tr>' +
      '<th>Time</th><th>Sender</th><th>Subject</th><th>Phishing prob.</th>' +
      '<th>Verdict</th><th>Risk</th><th>Status</th><th>Source</th></tr></thead><tbody>' +
      rows.map((r) =>
        '<tr class="clickable" data-href="/admin/detections/' + encodeURIComponent(r.scan_id) + '" tabindex="0">' +
        '<td data-label="Time" class="muted mono" style="font-size:.8rem">' + esc(relTime(r.scan_timestamp)) + '</td>' +
        '<td data-label="Sender">' + esc(r.from || '—') + '</td>' +
        '<td data-label="Subject">' + esc(r.subject || '(no subject)') + '</td>' +
        '<td data-label="Phishing prob." class="mono">' + A.pct(r.phishing_probability) + '</td>' +
        '<td data-label="Verdict">' + A.verdictBadge(r.classification) + '</td>' +
        '<td data-label="Risk">' + A.riskBadge(r.risk_level) + '</td>' +
        '<td data-label="Status">' + esc(r.status || '—') + '</td>' +
        '<td data-label="Source" class="muted">' + esc(A.sourceLabel(r.source)) + '</td></tr>'
      ).join('') + '</tbody></table></div>';
    els.body.querySelectorAll('tr[data-href]').forEach((tr) => {
      const go = () => { window.location.href = tr.getAttribute('data-href'); };
      tr.addEventListener('click', go);
      tr.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
    });
  }

  let timer = null;
  async function load() {
    setState(els.body, 'loading');
    try {
      render(await SentinelAPI.detectionList(params()));
    } catch (e) {
      setState(els.body, 'error', { title: 'Could not load detections', msg: e.message });
    }
  }
  function debounced() { clearTimeout(timer); timer = setTimeout(load, 280); }

  [els.classification, els.status, els.source, els.risk].forEach((s) => s.addEventListener('change', load));
  els.sender.addEventListener('input', debounced);
  document.getElementById('clearFilters').addEventListener('click', () => {
    els.classification.value = els.status.value = els.source.value = els.risk.value = '';
    els.sender.value = '';
    load();
  });

  load();
})();
