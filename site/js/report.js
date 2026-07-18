/* Employee .eml reporting page (any logged-in user). Minimal + functional. */
(function () {
  const $ = (id) => document.getElementById(id);

  function esc(s) {
    const d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    // innerHTML escapes <>& ; also escape quotes for attribute-context safety.
    return d.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function fmt(ts) {
    if (!ts) return '—';
    try { return new Date(ts).toLocaleString(); } catch (e) { return ts; }
  }

  function renderResult(report) {
    const scan = report.scan || {};
    const findings = (scan.findings || []).slice(0, 8);
    const rows = findings.map((f) =>
      `<li><b>${esc(f.type || f.summary || f.indicator || 'Signal')}</b>${f.severity ? ` — ${esc(f.severity)}` : ''}${(f.detail || f.evidence) ? `: ${esc(f.detail || f.evidence)}` : ''}</li>`
    ).join('');
    $('uploadResult').innerHTML =
      `<div class="card" style="padding:14px">
         <div><b>Assessment:</b> ${esc(scan.classification || '—')} (${esc(scan.risk_level || '—')} risk)</div>
         <div style="opacity:.7;font-size:.85rem">Report #${esc(report.id)} · status ${esc(report.status)}</div>
         ${rows ? `<ul style="margin:8px 0 0 18px">${rows}</ul>` : '<div style="opacity:.6;margin-top:6px">No specific risk signals detected.</div>'}
       </div>`;
    $('uploadResult').style.display = 'block';
  }

  async function upload() {
    const file = $('emlFile').files[0];
    const msg = $('uploadMsg');
    msg.style.display = 'block';
    if (!file) { msg.textContent = 'Choose a .eml file first.'; return; }
    msg.textContent = 'Analysing…';
    try {
      const report = await SentinelAPI.reportUpload(file);
      msg.textContent = 'Reported successfully.';
      renderResult(report);
      $('emlFile').value = '';
      loadReports();
    } catch (e) {
      msg.textContent = '✗ ' + (e.message || 'Upload failed');
    }
  }

  async function loadReports() {
    try {
      const reports = await SentinelAPI.reportsMine();
      const body = $('reportsBody');
      if (!reports.length) {
        $('reportsEmpty').style.display = 'block';
        $('reportsTable').style.display = 'none';
        return;
      }
      $('reportsEmpty').style.display = 'none';
      $('reportsTable').style.display = 'table';
      body.innerHTML = reports.map((r) => {
        const scan = r.scan || {};
        return `<tr style="border-top:1px solid rgba(255,255,255,.08)">
          <td style="padding:6px 4px">${esc(fmt(r.created_at))}</td>
          <td>${esc(r.filename)}</td>
          <td>${esc(scan.classification || '—')}</td>
          <td>${esc(r.status)}</td>
          <td>${esc(r.admin_verdict || '—')}</td>
        </tr>`;
      }).join('');
    } catch (e) { /* not logged in / no reports */ }
  }

  document.addEventListener('DOMContentLoaded', function () {
    $('uploadBtn').addEventListener('click', upload);
    loadReports();
  });
})();
