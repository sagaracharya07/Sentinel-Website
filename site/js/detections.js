/* Admin detections/incidents page. Minimal + functional (Checkpoint 4). */
(function () {
  const $ = (id) => document.getElementById(id);
  let currentTab = 'all';

  function esc(s) {
    const d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
  }
  function fmt(ts) { try { return ts ? new Date(ts).toLocaleString() : '—'; } catch (e) { return ts; } }

  async function loadList() {
    $('loadError').style.display = 'none';
    try {
      let items;
      if (currentTab === 'quarantine') items = await SentinelAPI.quarantineList();
      else if (currentTab === 'needs-review') items = await SentinelAPI.needsReviewList();
      else if (currentTab === 'reported') items = (await SentinelAPI.adminReports()).map((r) => ({ ...(r.scan || {}), _report: r }));
      else items = await SentinelAPI.detectionList({ limit: 100 });
      renderList(items);
    } catch (e) {
      if (e.status === 403 || e.status === 401) $('loadError').style.display = 'block';
    }
  }

  function renderList(items) {
    const body = $('listBody');
    $('listEmpty').style.display = items.length ? 'none' : 'block';
    body.innerHTML = items.map((s) => {
      const rid = s._report ? ` data-report="${esc(s._report.id)}"` : '';
      return `<tr class="drow" data-scan="${esc(s.scan_id)}"${rid} style="border-top:1px solid rgba(255,255,255,.08);cursor:pointer">
        <td style="padding:6px 4px">${esc(s.from || s.sender || '—')}</td>
        <td>${esc(s.subject || '—')}</td>
        <td>${esc(s.classification || '—')}</td>
        <td>${esc(s.source || '—')}</td>
      </tr>`;
    }).join('');
    body.querySelectorAll('.drow').forEach((row) =>
      row.addEventListener('click', () => showIncident(row.dataset.scan, row.dataset.report)));
  }

  function findingsHtml(findings) {
    if (!findings || !findings.length) return '<div style="opacity:.6">No specific signals.</div>';
    return '<ul style="margin:6px 0 0 18px">' + findings.slice(0, 12).map((f) =>
      `<li><b>${esc(f.type || f.summary || f.indicator)}</b>${f.severity ? ` — ${esc(f.severity)}` : ''}${(f.detail || f.evidence) ? `: ${esc(f.detail || f.evidence)}` : ''}</li>`
    ).join('') + '</ul>';
  }

  async function showIncident(scanId, reportId) {
    const el = $('detail');
    el.innerHTML = 'Loading…';
    try {
      const d = await SentinelAPI.incidentDetail(scanId);
      const timeline = (d.timeline || []).map((t) =>
        `<li>${esc(fmt(t.timestamp))} — ${esc(t.actor)} ${esc(t.action)}</li>`).join('');
      let reviewControls = '';
      if (reportId) {
        reviewControls =
          `<div style="margin-top:12px;display:flex;gap:8px">
             <button class="btn btn-sm btn-danger" id="markPhish">Confirm phishing</button>
             <button class="btn btn-sm" id="markLegit">Mark legitimate</button>
           </div>`;
      }
      el.innerHTML =
        `<h3 style="margin:0 0 8px">Incident ${esc(d.scan_id)}</h3>
         <div><b>From:</b> ${esc(d.from || '—')}</div>
         <div><b>Subject:</b> ${esc(d.subject || '—')}</div>
         <div><b>Verdict:</b> ${esc(d.classification)} (${esc(d.risk_level)} risk) · <b>Source:</b> ${esc(d.source)}</div>
         <div><b>Mailbox action:</b> ${esc(d.mailbox_action || 'none')}${d.mailbox_action_error ? ` <span style="color:#e88">(${esc(d.mailbox_action_error)})</span>` : ''}</div>
         <div><b>Related messages:</b> ${esc(d.related_count)}</div>
         <div style="margin-top:10px"><b>Findings</b>${findingsHtml(d.findings)}</div>
         <div style="margin-top:10px"><b>Timeline</b><ul style="margin:6px 0 0 18px">${timeline || '<li style="opacity:.6">No recorded actions.</li>'}</ul></div>
         ${reviewControls}`;
      if (reportId) {
        $('markPhish').addEventListener('click', () => review(reportId, 'Phishing'));
        $('markLegit').addEventListener('click', () => review(reportId, 'Legitimate'));
      }
    } catch (e) {
      el.innerHTML = '<span style="color:#e88">Could not load incident.</span>';
    }
  }

  async function review(reportId, verdict) {
    try {
      await SentinelAPI.reviewReport(reportId, verdict);
      await loadList();
      $('detail').innerHTML = `<div>Recorded verdict: <b>${esc(verdict)}</b>.</div>`;
    } catch (e) { $('detail').innerHTML = '<span style="color:#e88">Review failed.</span>'; }
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.ftab').forEach((btn) =>
      btn.addEventListener('click', () => {
        currentTab = btn.dataset.tab;
        document.querySelectorAll('.ftab').forEach((b) => b.classList.remove('btn-primary'));
        btn.classList.add('btn-primary');
        loadList();
      }));
    document.querySelector('.ftab[data-tab="all"]').classList.add('btn-primary');
    loadList();
  });
})();
