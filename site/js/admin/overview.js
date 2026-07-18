/* Admin Overview — real data from /api/stats, /api/admin/gmail/status,
   /api/admin/detections, /api/admin/audit-log. */
(function () {
  'use strict';
  const { esc, toast, relTime, setState } = window.SentinelUI;
  const A = window.AdminUI;

  async function loadProtection() {
    const panel = document.getElementById('protectionPanel');
    try {
      const data = await SentinelAPI.gmailStatus();
      const c = data.connection;
      if (!c) {
        panel.innerHTML =
          '<div class="row-wrap"><span class="status-dot off"></span>' +
          '<div><strong>No mailbox connected</strong>' +
          '<div class="muted" style="font-size:.85rem">Connect a Gmail mailbox to start automatic monitoring.</div></div>' +
          '<a class="btn btn-primary btn-sm" href="/admin/mailboxes" style="margin-left:auto">Connect Gmail</a></div>';
        return;
      }
      const active = c.connection_status === 'connected' && c.protection_enabled;
      const dot = active ? 'ok' : (c.connection_status === 'paused' ? 'warn' : 'bad');
      const label = active ? 'Protection active' : (c.connection_status === 'paused' ? 'Protection paused' : 'Attention needed');
      panel.innerHTML =
        '<div class="grid-2" style="gap:var(--sp-5)">' +
          '<div class="row-wrap"><span class="status-dot ' + dot + '"></span>' +
            '<div><strong>' + esc(label) + '</strong>' +
            '<div class="muted mono" style="font-size:.82rem">' + esc(c.mailbox_email || '—') + '</div></div></div>' +
          '<div class="mono" style="font-size:.82rem;color:var(--text-2)">' +
            'Monitoring: <strong>' + esc(c.monitoring_mode || '—') + '</strong><br>' +
            'Last successful sync: <strong>' + esc(relTime(c.last_successful_sync_at)) + '</strong><br>' +
            'Labels: <strong>' + (c.labels_ready ? 'ready' : 'not set up') + '</strong>' +
          '</div>' +
        '</div>';
    } catch (e) {
      setState(panel, 'error', { title: 'Could not load protection status', msg: e.message });
    }
  }

  async function loadMetrics() {
    const grid = document.getElementById('metricGrid');
    try {
      const s = await SentinelAPI.stats();
      const cards = [
        ['is-brand', s.total, 'Detections (total)'],
        ['is-threat', s.phishing, 'Phishing'],
        ['is-review', s.needs_review, 'Needs Review'],
        ['is-threat', s.quarantined, 'Quarantined'],
      ];
      grid.innerHTML = cards.map(([cls, val, label]) =>
        '<div class="metric ' + cls + '"><div class="metric-label">' + esc(label) + '</div>' +
        '<div class="metric-value">' + esc(val != null ? val : 0) + '</div></div>'
      ).join('');
    } catch (e) {
      setState(grid, 'error', { title: 'Could not load metrics', msg: e.message });
    }
  }

  async function loadFeed() {
    const feed = document.getElementById('feed');
    try {
      const rows = await SentinelAPI.detectionList({ limit: 8 });
      if (!rows.length) { setState(feed, 'empty', { title: 'No detections yet', msg: 'Detections will appear here as mail is analysed.' }); return; }
      feed.innerHTML =
        '<div class="table-wrap"><table class="data cards-on-mobile"><thead><tr>' +
        '<th>Time</th><th>Sender</th><th>Subject</th><th>Verdict</th></tr></thead><tbody>' +
        rows.map((r) =>
          '<tr class="clickable" data-href="/admin/detections/' + encodeURIComponent(r.scan_id) + '">' +
          '<td data-label="Time" class="muted mono" style="font-size:.8rem">' + esc(relTime(r.scan_timestamp)) + '</td>' +
          '<td data-label="Sender">' + esc(r.from || '—') + '</td>' +
          '<td data-label="Subject">' + esc(r.subject || '(no subject)') + '</td>' +
          '<td data-label="Verdict">' + A.verdictBadge(r.classification) + '</td></tr>'
        ).join('') + '</tbody></table></div>';
      wireRowNav(feed);
    } catch (e) {
      setState(feed, 'error', { title: 'Could not load detections', msg: e.message });
    }
  }

  async function loadDist() {
    const el = document.getElementById('dist');
    try {
      const s = await SentinelAPI.stats();
      const total = Math.max(s.total || 0, 1);
      const rows = [
        ['Legitimate', s.legitimate, 'var(--green)'],
        ['Needs Review', s.needs_review, 'var(--amber)'],
        ['Phishing', s.phishing, 'var(--red)'],
      ];
      el.innerHTML = rows.map(([label, n, color]) => {
        const w = Math.round(((n || 0) / total) * 100);
        return '<div class="dist-row"><span class="muted">' + esc(label) + '</span>' +
          '<span class="dist-track"><span class="dist-fill" style="width:' + w + '%;background:' + color + '"></span></span>' +
          '<span class="mono" style="text-align:right">' + (n || 0) + '</span></div>';
      }).join('');
    } catch (e) {
      setState(el, 'error', { msg: e.message });
    }
  }

  async function loadActivity() {
    const el = document.getElementById('activity');
    try {
      const rows = await SentinelAPI.auditLog(8);
      if (!rows.length) { setState(el, 'empty', { title: 'No activity yet' }); return; }
      el.innerHTML = rows.map((r) =>
        '<div class="row" style="justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border)">' +
        '<div><span class="mono" style="font-size:.82rem">' + esc(r.action) + '</span> ' +
        '<span class="muted" style="font-size:.8rem">' + esc(r.actor) + (r.target ? ' → ' + esc(r.target) : '') + '</span></div>' +
        '<span class="muted mono" style="font-size:.75rem">' + esc(relTime(r.timestamp)) + '</span></div>'
      ).join('');
    } catch (e) {
      setState(el, 'error', { msg: e.message });
    }
  }

  function wireRowNav(container) {
    container.querySelectorAll('tr[data-href]').forEach((tr) => {
      tr.addEventListener('click', () => { window.location.href = tr.getAttribute('data-href'); });
    });
  }

  document.getElementById('scanNowBtn').addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    try {
      const res = await SentinelAPI.gmailScanNow();
      toast('Scan complete: ' + (res.new_detections ?? res.new ?? 0) + ' new', 'ok');
      loadMetrics(); loadFeed(); A.refreshSidebarCounts();
    } catch (err) {
      toast(err.status === 404 ? 'No mailbox connected' : ('Scan failed: ' + err.message), 'err');
    } finally { btn.disabled = false; }
  });

  loadProtection(); loadMetrics(); loadFeed(); loadDist(); loadActivity();
})();
