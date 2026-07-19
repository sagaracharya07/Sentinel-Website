/* Admin Overview — real data from /api/stats, /api/admin/gmail/status,
   /api/admin/detections, /api/admin/audit-log. */
(function () {
  'use strict';
  const { esc, toast, relTime, setState } = window.SentinelUI;
  const A = window.AdminUI;

  /* Onboarding checklist -- derived entirely from real GmailConnection
     state each render, so it naturally "resumes" without any separate
     progress storage and never re-forces a step that's already done. */
  function renderOnboarding(c) {
    const panel = document.getElementById('onboardingPanel');
    const body = document.getElementById('onboardingBody');
    const steps = [
      { label: 'Connect Gmail', done: !!c },
      { label: 'Verify Gmail labels', done: !!(c && c.labels_ready) },
      { label: 'Activate protection', done: !!(c && c.protection_enabled) },
      { label: 'Run first scan', done: !!(c && c.last_successful_sync_at) },
    ];
    if (steps.every((s) => s.done)) { panel.hidden = true; return; }
    panel.hidden = false;
    let firstPending = true;
    body.innerHTML = '<div class="steps">' + steps.map((s) => {
      const cls = s.done ? 'done' : (firstPending ? 'active' : '');
      if (!s.done) firstPending = false;
      return '<div class="step ' + cls + '"><span class="step-dot">' + (s.done ? '✓' : '') + '</span> ' + esc(s.label) + '</div>';
    }).join('') + '</div>' +
      '<a href="/admin/mailboxes" class="btn btn-primary btn-sm" style="margin-top:var(--sp-4)">Continue setup →</a>';
  }

  async function loadProtection() {
    const panel = document.getElementById('protectionPanel');
    try {
      const data = await SentinelAPI.gmailStatus();
      const c = data.connection;
      renderOnboarding(c);
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
          '<tr class="clickable" data-href="/admin/detections/' + encodeURIComponent(r.scan_id) + '" tabindex="0">' +
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
      const go = () => { window.location.href = tr.getAttribute('data-href'); };
      tr.addEventListener('click', go);
      tr.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
    });
  }

  document.getElementById('scanNowBtn').addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    try {
      const res = await SentinelAPI.gmailScanNow();
      const d = A.describeSyncResult(res);
      toast(d.message, d.kind);
      loadMetrics(); loadFeed(); A.refreshSidebarCounts();
    } catch (err) {
      toast(err.status === 404 ? 'No mailbox connected' : ('Scan failed: ' + err.message), 'err');
    } finally { btn.disabled = false; }
  });

  loadProtection(); loadMetrics(); loadFeed(); loadDist(); loadActivity();

  // Live operational updates: re-fetch the same real data every 20s so a
  // detection that arrives while this page is open shows up without a
  // manual reload. Pauses automatically while the tab is hidden (see
  // SentinelUI.startPolling) -- this is short polling, not a persistent
  // connection, chosen as the smallest option that works for every admin
  // page without adding a WebSocket/SSE server dependency.
  window.SentinelUI.startPolling(() => {
    loadProtection(); loadMetrics(); loadFeed(); loadDist(); loadActivity();
  }, 20000);
})();
