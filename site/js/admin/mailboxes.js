/* Admin Connected Mailboxes — Gmail OAuth lifecycle via /api/admin/gmail/*.
   No token/secret is ever rendered. Success animations/toasts fire only after
   the backend confirms the operation. */
(function () {
  'use strict';
  const { esc, toast, relTime, absTime, setState } = window.SentinelUI;
  const A = window.AdminUI;

  const dot = document.getElementById('mbDot');
  const pill = document.getElementById('mbPill');
  const panel = document.getElementById('mbPanel');

  /* ---- OAuth result banner (?connected / ?error) ------------------------ */
  function showBanner() {
    const p = new URLSearchParams(location.search);
    const banner = document.getElementById('banner');
    if (p.get('connected')) {
      banner.hidden = false;
      banner.className = 'callout';
      banner.innerHTML = '<svg class="icon" aria-hidden="true"><use href="#i-check"></use></svg><div>Gmail connected. Protection is active.</div>';
    } else if (p.get('error')) {
      banner.hidden = false;
      banner.className = 'callout warn';
      banner.innerHTML = '<svg class="icon" aria-hidden="true"><use href="#i-alert"></use></svg><div>Connection did not complete (' + esc(p.get('error')) + '). Please try again.</div>';
    }
    if (p.get('connected') || p.get('error')) {
      history.replaceState(null, '', '/admin/mailboxes');
    }
  }

  /* ---- render status ---------------------------------------------------- */
  function render(data) {
    const c = data.connection;
    if (!c) {
      dot.className = 'status-dot off';
      pill.className = 'badge badge-muted'; pill.textContent = 'Not connected';
      const cfgWarn = data.oauth_configured ? '' :
        '<div class="callout warn" style="margin-bottom:var(--sp-4)"><svg class="icon" aria-hidden="true"><use href="#i-alert"></use></svg>' +
        '<div>Google OAuth is not configured on the server. Set <code>GOOGLE_CLIENT_ID</code>, <code>GOOGLE_CLIENT_SECRET</code> and ' +
        '<code>GOOGLE_OAUTH_REDIRECT_URI</code> (see <code>backend/.env.example</code>), then reload.</div></div>';
      panel.innerHTML = cfgWarn +
        '<p class="muted" style="margin-bottom:var(--sp-4)">No Gmail mailbox is connected — Sentinel is not watching a live inbox.</p>' +
        '<button class="btn btn-primary" id="connectBtn"' + (data.oauth_configured ? '' : ' disabled') + '>Connect Gmail</button>';
      const cb = document.getElementById('connectBtn');
      if (cb) cb.addEventListener('click', connect);
      return;
    }
    // "Protection active" used to mean only connected+enabled, which could
    // claim protection while required labels were never set up or the last
    // Gmail call actually failed. Fold in labels_ready/last_error_code (both
    // already tracked on the connection) so the badge can't overstate health.
    const state = protectionState(c);
    const STATE_STYLE = {
      active: { dot: 'ok', badge: 'badge-legit', text: 'Protection active' },
      setup_incomplete: { dot: 'warn', badge: 'badge-review', text: 'Setup incomplete' },
      degraded: { dot: 'warn', badge: 'badge-review', text: 'Degraded' },
      paused: { dot: 'warn', badge: 'badge-review', text: 'Paused' },
      disconnected: { dot: 'bad', badge: 'badge-phish', text: c.connection_status },
    };
    const s = STATE_STYLE[state];
    dot.className = 'status-dot ' + s.dot;
    pill.className = 'badge ' + s.badge;
    pill.textContent = s.text;

    panel.innerHTML =
      '<dl class="kv" style="grid-template-columns:150px 1fr;gap:8px 16px">' +
        row('Account', esc(c.mailbox_email || '—')) +
        row('Connection', esc(c.connection_status)) +
        row('Protection', c.protection_enabled ? 'Enabled' : 'Paused') +
        row('Monitoring', esc(c.monitoring_mode || '—')) +
        row('Labels', c.labels_ready ? 'Ready' : 'Not set up') +
        row('Granted scopes', (c.granted_scopes || []).length + ' scope(s)') +
        row('Last successful sync', esc(relTime(c.last_successful_sync_at)) + ' <span class="muted">(' + esc(absTime(c.last_successful_sync_at)) + ')</span>') +
        row('Last attempt', esc(relTime(c.last_attempted_sync_at))) +
        (c.last_error_message ? row('Last error', '<span style="color:var(--red)">' + esc(c.last_error_message) + '</span>') : '') +
      '</dl>' +
      '<div class="row-wrap" style="margin-top:var(--sp-4)">' +
        '<button class="btn btn-sm" data-op="test">Test connection</button>' +
        '<button class="btn btn-sm btn-primary" data-op="scan">Scan now</button>' +
        (c.protection_enabled ? '<button class="btn btn-sm" data-op="pause">Pause</button>'
                              : '<button class="btn btn-sm" data-op="resume">Resume</button>') +
        '<button class="btn btn-sm" data-op="reconnect">Reconnect</button>' +
        '<button class="btn btn-sm btn-danger" data-op="disconnect">Disconnect</button>' +
      '</div>';
    panel.querySelectorAll('[data-op]').forEach((b) => b.addEventListener('click', () => op(b)));
  }
  function row(k, v) { return '<dt>' + esc(k) + '</dt><dd>' + v + '</dd>'; }

  function protectionState(c) {
    if (c.connection_status === 'paused') return 'paused';
    if (c.connection_status !== 'connected') return 'disconnected';
    if (!c.labels_ready) return 'setup_incomplete';
    if (c.last_error_code) return 'degraded';
    return 'active';
  }

  /* ---- operations ------------------------------------------------------- */
  async function connect() {
    try {
      const res = await SentinelAPI.gmailAuthorizeUrl();
      if (res.authorization_url) { window.location.href = res.authorization_url; }
      else { toast(res.error || 'OAuth not configured', 'err'); }
    } catch (e) { toast('Could not start connect: ' + e.message, 'err'); }
  }

  async function op(btn) {
    const kind = btn.getAttribute('data-op');
    btn.disabled = true;
    try {
      if (kind === 'test') {
        const r = await SentinelAPI.gmailTest();
        toast(r.ok ? 'Connection OK: ' + (r.email || '') : ('Test failed: ' + (r.error || '')), r.ok ? 'ok' : 'err');
      } else if (kind === 'scan') {
        const r = await SentinelAPI.gmailScanNow();
        const d = A.describeSyncResult(r);
        toast(d.message, d.kind);
        A.refreshSidebarCounts();
      } else if (kind === 'pause') { await SentinelAPI.gmailPause(); toast('Protection paused', 'ok'); }
      else if (kind === 'resume') { await SentinelAPI.gmailResume(); toast('Protection resumed', 'ok'); }
      else if (kind === 'reconnect') {
        const r = await SentinelAPI.gmailReconnect();
        if (r.authorization_url) { window.location.href = r.authorization_url; return; }
        toast(r.error || 'Reconnect unavailable', 'err');
      } else if (kind === 'disconnect') {
        if (!confirm('Disconnect this mailbox? Stored tokens will be wiped and monitoring will stop.')) { btn.disabled = false; return; }
        await SentinelAPI.gmailDisconnect(); toast('Mailbox disconnected', 'ok');
      }
      load(); A.refreshProtectionPill();
    } catch (e) {
      toast('Action failed: ' + e.message, 'err');
      btn.disabled = false;
    }
  }

  async function load() {
    try { render(await SentinelAPI.gmailStatus()); }
    catch (e) { setState(panel, 'error', { title: 'Could not load mailbox status', msg: 'Gmail management is admin-only. ' + e.message }); }
  }

  showBanner();
  load();
})();
