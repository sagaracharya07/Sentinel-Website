/* ==========================================================================
   Connected Mailboxes page — Gmail OAuth connection management (admin only).
   Talks to the /api/admin/gmail/* endpoints via SentinelAPI. Deliberately
   minimal/functional (Checkpoint 1): the visual redesign comes later.
   ========================================================================== */
(function () {
  const $ = (id) => document.getElementById(id);

  const BANNER_MESSAGES = {
    connected: ['ok', 'Gmail connected successfully.'],
    access_denied: ['warn', 'Connection cancelled — you declined consent on Google.'],
    state_mismatch: ['err', 'Security check failed (state mismatch). Please try connecting again.'],
    oauth_failed: ['err', 'Google sign-in failed. Please try again.'],
    no_refresh_token: ['err', 'Google did not return a refresh token. Remove Sentinel’s access at myaccount.google.com/permissions and reconnect.'],
    missing_code: ['err', 'The Google callback was incomplete. Please try again.'],
  };

  function showBanner(kind, text) {
    const b = $('banner');
    const colors = {
      ok: ['#12351d', '#8fe3a6'],
      warn: ['#3a2a10', '#e8c98a'],
      err: ['#3a1414', '#e89a9a'],
    };
    const [bg, fg] = colors[kind] || colors.err;
    b.style.background = bg;
    b.style.color = fg;
    b.textContent = text;
    b.style.display = 'block';
  }

  function handleQueryParams() {
    const p = new URLSearchParams(location.search);
    if (p.get('connected')) {
      const [k, t] = BANNER_MESSAGES.connected;
      showBanner(k, t);
    } else if (p.get('error')) {
      const entry = BANNER_MESSAGES[p.get('error')] || ['err', 'Something went wrong connecting Gmail.'];
      showBanner(entry[0], entry[1]);
    }
    // Clean the URL so a refresh doesn't re-show the banner.
    if (p.get('connected') || p.get('error')) {
      history.replaceState({}, '', '/mailboxes.html');
    }
  }

  function fmt(ts) {
    if (!ts) return '—';
    try { return new Date(ts).toLocaleString(); } catch (e) { return ts; }
  }

  function render(data) {
    const conn = data.connection;
    $('loadError').style.display = 'none';

    if (!conn || conn.connection_status === 'disconnected') {
      $('connected').style.display = 'none';
      $('notConnected').style.display = 'block';
      $('statusPill').textContent = 'Not connected';
      $('statusDot').style.background = '#888';
      $('oauthNotConfigured').style.display = data.oauth_configured ? 'none' : 'block';
      $('connectBtn').disabled = !data.oauth_configured;
      return;
    }

    $('notConnected').style.display = 'none';
    $('connected').style.display = 'block';

    const active = conn.protection_enabled && conn.connection_status === 'connected';
    $('statusPill').textContent = conn.connection_status;
    $('statusDot').style.background = active ? '#31d07f' : (conn.connection_status === 'paused' ? '#e8c98a' : '#e88');

    $('mbEmail').textContent = conn.mailbox_email || '—';
    $('mbStatus').textContent = conn.connection_status;
    $('mbProtection').textContent = conn.protection_enabled ? 'Active' : 'Paused';
    $('mbMode').textContent = conn.monitoring_mode || 'polling';
    $('mbLabels').textContent = conn.labels_ready ? 'Ready' : 'Not created yet';
    $('mbLastSync').textContent = fmt(conn.last_successful_sync_at);
    $('mbLastAttempt').textContent = fmt(conn.last_attempted_sync_at);
    $('mbError').textContent = conn.last_error_message || 'None';

    $('pauseBtn').disabled = !conn.protection_enabled;
    $('resumeBtn').disabled = conn.protection_enabled;
  }

  async function load() {
    try {
      render(await SentinelAPI.gmailStatus());
    } catch (e) {
      $('notConnected').style.display = 'none';
      $('connected').style.display = 'none';
      $('loadError').style.display = 'block';
    }
  }

  async function connect() {
    try {
      const res = await SentinelAPI.gmailAuthorizeUrl();
      if (res.authorization_url) window.location = res.authorization_url;
    } catch (e) {
      showBanner('err', e.message || 'Could not start Gmail connection.');
    }
  }

  async function action(fn, confirmMsg) {
    if (confirmMsg && !window.confirm(confirmMsg)) return;
    try {
      if (fn === SentinelAPI.gmailReconnect) {
        const res = await fn();
        if (res.authorization_url) { window.location = res.authorization_url; return; }
      } else {
        await fn();
      }
      await load();
    } catch (e) {
      showBanner('err', e.message || 'Action failed.');
    }
  }

  function showOp(text) {
    const el = $('opResult');
    el.textContent = text;
    el.style.display = 'block';
  }

  async function test() {
    showOp('Testing connection…');
    try {
      const r = await SentinelAPI.gmailTest();
      showOp(r.ok
        ? `✓ Connected as ${r.email} · ${r.messages_total} messages · labels ${r.labels_ready ? 'ready' : 'pending'}`
        : `✗ ${r.error}`);
      await load();
    } catch (e) { showOp('✗ ' + (e.message || 'Test failed')); }
  }

  async function scanNow() {
    showOp('Scanning…');
    try {
      const r = await SentinelAPI.gmailScanNow();
      if (r.ran === false) { showOp('Not scanned: ' + (r.reason || 'unavailable')); }
      else {
        showOp(`Scan complete · new: ${r.new_messages} · scanned: ${r.scanned} · `
          + `duplicates: ${r.skipped_duplicates} · failed: ${r.failed_retrieve + r.failed_classification}`
          + (r.error ? ` · error: ${r.error}` : ''));
      }
      await load();
    } catch (e) { showOp('✗ ' + (e.message || 'Scan failed')); }
  }

  document.addEventListener('DOMContentLoaded', function () {
    handleQueryParams();
    $('connectBtn').addEventListener('click', connect);
    $('testBtn').addEventListener('click', test);
    $('scanBtn').addEventListener('click', scanNow);
    $('pauseBtn').addEventListener('click', () => action(SentinelAPI.gmailPause));
    $('resumeBtn').addEventListener('click', () => action(SentinelAPI.gmailResume));
    $('reconnectBtn').addEventListener('click', () => action(SentinelAPI.gmailReconnect));
    $('disconnectBtn').addEventListener('click', () =>
      action(SentinelAPI.gmailDisconnect, 'Disconnect this Gmail mailbox? Stored access will be cleared.'));
    load();
  });
})();
