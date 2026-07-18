/* Settings -> Gmail Protection. Read-only summary of the real connection --
   actionable controls (pause/resume/reconnect/disconnect) live on Connected
   Mailboxes to avoid duplicating that page's logic here. */
(function () {
  'use strict';
  const { esc, relTime, setState } = window.SentinelUI;
  const body = document.getElementById('gmailSettingsBody');

  async function load() {
    try {
      const data = await SentinelAPI.gmailStatus();
      const c = data.connection;
      if (!c) {
        body.innerHTML = '<div class="muted">No mailbox connected yet.</div>';
        return;
      }
      body.innerHTML =
        '<div class="setting-row"><div><div class="s-label">Connected account</div></div><div class="mono">' + esc(c.mailbox_email) + '</div></div>' +
        '<div class="setting-row"><div><div class="s-label">Protection enabled</div></div><div>' + (c.protection_enabled ? 'Yes' : 'No') + '<span class="setting-tag configurable" style="margin-left:8px">Configurable Here</span></div></div>' +
        '<div class="setting-row"><div><div class="s-label">Monitoring mode</div></div><div class="mono">' + esc(c.monitoring_mode) + '</div></div>' +
        '<div class="setting-row"><div><div class="s-label">Gmail labels</div></div><div>' + (c.labels_ready ? 'Ready' : 'Not set up') + '</div></div>' +
        '<div class="setting-row"><div><div class="s-label">Last successful sync</div></div><div class="muted">' + esc(relTime(c.last_successful_sync_at)) + '</div></div>';
    } catch (e) {
      setState(body, 'error', { title: 'Could not load Gmail status', msg: e.message });
    }
  }
  load();
})();
