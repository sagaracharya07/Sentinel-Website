/* Admin Background Tasks — composes /api/admin/system-health (Celery
   liveness) with /api/admin/gmail/status (sync schedule) rather than adding
   a new endpoint; "Trigger Gmail Sync" reuses the existing scan-now action. */
(function () {
  'use strict';
  const { esc, toast, relTime, setState } = window.SentinelUI;
  const A = window.AdminUI;

  const celeryEl = document.getElementById('celeryPanel');
  const gmailEl = document.getElementById('gmailPanel');

  function statusDot(s) {
    return s === 'healthy' ? 'ok' : s === 'degraded' ? 'warn' : s === 'unavailable' ? 'bad' : 'off';
  }

  async function load() {
    setState(celeryEl, 'loading'); setState(gmailEl, 'loading');
    try {
      const health = await SentinelAPI.systemHealth();
      const w = health.checks.celery_worker;
      const b = health.checks.celery_beat;
      celeryEl.innerHTML =
        '<div class="row-wrap" style="margin-bottom:8px"><span class="status-dot ' + statusDot(w.status) + '"></span> Worker: ' + esc(w.status) +
          (w.worker_count ? ' (' + w.worker_count + ')' : '') + '</div>' +
        '<div class="row-wrap"><span class="status-dot ' + statusDot(b.status) + '"></span> Beat: ' + esc(b.status) + '</div>' +
        '<p class="muted" style="font-size:.8rem;margin-top:10px">Beat has no built-in liveness signal exposed yet — reported honestly as unknown.</p>';
    } catch (e) { setState(celeryEl, 'error', { msg: e.message }); }

    try {
      const status = await SentinelAPI.gmailStatus();
      const c = status.connection;
      if (!c) { gmailEl.innerHTML = '<div class="muted">No mailbox connected.</div>'; return; }
      gmailEl.innerHTML =
        '<div class="kv" style="grid-template-columns:150px 1fr">' +
        '<dt>Monitoring mode</dt><dd>' + esc(c.monitoring_mode) + '</dd>' +
        '<dt>Last successful sync</dt><dd>' + esc(relTime(c.last_successful_sync_at)) + '</dd>' +
        '<dt>Last attempt</dt><dd>' + esc(relTime(c.last_attempted_sync_at)) + '</dd>' +
        '</div>';
    } catch (e) { setState(gmailEl, 'error', { msg: e.message }); }
  }

  document.getElementById('refreshBtn').addEventListener('click', load);
  document.getElementById('triggerBtn').addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    try {
      const r = await SentinelAPI.gmailScanNow();
      const d = A.describeSyncResult(r);
      toast(d.message, d.kind);
      load();
    } catch (err) {
      toast(err.status === 404 ? 'No mailbox connected' : 'Trigger failed: ' + err.message, 'err');
    } finally { btn.disabled = false; }
  });

  load();
})();
