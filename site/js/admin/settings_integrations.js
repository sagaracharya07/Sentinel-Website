/* Settings -> Integrations. Real status pulled from /api/admin/system-health
   + /api/admin/gmail/status -- same honesty rule as System Health: never
   show Healthy without a real check behind it. */
(function () {
  'use strict';
  const { esc, setState } = window.SentinelUI;
  const body = document.getElementById('integrationsBody');

  function row(title, statusLabel, cls, detail) {
    return '<div class="setting-row"><div><div class="s-label">' + esc(title) + '</div>' +
      (detail ? '<div class="s-desc">' + esc(detail) + '</div>' : '') + '</div>' +
      '<span class="badge ' + cls + '">' + esc(statusLabel) + '</span></div>';
  }

  async function load() {
    try {
      const [health, gmail] = await Promise.all([SentinelAPI.systemHealth(), SentinelAPI.gmailStatus()]);
      const c = health.checks;
      body.innerHTML =
        row('Gmail / Google Workspace', gmail.connection ? 'Available' : 'Not Configured', gmail.connection ? 'badge-legit' : 'badge-muted', gmail.connection ? gmail.connection.mailbox_email : 'No mailbox connected') +
        row('Legacy IMAP', 'Development Fallback', 'badge-review', 'Off by default') +
        row('Redis', c.redis.status === 'healthy' ? 'Available' : 'Not Configured', c.redis.status === 'healthy' ? 'badge-legit' : 'badge-muted') +
        row('Celery', c.celery_worker.status === 'healthy' ? 'Available' : 'Not Configured', c.celery_worker.status === 'healthy' ? 'badge-legit' : 'badge-muted', c.celery_worker.worker_count ? c.celery_worker.worker_count + ' worker(s)' : '') +
        row('Database', c.database.status === 'healthy' ? 'Available' : 'Unavailable', c.database.status === 'healthy' ? 'badge-legit' : 'badge-phish') +
        row('Microsoft 365', 'Planned', 'badge-muted', 'Not implemented');
    } catch (e) {
      setState(body, 'error', { title: 'Could not load integration status', msg: e.message });
    }
  }
  load();
})();
