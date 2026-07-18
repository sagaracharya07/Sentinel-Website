/* Admin System Health — /api/admin/system-health. Every card's status/dot
   comes directly from the API's real check; nothing here is fabricated. */
(function () {
  'use strict';
  const { esc, setState } = window.SentinelUI;
  const grid = document.getElementById('healthGrid');

  const STATUS_META = {
    healthy: ['ok', 'Healthy'],
    degraded: ['warn', 'Degraded'],
    unavailable: ['bad', 'Unavailable'],
    not_configured: ['off', 'Not Configured'],
    unknown: ['off', 'Unknown'],
  };

  function card(title, status, detail) {
    const [dot, label] = STATUS_META[status] || ['off', status];
    return '<div class="metric">' +
      '<div class="row-wrap" style="margin-bottom:8px"><span class="status-dot ' + dot + '"></span><span class="metric-label" style="margin:0">' + esc(title) + '</span></div>' +
      '<div style="font-weight:700">' + esc(label) + '</div>' +
      (detail ? '<div class="muted" style="font-size:.78rem;margin-top:4px">' + esc(detail) + '</div>' : '') +
      '</div>';
  }

  async function load() {
    setState(grid, 'loading');
    try {
      const data = await SentinelAPI.systemHealth();
      const c = data.checks;
      grid.innerHTML =
        card('Web application', c.web.status) +
        card('Database', c.database.status, c.database.error) +
        card('Redis', c.redis.status, c.redis.error) +
        card('Celery worker', c.celery_worker.status, c.celery_worker.worker_count ? c.celery_worker.worker_count + ' worker(s) responding' : c.celery_worker.error) +
        card('Celery beat', c.celery_beat.status, 'No liveness signal exposed yet') +
        card('Gmail mailbox', c.gmail_mailbox.status, c.gmail_mailbox.mailbox_email) +
        card('Active model', c.model.status, c.model.info ? c.model.info.version : null) +
        card('Migration version', c.migration_version ? 'healthy' : 'unknown', c.migration_version);
    } catch (e) {
      setState(grid, 'error', { title: 'Could not load system health', msg: e.message });
    }
  }

  document.getElementById('refreshBtn').addEventListener('click', load);
  load();
})();
