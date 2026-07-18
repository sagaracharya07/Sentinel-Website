/* Admin Model Management — /api/admin/model-info, /retrain (+poll), and
   /model-version/<v>/promote (the same endpoint serves both promotion of a
   new candidate and rollback to an older version). */
(function () {
  'use strict';
  const { esc, toast, absTime, setState } = window.SentinelUI;

  const activeEl = document.getElementById('activeModel');
  const versionsEl = document.getElementById('versionList');
  const feedbackTag = document.getElementById('pendingFeedbackTag');
  const retrainBtn = document.getElementById('retrainBtn');
  const retrainStatus = document.getElementById('retrainStatus');

  function metric(label, val) {
    return '<div class="metric" style="padding:12px"><div class="metric-label">' + esc(label) + '</div><div class="metric-value" style="font-size:1.3rem">' + val + '</div></div>';
  }

  function renderActive(info) {
    const c = info.current;
    const m = c.metrics || {};
    feedbackTag.textContent = info.pending_feedback_count + ' feedback item(s) pending';
    activeEl.innerHTML =
      '<div class="row-wrap" style="margin-bottom:var(--sp-4)">' +
        '<span class="badge badge-brand mono">' + esc(c.version) + '</span>' +
        '<span class="muted mono" style="font-size:.8rem">trained ' + esc(absTime(c.meta?.trained_at)) + '</span>' +
      '</div>' +
      '<div class="metric-grid" style="grid-template-columns:repeat(3,1fr)">' +
        metric('Accuracy', Math.round((m.accuracy || 0) * 100) + '%') +
        metric('Precision', Math.round((m.precision || 0) * 100) + '%') +
        metric('Recall', Math.round((m.recall || 0) * 100) + '%') +
        metric('F1 score', Math.round((m.f1_score || 0) * 100) + '%') +
        metric('False positive rate', Math.round((m.false_positive_rate || 0) * 100) + '%') +
        metric('False negative rate', Math.round((m.false_negative_rate || 0) * 100) + '%') +
      '</div>';
  }

  function renderVersions(versions, currentVersion) {
    if (!versions.length) { setState(versionsEl, 'empty', { title: 'No version history' }); return; }
    versionsEl.innerHTML = '<div class="table-wrap"><table class="data cards-on-mobile"><thead><tr>' +
      '<th>Version</th><th>Trained</th><th>Accuracy</th><th>Test samples</th><th>Status</th><th></th></tr></thead><tbody>' +
      versions.map((v) =>
        '<tr>' +
        '<td data-label="Version" class="mono">' + esc(v.version) + '</td>' +
        '<td data-label="Trained" class="muted mono" style="font-size:.8rem">' + esc(absTime(v.trained_at)) + '</td>' +
        '<td data-label="Accuracy">' + Math.round((v.accuracy || 0) * 100) + '%</td>' +
        '<td data-label="Test samples" class="mono">' + (v.n_test ?? '—') + '</td>' +
        '<td data-label="Status">' + (v.is_current ? '<span class="badge badge-legit">Live</span>' : '<span class="badge badge-muted">Inactive</span>') + '</td>' +
        '<td data-label="">' + (v.is_current ? '' : '<button class="btn btn-sm" data-promote="' + esc(v.version) + '">' + (v.version < currentVersion ? 'Roll back to this' : 'Promote') + '</button>') + '</td>' +
        '</tr>'
      ).join('') + '</tbody></table></div>';
    versionsEl.querySelectorAll('[data-promote]').forEach((b) => b.addEventListener('click', () => promote(b)));
  }

  async function promote(btn) {
    const version = btn.getAttribute('data-promote');
    if (!confirm('Make ' + version + ' the live model? This immediately changes what classify() serves.')) return;
    btn.disabled = true;
    try {
      await SentinelAPI.promoteModelVersion(version);
      toast(version + ' promoted to live', 'ok');
      load();
    } catch (e) {
      toast('Promote failed: ' + e.message, 'err');
      btn.disabled = false;
    }
  }

  retrainBtn.addEventListener('click', async () => {
    retrainBtn.disabled = true;
    retrainStatus.textContent = 'Queuing retraining job…';
    try {
      const job = await SentinelAPI.retrain();
      poll(job.job_id);
    } catch (e) {
      retrainStatus.textContent = 'Could not start retraining: ' + e.message;
      retrainBtn.disabled = false;
    }
  });

  function poll(jobId) {
    retrainStatus.textContent = 'Retraining in progress…';
    const interval = setInterval(async () => {
      try {
        const s = await SentinelAPI.retrainStatus(jobId);
        if (s.status === 'done') {
          clearInterval(interval);
          retrainStatus.textContent = 'Retraining complete — new candidate version ' + (s.version || '') + ' created. Promote it above to make it live.';
          retrainBtn.disabled = false;
          load();
        } else if (s.status === 'failed') {
          clearInterval(interval);
          retrainStatus.textContent = 'Retraining failed: ' + (s.error || 'unknown error');
          retrainBtn.disabled = false;
        } else {
          retrainStatus.textContent = 'Retraining ' + s.status + '…';
        }
      } catch (e) {
        clearInterval(interval);
        retrainStatus.textContent = 'Could not reach the job queue: ' + e.message;
        retrainBtn.disabled = false;
      }
    }, 2500);
  }

  async function load() {
    try {
      const info = await SentinelAPI.modelInfo();
      renderActive(info);
      renderVersions(info.versions || [], info.current.version);
    } catch (e) {
      setState(activeEl, 'error', { title: 'Could not load model info', msg: e.message });
    }
  }
  load();
})();
