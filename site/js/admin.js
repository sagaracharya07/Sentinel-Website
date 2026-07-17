(() => {
  const statTotal = document.getElementById('statTotal');
  const statPhishing = document.getElementById('statPhishing');
  const statNeedsReview = document.getElementById('statNeedsReview');
  const statLegit = document.getElementById('statLegit');
  const statQuarantined = document.getElementById('statQuarantined');
  const statAvgConf = document.getElementById('statAvgConf');
  const barChart = document.getElementById('barChart');
  const donut = document.getElementById('donut');
  const legPhish = document.getElementById('legPhish');
  const legLegit = document.getElementById('legLegit');
  const logBody = document.getElementById('logBody');
  const tableCount = document.getElementById('tableCount');
  const filterTabs = document.getElementById('filterTabs');
  const sourceTabs = document.getElementById('sourceTabs');
  const resetDataBtn = document.getElementById('resetDataBtn');
  const toast = document.getElementById('toast');

  const mailboxDot = document.getElementById('mailboxDot');
  const mailboxConfigured = document.getElementById('mailboxConfigured');
  const mailboxNotConfigured = document.getElementById('mailboxNotConfigured');
  const mbHost = document.getElementById('mbHost');
  const mbUser = document.getElementById('mbUser');
  const mbFolder = document.getElementById('mbFolder');
  const mbQFolder = document.getElementById('mbQFolder');
  const mbLastSync = document.getElementById('mbLastSync');
  const mbLastNew = document.getElementById('mbLastNew');
  const mbTotal = document.getElementById('mbTotal');
  const mbError = document.getElementById('mbError');
  const mbTestBtn = document.getElementById('mbTestBtn');
  const mbSyncBtn = document.getElementById('mbSyncBtn');

  const modalBackdrop = document.getElementById('modalBackdrop');
  const modalClose = document.getElementById('modalClose');
  const modalId = document.getElementById('modalId');
  const modalSubject = document.getElementById('modalSubject');
  const modalFrom = document.getElementById('modalFrom');
  const modalTime = document.getElementById('modalTime');
  const modalVerdict = document.getElementById('modalVerdict');
  const modalStatus = document.getElementById('modalStatus');
  const modalBodyText = document.getElementById('modalBodyText');
  const modalFindings = document.getElementById('modalFindings');
  const modalActions = document.getElementById('modalActions');

  const retrainBtn = document.getElementById('retrainBtn');
  const pendingFeedbackTag = document.getElementById('pendingFeedbackTag');
  const modelVersionTag = document.getElementById('modelVersionTag');
  const modelTrainedAt = document.getElementById('modelTrainedAt');
  const modelSampleCount = document.getElementById('modelSampleCount');
  const modelVersionList = document.getElementById('modelVersionList');
  const mAccuracy = document.getElementById('mAccuracy');
  const mPrecision = document.getElementById('mPrecision');
  const mRecall = document.getElementById('mRecall');
  const mF1 = document.getElementById('mF1');
  const mFPR = document.getElementById('mFPR');
  const mFNR = document.getElementById('mFNR');

  let activeFilter = 'All';
  let activeSource = 'All';
  let cachedRecords = [];

  (async function init() {
    const user = await SentinelAuth.requireLogin({ requireAdmin: true });
    if (!user) return; // redirected
    SentinelAuth.renderUserBadge(user);
    await renderAll();
    await renderModelInfo();
    await renderMailboxStatus();
    setInterval(renderMailboxStatus, 15000); // reflect background poller's progress
  })();

  async function renderMailboxStatus() {
    const s = await SentinelAPI.mailboxStatus();
    if (!s.configured) {
      mailboxConfigured.style.display = 'none';
      mailboxNotConfigured.style.display = 'block';
      mailboxDot.className = 'mailbox-dot';
      return;
    }
    mailboxConfigured.style.display = 'block';
    mailboxNotConfigured.style.display = 'none';
    mailboxDot.className = 'mailbox-dot ' + (s.connected ? 'connected' : 'disconnected');
    mbHost.textContent = s.host || '—';
    mbUser.textContent = s.username || '—';
    mbFolder.textContent = s.inbox_folder || '—';
    mbQFolder.textContent = s.quarantine_folder || '—';
    mbLastSync.textContent = s.last_sync_at ? new Date(s.last_sync_at + 'Z').toLocaleString() : 'never yet';
    mbLastNew.textContent = s.last_new_messages ?? '0';
    mbTotal.textContent = s.total_synced ?? '0';
    if (s.last_error) {
      mbError.textContent = s.last_error;
      mbError.classList.add('show');
    } else {
      mbError.classList.remove('show');
    }
  }

  mbTestBtn.addEventListener('click', async () => {
    mbTestBtn.setAttribute('disabled', 'disabled');
    mbTestBtn.textContent = 'Testing…';
    try {
      const res = await SentinelAPI.mailboxTest();
      showToast(res.ok ? `Connected — ${res.message_count} message(s) in ${res.folder}` : (res.error || 'Connection failed'));
    } catch (err) {
      showToast(err.message || 'Connection test failed');
    } finally {
      mbTestBtn.removeAttribute('disabled');
      mbTestBtn.textContent = 'Test connection';
    }
    await renderMailboxStatus();
  });

  mbSyncBtn.addEventListener('click', async () => {
    mbSyncBtn.setAttribute('disabled', 'disabled');
    mbSyncBtn.textContent = 'Syncing…';
    try {
      const res = await SentinelAPI.mailboxSync();
      showToast(res.error ? res.error : `Synced — ${res.new_messages} new message(s) scanned`);
      await renderAll();
    } catch (err) {
      showToast(err.message || 'Sync failed');
    } finally {
      mbSyncBtn.removeAttribute('disabled');
      mbSyncBtn.textContent = 'Sync now';
    }
    await renderMailboxStatus();
  });

  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2200);
  }

  function fmtTime(iso) {
    const d = new Date(iso + (iso.endsWith('Z') ? '' : 'Z'));
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' · ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  }
  function pct(x) { return x == null ? '—' : Math.round(x * 100) + '%'; }

  async function renderStats() {
    const s = await SentinelAPI.stats();
    statTotal.textContent = s.total;
    statPhishing.textContent = s.phishing;
    statNeedsReview.textContent = s.needs_review ?? 0;
    statLegit.textContent = s.legitimate;
    statQuarantined.textContent = s.quarantined;
    statAvgConf.textContent = Math.round((s.avg_confidence || 0) * 100) + '%';

    donut.style.setProperty('--pct', s.total ? (s.phishing / s.total * 100) + '%' : '0%');
    legPhish.textContent = s.phishing;
    legLegit.textContent = s.legitimate;
  }

  function renderBarChart(records) {
    const days = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      days.push({ key: d.toDateString(), label: d.toLocaleDateString(undefined, { weekday: 'short' }), safe: 0, threat: 0 });
    }
    records.forEach(r => {
      const key = new Date(r.scan_timestamp + (r.scan_timestamp.endsWith('Z') ? '' : 'Z')).toDateString();
      const day = days.find(d => d.key === key);
      if (!day) return;
      if (r.classification === 'Phishing') day.threat++; else day.safe++;
    });
    const max = Math.max(1, ...days.map(d => d.safe + d.threat));
    barChart.innerHTML = days.map(d => {
      const totalH = ((d.safe + d.threat) / max) * 130;
      const safeH = d.safe / (d.safe + d.threat || 1) * totalH;
      const threatH = totalH - safeH;
      return `<div class="bar-col">
        <div class="bar-stack" style="height:${Math.max(totalH, 2)}px">
          ${d.threat ? `<div class="bar-seg-threat" style="height:${threatH}px"></div>` : ''}
          ${d.safe ? `<div class="bar-seg-safe" style="height:${safeH}px"></div>` : ''}
        </div>
        <small>${d.label}</small>
      </div>`;
    }).join('');
  }

  function renderTable() {
    let records = cachedRecords;
    if (activeFilter !== 'All') records = records.filter(r => r.status === activeFilter);
    if (activeSource !== 'All') records = records.filter(r => r.source === activeSource);
    tableCount.textContent = `${records.length} record(s)`;
    logBody.innerHTML = records.map(r => {
      const copy = Sentinel.verdictCopy(r.classification);
      const conf = r.prediction_confidence ?? Math.max(r.confidence_score || 0, 1 - (r.confidence_score || 0));
      return `
      <tr data-id="${r.scan_id}">
        <td style="font-family:var(--mono);font-size:.78rem;color:var(--paper-muted)">${fmtTime(r.scan_timestamp)}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${Sentinel.escapeHtml(r.from || '')}</td>
        <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${Sentinel.escapeHtml(r.subject || '')}</td>
        <td><span class="chip ${copy.chip}">${r.classification}</span></td>
        <td>${r.risk_level}</td>
        <td style="font-family:var(--mono)">${Math.round(conf * 100)}%</td>
        <td><span class="status-pill status-${r.status}">${r.status}</span></td>
        <td><span class="source-chip ${r.source === 'mailbox' ? 'source-mailbox' : 'source-manual'}">${r.source === 'mailbox' ? 'Live mailbox' : 'Manual'}</span></td>
        <td style="font-family:var(--mono);font-size:.78rem;color:var(--paper-muted)">${r.user_feedback ? '✓ ' + r.user_feedback : '—'}</td>
      </tr>
    `;
    }).join('') || `<tr><td colspan="9" style="text-align:center;color:var(--paper-muted);padding:32px">No records in this view.</td></tr>`;

    logBody.querySelectorAll('tr[data-id]').forEach(row => {
      row.addEventListener('click', () => openModal(row.getAttribute('data-id')));
    });
  }

  async function renderAll() {
    cachedRecords = await SentinelAPI.all({ limit: 500 });
    await renderStats();
    renderBarChart(cachedRecords);
    renderTable();
  }

  async function renderModelInfo() {
    const info = await SentinelAPI.modelInfo();
    const m = info.current.metrics;
    const meta = info.current.meta;
    modelVersionTag.textContent = info.current.version;
    modelTrainedAt.textContent = new Date(meta.trained_at).toLocaleString();
    modelSampleCount.textContent = meta.n_samples_total.toLocaleString();
    mAccuracy.textContent = pct(m.accuracy);
    mPrecision.textContent = pct(m.precision);
    mRecall.textContent = pct(m.recall);
    mF1.textContent = pct(m.f1_score);
    mFPR.textContent = pct(m.false_positive_rate);
    mFNR.textContent = pct(m.false_negative_rate);
    pendingFeedbackTag.textContent = `${info.pending_feedback_count} feedback item(s) awaiting retrain`;

    modelVersionList.innerHTML = info.versions.map(v => `
      <div class="model-version-row">
        <span class="v-tag ${v.is_current ? 'v-current' : ''}">${v.version}${v.is_current ? ' (current)' : ''}</span>
        <span>${new Date(v.trained_at).toLocaleDateString()}</span>
        <span>acc ${pct(v.accuracy)} · prec ${pct(v.precision)} · recall ${pct(v.recall)}</span>
        <span style="color:var(--paper-muted)">+${v.n_feedback_folded_in} feedback</span>
        ${v.is_current ? '' : `<button class="btn btn-ghost btn-sm" data-promote="${v.version}">Promote</button>`}
      </div>
    `).join('');
  }

  modelVersionList.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-promote]');
    if (!btn) return;
    const version = btn.dataset.promote;
    btn.setAttribute('disabled', 'disabled');
    btn.textContent = 'Promoting…';
    try {
      await SentinelAPI.promoteModelVersion(version);
      showToast(`${version} is now live`);
      await renderModelInfo();
    } catch (err) {
      showToast(err.message || `Could not promote ${version}`);
      btn.removeAttribute('disabled');
      btn.textContent = 'Promote';
    }
  });

  function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

  async function pollRetrainJob(jobId, { intervalMs = 2000, timeoutMs = 5 * 60000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const status = await SentinelAPI.retrainStatus(jobId);
      if (status.status === 'done') return status;
      if (status.status === 'failed') throw new Error(status.error || 'Retrain job failed');
      await sleep(intervalMs);
    }
    throw new Error('Retrain job timed out waiting for a result');
  }

  retrainBtn.addEventListener('click', async () => {
    retrainBtn.setAttribute('disabled', 'disabled');
    retrainBtn.textContent = 'Queuing retrain job…';
    try {
      const { job_id } = await SentinelAPI.retrain();
      retrainBtn.textContent = 'Retraining… (this can take ~1 minute)';
      const res = await pollRetrainJob(job_id);
      // Deliberately not live yet -- see the version-history "Promote"
      // button. Training produces a candidate; an admin reviews these
      // metrics and decides whether it's actually better before it
      // serves real traffic.
      showToast(`${res.version} trained — precision ${Math.round(res.metrics.precision * 100)}%. Review and promote below when ready.`);
      await renderModelInfo();
    } catch (err) {
      showToast(err.message || 'Retrain failed');
    } finally {
      retrainBtn.removeAttribute('disabled');
      retrainBtn.textContent = 'Retrain with new feedback';
    }
  });

  filterTabs.addEventListener('click', (e) => {
    const btn = e.target.closest('.ftab');
    if (!btn) return;
    filterTabs.querySelectorAll('.ftab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = btn.getAttribute('data-f');
    renderTable();
  });

  sourceTabs.addEventListener('click', (e) => {
    const btn = e.target.closest('.ftab');
    if (!btn) return;
    sourceTabs.querySelectorAll('.ftab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeSource = btn.getAttribute('data-s');
    renderTable();
  });

  resetDataBtn.addEventListener('click', async () => {
    resetDataBtn.setAttribute('disabled', 'disabled');
    try {
      await SentinelAPI.resetDemoData();
      await renderAll();
      showToast('Demo data reset');
    } catch (err) {
      showToast(err.message || 'Reset failed');
    } finally {
      resetDataBtn.removeAttribute('disabled');
    }
  });

  async function openModal(scanId) {
    const record = await SentinelAPI.getScan(scanId);
    modalId.textContent = record.scan_id;
    modalSubject.textContent = record.subject;
    modalFrom.textContent = record.from;
    modalTime.textContent = fmtTime(record.scan_timestamp);
    {
      const copy = Sentinel.verdictCopy(record.classification);
      const phishPct = Math.round((record.phishing_probability ?? record.confidence_score ?? 0) * 100);
      const confPct = Math.round((record.prediction_confidence ?? Math.max(record.confidence_score || 0, 1 - (record.confidence_score || 0))) * 100);
      modalVerdict.innerHTML = `<span class="chip ${copy.chip}">${record.classification}</span> &nbsp; ${phishPct}% phishing probability · ${confPct}% prediction confidence · ${record.risk_level} risk · model ${record.model_version || '—'}`;
    }
    modalStatus.innerHTML = `<span class="status-pill status-${record.status}">${record.status}</span>
      <span class="source-chip ${record.source === 'mailbox' ? 'source-mailbox' : 'source-manual'}" style="margin-left:8px">${record.source === 'mailbox' ? 'Live mailbox' : 'Manual'}</span>
      ${record.source === 'mailbox' ? `<div style="margin-top:6px;font-family:var(--mono);font-size:.76rem;color:var(--paper-muted)">
        Real mailbox action: ${record.mailbox_action === 'quarantined' ? 'moved to quarantine folder' : record.mailbox_action === 'flagged' ? 'flagged in inbox' : 'left in inbox'}
        ${record.mailbox_action_error ? `<br><span style="color:var(--threat)">Action failed: ${Sentinel.escapeHtml(record.mailbox_action_error)}</span>` : ''}
      </div>` : ''}`;
    modalBodyText.innerHTML = record.body_purged
      ? `<em style="color:var(--paper-muted)">${Sentinel.escapeHtml(record.body)}</em>`
      : Sentinel.highlight(record.body || '', record.highlights).replace(/\n/g, '<br>');

    modalFindings.innerHTML = (record.findings || []).length
      ? record.findings.map(f => `<div class="finding-item"><span class="finding-sev ${f.severity}"></span><div><div class="finding-title">${f.type} <span style="color:var(--paper-muted);font-weight:400">(${Sentinel.findingCategory(f.type)})</span></div><div class="finding-detail">${Sentinel.escapeHtml(f.detail)}</div></div></div>`).join('')
      : '<div class="finding-item"><span class="finding-sev low"></span><div class="finding-title">No explicit rule-based phishing indicators were detected. The decision was influenced mainly by the machine-learning text model.</div></div>';

    modalActions.innerHTML = '';
    if (record.status === 'Quarantined' || record.status === 'Flagged') {
      addAction('Release (false positive)', 'btn-safe', () => actOn(scanId, 'release'));
      addAction('Confirm phishing', 'btn-danger', () => actOn(scanId, 'confirm'));
      addAction('Escalate for review', 'btn-dark', () => actOn(scanId, 'escalate'));
    } else {
      addAction('Report as phishing', 'btn-danger', () => actOn(scanId, 'confirm'));
    }

    modalBackdrop.classList.add('show');
  }

  function addAction(label, cls, handler) {
    const b = document.createElement('button');
    b.className = 'btn btn-sm ' + cls;
    b.textContent = label;
    b.addEventListener('click', handler);
    modalActions.appendChild(b);
  }

  async function actOn(scanId, action) {
    try {
      const record = await SentinelAPI.adminAction(scanId, action);
      showToast(record.notes);
      closeModal();
      await renderAll();
    } catch (err) {
      showToast(err.message || 'Action failed');
    }
  }

  function closeModal() {
    modalBackdrop.classList.remove('show');
  }
  modalClose.addEventListener('click', closeModal);
  modalBackdrop.addEventListener('click', (e) => { if (e.target === modalBackdrop) closeModal(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });
})();
