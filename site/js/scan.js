(() => {
  const fromInput = document.getElementById('fromInput');
  const subjectInput = document.getElementById('subjectInput');
  const bodyInput = document.getElementById('bodyInput');
  const errMsg = document.getElementById('errMsg');
  const scanBtn = document.getElementById('scanBtn');
  const sampleBtn = document.getElementById('sampleBtn');
  const resetBtn = document.getElementById('resetBtn');
  const processing = document.getElementById('processing');

  const emptyHint = document.getElementById('emptyHint');
  const resultCard = document.getElementById('resultCard');
  const gauge = document.getElementById('gauge');
  const gaugeNum = document.getElementById('gaugeNum');
  const verdictTitle = document.getElementById('verdictTitle');
  const verdictSub = document.getElementById('verdictSub');
  const riskChip = document.getElementById('riskChip');
  const findingsBox = document.getElementById('findingsBox');
  const annotated = document.getElementById('annotated');
  const fbLegit = document.getElementById('fbLegit');
  const fbPhish = document.getElementById('fbPhish');
  const fbNote = document.getElementById('fbNote');

  const recentBody = document.getElementById('recentBody');
  const recentCount = document.getElementById('recentCount');

  let currentScanId = null;

  const SAMPLE = {
    from: '"PayPal Security" <security@paypa1-support.com>',
    subject: 'Your account will be suspended — verify now',
    body: 'Dear Customer,\n\nWe detected unusual activity on your account. Verify your account immediately or it will be suspended within 24 hours.\n\nClick here to confirm your password and avoid interruption: http://bit.ly/verify-acct\n\nPayPal Security Team'
  };

  (async function init() {
    const user = await SentinelAuth.requireLogin();
    if (!user) return; // redirected to login
    SentinelAuth.renderUserBadge(user);
    renderRecent();
  })();

  sampleBtn.addEventListener('click', () => {
    fromInput.value = SAMPLE.from;
    subjectInput.value = SAMPLE.subject;
    bodyInput.value = SAMPLE.body;
    errMsg.style.display = 'none';
  });

  resetBtn.addEventListener('click', () => {
    fromInput.value = '';
    subjectInput.value = '';
    bodyInput.value = '';
    errMsg.style.display = 'none';
    resultCard.classList.remove('show');
    emptyHint.style.display = 'block';
  });

  scanBtn.addEventListener('click', async () => {
    const body = bodyInput.value.trim();
    if (!body) {
      errMsg.textContent = 'Please paste the email body before scanning.';
      errMsg.style.display = 'block';
      bodyInput.focus();
      return;
    }
    errMsg.style.display = 'none';
    emptyHint.style.display = 'none';
    resultCard.classList.remove('show');
    processing.classList.add('show');
    scanBtn.setAttribute('disabled', 'disabled');

    try {
      const record = await SentinelAPI.scan({
        subject: subjectInput.value.trim(),
        body,
        from: fromInput.value.trim(),
      });
      renderResult(record);
      currentScanId = record.scan_id;
      renderRecent();
    } catch (err) {
      errMsg.textContent = err.message || 'Scan failed — please try again.';
      errMsg.style.display = 'block';
    } finally {
      processing.classList.remove('show');
      scanBtn.removeAttribute('disabled');
    }
  });

  function renderResult(result) {
    const isPhish = result.classification === 'Phishing';
    const color = isPhish ? 'var(--threat)' : 'var(--safe)';

    gauge.style.setProperty('--gpct', 0);
    gauge.style.setProperty('--gcolor', color);
    requestAnimationFrame(() => {
      let n = 0;
      const target = result.score;
      const step = () => {
        n = Math.min(target, n + Math.ceil(target / 24 || 1));
        gaugeNum.textContent = n;
        gauge.style.setProperty('--gpct', n);
        if (n < target) requestAnimationFrame(step);
      };
      step();
    });

    verdictTitle.textContent = isPhish ? 'Phishing detected' : 'Looks legitimate';
    verdictTitle.style.color = color;
    verdictSub.textContent = `Confidence ${(result.confidence_score * 100).toFixed(0)}% · ${result.findings.length} signal(s) found · model ${result.model_version}`;

    riskChip.className = 'chip ' + (result.risk_level === 'High' ? 'chip-threat' : result.risk_level === 'Medium' ? 'chip-warn' : 'chip-safe');
    riskChip.textContent = result.risk_level + ' risk';

    findingsBox.innerHTML = '';
    if (result.findings.length === 0) {
      findingsBox.innerHTML = '<div class="finding-item"><span class="finding-sev low"></span><div><div class="finding-title">No risk signals detected</div><div class="finding-detail">No known phishing indicators were found in this message.</div></div></div>';
    } else {
      result.findings.forEach(f => {
        const row = document.createElement('div');
        row.className = 'finding-item';
        row.innerHTML = `<span class="finding-sev ${f.severity}"></span><div><div class="finding-title">${f.type} <span style="color:var(--paper-muted);font-weight:400">+${f.weight}pts</span></div><div class="finding-detail">${Sentinel.escapeHtml(f.detail)}</div></div>`;
        findingsBox.appendChild(row);
      });
    }

    annotated.innerHTML = Sentinel.highlight(result.body, result.highlights).replace(/\n/g, '<br>');

    fbNote.classList.remove('show');
    resultCard.classList.add('show');
  }

  fbLegit.addEventListener('click', () => submitFeedback('Legitimate'));
  fbPhish.addEventListener('click', () => submitFeedback('Phishing'));

  async function submitFeedback(correctedLabel) {
    if (!currentScanId) return;
    try {
      await SentinelAPI.submitFeedback(currentScanId, correctedLabel);
      fbNote.textContent = `Thanks — recorded as ${correctedLabel}. This feeds the next model retraining pass.`;
      fbNote.classList.add('show');
      renderRecent();
    } catch (err) {
      fbNote.textContent = err.message || 'Could not record feedback.';
      fbNote.classList.add('show');
    }
  }

  function timeAgo(iso) {
    const diff = Date.now() - new Date(iso + (iso.endsWith('Z') ? '' : 'Z')).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  }

  async function renderRecent() {
    try {
      const records = await SentinelAPI.all({ mine: true, limit: 8 });
      recentCount.textContent = `${records.length} scan(s)`;
      recentBody.innerHTML = records.map(r => `
        <tr>
          <td style="font-family:var(--mono);font-size:.78rem;color:var(--paper-muted)">${timeAgo(r.scan_timestamp)}</td>
          <td>${Sentinel.escapeHtml(r.subject).slice(0, 52)}</td>
          <td><span class="chip ${r.classification === 'Phishing' ? 'chip-threat' : 'chip-safe'}">${r.classification}</span></td>
          <td style="font-family:var(--mono)">${Math.round((r.confidence_score || 0) * 100)}%</td>
          <td>${r.risk_level}</td>
          <td><span class="status-pill status-${r.status}">${r.status}</span></td>
        </tr>
      `).join('');
    } catch (err) {
      recentBody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--paper-muted);padding:24px">Could not load history.</td></tr>`;
    }
  }
})();
