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
  const confidenceRow = document.getElementById('confidenceRow');
  const senderBox = document.getElementById('senderBox');
  const contentBox = document.getElementById('contentBox');
  const linkBox = document.getElementById('linkBox');
  const recommendedActionBox = document.getElementById('recommendedActionBox');
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

  function findingRowHtml(f) {
    return `<div class="finding-item"><span class="finding-sev ${f.severity}"></span><div><div class="finding-title">${f.type} <span style="color:var(--paper-muted);font-weight:400">+${f.weight}pts</span></div><div class="finding-detail">${Sentinel.escapeHtml(f.detail)}</div></div></div>`;
  }

  function renderResult(result) {
    const copy = Sentinel.verdictCopy(result.classification);

    gauge.style.setProperty('--gpct', 0);
    gauge.style.setProperty('--gcolor', copy.color);
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

    verdictTitle.textContent = copy.title;
    verdictTitle.style.color = copy.color;
    verdictSub.textContent = `${result.findings.length} signal(s) found · model ${result.model_version}`;

    const phishingPct = Math.round((result.phishing_probability ?? result.confidence_score ?? 0) * 100);
    const confPct = Math.round((result.prediction_confidence ?? Math.max(result.confidence_score, 1 - result.confidence_score)) * 100);
    confidenceRow.innerHTML = `<span>Phishing probability: <b>${phishingPct}%</b></span><span>Prediction confidence: <b>${confPct}%</b></span>`;

    riskChip.className = 'chip ' + copy.chip;
    riskChip.textContent = result.risk_level + ' risk';

    // Manual scans on this page are never a live mailbox message, so the
    // mailbox-action section always reads "not applicable" here -- the
    // admin console is where a real mailbox_action shows up.
    document.getElementById('sourceTag').textContent = 'Manual text scan';
    recommendedActionBox.textContent = copy.action;

    const bySection = { 'Sender analysis': [], 'Content indicators': [], 'Link indicators': [] };
    (result.findings || []).forEach(f => bySection[Sentinel.findingCategory(f.type)].push(f));

    const emptyNote = 'No explicit rule-based phishing indicators were detected. The decision was influenced mainly by the machine-learning text model.';
    [['Sender analysis', senderBox], ['Content indicators', contentBox], ['Link indicators', linkBox]].forEach(([key, el]) => {
      const items = bySection[key];
      el.innerHTML = items.length
        ? items.map(findingRowHtml).join('')
        : `<div class="result-section-empty">${result.findings.length === 0 ? emptyNote : 'No indicators in this category.'}</div>`;
    });

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
      recentBody.innerHTML = records.map(r => {
        const copy = Sentinel.verdictCopy(r.classification);
        const conf = r.prediction_confidence ?? Math.max(r.confidence_score || 0, 1 - (r.confidence_score || 0));
        return `
        <tr>
          <td style="font-family:var(--mono);font-size:.78rem;color:var(--paper-muted)">${timeAgo(r.scan_timestamp)}</td>
          <td>${Sentinel.escapeHtml(r.subject).slice(0, 52)}</td>
          <td><span class="chip ${copy.chip}">${r.classification}</span></td>
          <td style="font-family:var(--mono)">${Math.round(conf * 100)}%</td>
          <td>${r.risk_level}</td>
          <td><span class="status-pill status-${r.status}">${r.status}</span></td>
        </tr>
      `;
      }).join('');
    } catch (err) {
      recentBody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--paper-muted);padding:24px">Could not load history.</td></tr>`;
    }
  }
})();
