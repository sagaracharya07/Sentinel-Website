/* ==========================================================================
   Live Demo — entirely simulated, client-side only. No network calls, no
   real detection records are created. Clearly labelled as simulated
   throughout (see demo.html's banner).
   ========================================================================== */
(function () {
  'use strict';
  const { esc } = window.SentinelUI;

  const SCENARIOS = [
    {
      id: 'legit',
      label: 'Legitimate meeting email',
      from: 'Priya Nair <priya.nair@company-example.com>',
      subject: 'Team meeting notes — kickoff',
      body: 'Hi all, following up on scheduling our kickoff meeting this week. Let me know your availability.',
      verdict: 'Legitimate', risk: 'Low', probability: 0.06, confidence: 0.94,
      action: 'Delivered to inbox — no label change',
      findings: [
        { title: 'No sender anomalies', severity: 'low', evidence: 'Display name matches the sending domain' },
        { title: 'Authentication passed', severity: 'low', evidence: 'SPF, DKIM and DMARC all reported pass' },
      ],
    },
    {
      id: 'invoice',
      label: 'Suspicious invoice',
      from: 'Billing <billing@invoice-secure-payments.net>',
      subject: 'Invoice #88213 overdue — action required',
      body: 'Your invoice is overdue. Pay immediately via the secure link to avoid a penalty: http://bit.ly/pay-inv-now',
      verdict: 'Needs Review', risk: 'Medium', probability: 0.61, confidence: 0.61,
      action: 'Needs Review label applied — held for analyst review',
      findings: [
        { title: 'Urgency / pressure language', severity: 'medium', evidence: '"overdue", "immediately", "avoid a penalty"' },
        { title: 'Link uses a URL shortener', severity: 'medium', evidence: 'bit.ly' },
        { title: 'Sender domain is unfamiliar', severity: 'low', evidence: 'invoice-secure-payments.net has no prior history' },
      ],
    },
    {
      id: 'credential',
      label: 'Credential-phishing message',
      from: '"Microsoft Security" <security@micros0ft-verify.com>',
      subject: 'Unusual sign-in detected — verify your password now',
      body: 'We detected unusual activity on your account. Verify your password immediately or your account will be locked: http://bit.ly/ms-verify-acct',
      verdict: 'Phishing', risk: 'High', probability: 0.93, confidence: 0.93,
      action: 'Quarantined — moved out of the inbox via Gmail label',
      findings: [
        { title: 'Sender / brand mismatch', severity: 'high', evidence: 'Display name "Microsoft Security", domain micros0ft-verify.com (lookalike, zero for "o")' },
        { title: 'Requests sensitive information', severity: 'high', evidence: '"verify your password"' },
        { title: 'Urgency / pressure language', severity: 'high', evidence: '"immediately", "will be locked"' },
        { title: 'Displayed link differs from destination', severity: 'medium', evidence: 'shows a Microsoft-style link, goes to bit.ly' },
      ],
    },
  ];

  const STAGES = ['Validating message', 'Checking sender & authentication', 'Inspecting links', 'Calculating risk', 'Applying verdict'];

  const cardsEl = document.getElementById('demoCards');
  const stageCard = document.getElementById('demoStageCard');
  const progressEl = document.getElementById('demoProgress');
  const stepsEl = document.getElementById('demoSteps');
  const resultEl = document.getElementById('demoResult');
  let activeTimer = null;

  cardsEl.innerHTML = SCENARIOS.map((s) =>
    '<button class="demo-card" data-id="' + s.id + '">' +
      '<div class="d-subject">' + esc(s.subject) + '</div>' +
      '<div class="d-sender">' + esc(s.from) + '</div>' +
    '</button>'
  ).join('');

  function verdictBadge(v) {
    const map = { Legitimate: 'badge-legit', 'Needs Review': 'badge-review', Phishing: 'badge-phish' };
    return '<span class="badge ' + (map[v] || 'badge-muted') + '"><span class="dot"></span>' + esc(v) + '</span>';
  }

  function run(scenario) {
    clearTimeout(activeTimer);
    cardsEl.querySelectorAll('.demo-card').forEach((c) => c.classList.toggle('active', c.getAttribute('data-id') === scenario.id));
    stageCard.hidden = false;
    document.getElementById('stageSubject').textContent = scenario.subject;
    document.getElementById('stageSender').textContent = scenario.from;
    resultEl.innerHTML = '';
    progressEl.innerHTML = STAGES.map(() => '<span></span>').join('');
    stepsEl.innerHTML = STAGES.map((s) => '<div class="step"><span class="step-dot"></span> ' + esc(s) + '</div>').join('');

    const stepEls = Array.from(stepsEl.children);
    const barEls = Array.from(progressEl.children);
    let i = 0;
    function advance() {
      if (i > 0) { stepEls[i - 1].classList.remove('active'); stepEls[i - 1].classList.add('done'); }
      if (i < STAGES.length) {
        stepEls[i].classList.add('active');
        barEls[i].classList.add('done');
        i++;
        activeTimer = setTimeout(advance, 480);
      } else {
        showResult(scenario);
      }
    }
    advance();
  }

  function showResult(scenario) {
    resultEl.innerHTML =
      '<div class="row-wrap">' + verdictBadge(scenario.verdict) +
        '<span class="risk risk-' + scenario.risk.toLowerCase() + '">' + esc(scenario.risk) + ' risk</span></div>' +
      '<div class="mono" style="font-size:.85rem;color:var(--text-2)">Phishing probability: <strong>' + Math.round(scenario.probability * 100) + '%</strong> · ' +
        'Confidence: <strong>' + Math.round(scenario.confidence * 100) + '%</strong></div>' +
      scenario.findings.map((f) =>
        '<div class="finding"><span class="sev ' + f.severity + '"></span><div><div class="f-title">' + esc(f.title) + '</div><div class="f-evidence">' + esc(f.evidence) + '</div></div></div>'
      ).join('') +
      '<div class="callout" style="margin-top:var(--sp-3)"><svg class="icon" aria-hidden="true"><use href="#i-mail"></use></svg><div><strong>Simulated Gmail action:</strong> ' + esc(scenario.action) + '</div></div>';
  }

  cardsEl.addEventListener('click', (e) => {
    const btn = e.target.closest('.demo-card');
    if (!btn) return;
    const scenario = SCENARIOS.find((s) => s.id === btn.getAttribute('data-id'));
    if (scenario) run(scenario);
  });

  document.getElementById('demoResetBtn').addEventListener('click', () => {
    clearTimeout(activeTimer);
    stageCard.hidden = true;
    cardsEl.querySelectorAll('.demo-card').forEach((c) => c.classList.remove('active'));
  });
})();
