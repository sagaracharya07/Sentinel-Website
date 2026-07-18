/* Quick Analysis — pasted-text scan via /api/scan (secondary method; see
   report.js for the primary .eml upload). */
(function () {
  'use strict';
  const { esc, toast } = window.SentinelUI;
  const P = window.PortalUI;

  const btn = document.getElementById('qaScanBtn');
  const errorBox = document.getElementById('qaError');
  const result = document.getElementById('qaResult');

  function render(scan) {
    const findings = scan.findings || [];
    result.hidden = false;
    result.innerHTML =
      '<h3 style="margin-bottom:var(--sp-3)">Result</h3>' +
      '<div class="row-wrap" style="margin-bottom:var(--sp-3)">' + P.verdictBadge(scan.classification) +
        '<span class="risk risk-' + (scan.risk_level || 'low').toLowerCase() + '">' + esc(scan.risk_level || '') + ' risk</span></div>' +
      '<div class="mono" style="font-size:.85rem;color:var(--text-2);margin-bottom:var(--sp-3)">' +
        'Phishing probability: <strong>' + P.pct(scan.phishing_probability) + '</strong> · ' +
        'Confidence: <strong>' + P.pct(scan.prediction_confidence) + '</strong></div>' +
      (findings.length ? findings.map(P.findingHtml).join('') :
        '<div class="muted" style="font-size:.85rem">No specific risk signals detected in the pasted text.</div>') +
      '<div class="callout" style="margin-top:var(--sp-4)"><svg class="icon" aria-hidden="true"><use href="#i-alert"></use></svg>' +
      '<div>This is a limited, text-only check — it did not verify sender authentication or real link destinations. For a full investigation, use Report Suspicious Email.</div></div>';
  }

  btn.addEventListener('click', async () => {
    const body = document.getElementById('qaBody').value.trim();
    errorBox.classList.remove('show');
    if (!body) {
      errorBox.textContent = 'Message body is required.';
      errorBox.classList.add('show');
      return;
    }
    btn.disabled = true;
    try {
      const scan = await SentinelAPI.scan({
        from: document.getElementById('qaFrom').value.trim(),
        subject: document.getElementById('qaSubject').value.trim(),
        body,
      });
      render(scan);
    } catch (e) {
      errorBox.textContent = e.message || 'Analysis failed';
      errorBox.classList.add('show');
      toast('Analysis failed: ' + e.message, 'err');
    } finally { btn.disabled = false; }
  });
})();
