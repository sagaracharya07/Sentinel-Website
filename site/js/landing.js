(() => {
  const mailTextEl = document.getElementById('heroMailText');
  const scanlineEl = document.getElementById('scanline');
  const scoreRing = document.getElementById('scoreRing');
  const scoreNum = document.getElementById('scoreNum');
  const verdictChip = document.getElementById('verdictChip');
  const findingsList = document.getElementById('findingsList');
  const replayBtn = document.getElementById('replay');

  if (!mailTextEl) return;

  let result = null; // filled in from the real backend on first load

  function buildMarkup() {
    if (!result) return '';
    return Sentinel.highlight(result.body, result.highlights).replace(/\n/g, '<br>');
  }

  function animateScore(target) {
    let current = 0;
    const duration = 900;
    const start = performance.now();
    function tick(now) {
      const p = Math.min(1, (now - start) / duration);
      current = Math.round(target * p);
      scoreNum.textContent = current;
      scoreRing.style.setProperty('--pct', current);
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  function runDemo() {
    if (!result) return;
    mailTextEl.innerHTML = buildMarkup();
    findingsList.innerHTML = '';
    scoreNum.textContent = '0';
    scoreRing.style.setProperty('--pct', 0);
    verdictChip.textContent = 'Analyzing…';
    verdictChip.style.color = 'var(--ink-text)';

    scanlineEl.classList.remove('run');
    void scanlineEl.offsetWidth; // restart animation
    scanlineEl.classList.add('run');

    const marks = mailTextEl.querySelectorAll('mark');
    marks.forEach((m, i) => {
      setTimeout(() => m.classList.add('hit'), 300 + i * 260);
    });

    setTimeout(() => {
      animateScore(result.score);
    }, 500);

    result.findings.slice(0, 4).forEach((f, i) => {
      const row = document.createElement('div');
      row.className = 'finding-row';
      row.innerHTML = `<span class="fdot"></span>${f.type}`;
      findingsList.appendChild(row);
      setTimeout(() => row.classList.add('show'), 700 + i * 220);
    });

    setTimeout(() => {
      verdictChip.textContent = result.label === 'Phishing' ? 'Phishing detected' : 'Looks legitimate';
      verdictChip.style.color = result.label === 'Phishing' ? 'var(--threat)' : 'var(--safe)';
    }, 1900);
  }

  // This hits the real trained Random Forest model (same one the live
  // scanner uses) so the homepage hero shows a genuine verdict, not a
  // hardcoded number.
  SentinelAPI.demoScan()
    .then(r => { result = r; runDemo(); })
    .catch(() => {
      verdictChip.textContent = 'Demo unavailable';
      mailTextEl.textContent = 'Could not reach the detection service. Start the backend (see README) to see this live.';
    });

  replayBtn.addEventListener('click', runDemo);
})();
