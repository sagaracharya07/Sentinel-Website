/* Settings -> Detection Policy — the one write-capable settings page. Reads
   current values, validates ordering client-side (server re-validates
   authoritatively -- see routes/settings.py), and requires confirmation
   before submitting since this changes live classification behaviour. */
(function () {
  'use strict';
  const { esc, toast, absTime } = window.SentinelUI;

  const loading = document.getElementById('policyLoading');
  const form = document.getElementById('policyForm');
  const needsReviewInput = document.getElementById('needsReviewInput');
  const phishingInput = document.getElementById('phishingInput');
  const errorBox = document.getElementById('policyError');
  const meta = document.getElementById('policyMeta');
  const saveBtn = document.getElementById('policySaveBtn');

  async function load() {
    try {
      const data = await SentinelAPI.detectionPolicy();
      needsReviewInput.value = data.needs_review_threshold;
      phishingInput.value = data.phishing_threshold;
      meta.textContent = data.updated_by ? 'Last changed by ' + data.updated_by + ' — ' + esc(absTime(data.updated_at)) : 'Using project defaults';
      loading.hidden = true;
      form.hidden = false;
    } catch (e) {
      loading.innerHTML = '<div class="state state-error"><div class="state-title">Could not load settings</div><div class="state-msg">' + esc(e.message) + '</div></div>';
    }
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorBox.classList.remove('show');
    const nr = parseFloat(needsReviewInput.value);
    const ph = parseFloat(phishingInput.value);
    if (!(nr > 0 && ph > nr && ph < 1)) {
      errorBox.textContent = 'Needs Review threshold must be less than Phishing threshold, and both must be between 0 and 1.';
      errorBox.classList.add('show');
      return;
    }
    if (!confirm('Apply new detection thresholds? This changes how new mail is classified immediately.')) return;
    saveBtn.disabled = true;
    try {
      const data = await SentinelAPI.updateDetectionPolicy(nr, ph);
      toast('Detection policy updated', 'ok');
      meta.textContent = 'Last changed by ' + data.updated_by + ' — ' + esc(absTime(data.updated_at));
    } catch (err) {
      errorBox.textContent = err.data?.error || err.message;
      errorBox.classList.add('show');
    } finally { saveBtn.disabled = false; }
  });

  load();
})();
