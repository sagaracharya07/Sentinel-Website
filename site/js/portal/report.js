/* Report Suspicious Email — drag/drop .eml upload -> /api/reports/upload.
   Progress steps are honest: "validate" completes once the file passes
   client-side sanity checks (extension/size), "upload" marks active only
   while the request is in flight, and "analyse" is only marked done once the
   server actually returns the created report -- no step is shown complete
   before its backend counterpart has actually finished. */
(function () {
  'use strict';
  const { esc, toast } = window.SentinelUI;

  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('emlFile');
  const fileInfo = document.getElementById('fileInfo');
  const uploadBtn = document.getElementById('uploadBtn');
  const errorBox = document.getElementById('uploadError');
  const progressBox = document.getElementById('progressBox');
  const resultCard = document.getElementById('resultCard');

  const MAX_BYTES = 5 * 1024 * 1024;
  let selectedFile = null;

  function setStep(name, state) {
    const el = progressBox.querySelector('[data-step="' + name + '"]');
    if (!el) return;
    el.classList.remove('done', 'active', 'failed');
    if (state) el.classList.add(state);
  }

  function validate(file) {
    if (!file.name.toLowerCase().endsWith('.eml')) return 'Only .eml files are accepted.';
    if (file.size === 0) return 'The selected file is empty.';
    if (file.size > MAX_BYTES) return 'File too large (max 5 MB).';
    return null;
  }

  function selectFile(file) {
    errorBox.classList.remove('show');
    const err = validate(file);
    if (err) {
      selectedFile = null; uploadBtn.disabled = true;
      fileInfo.hidden = true;
      errorBox.textContent = err; errorBox.classList.add('show');
      return;
    }
    selectedFile = file;
    fileInfo.hidden = false;
    fileInfo.textContent = file.name + ' — ' + (file.size / 1024).toFixed(1) + ' KB';
    uploadBtn.disabled = false;
  }

  fileInput.addEventListener('change', () => { if (fileInput.files[0]) selectFile(fileInput.files[0]); });
  ['dragover', 'dragenter'].forEach((evt) => dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach((evt) => dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.remove('drag'); }));
  dropzone.addEventListener('drop', (e) => {
    const f = e.dataTransfer.files[0];
    if (f) selectFile(f);
  });

  function renderResult(report) {
    const scan = report.scan || {};
    const findings = (scan.findings || []).slice(0, 8);
    resultCard.hidden = false;
    resultCard.innerHTML =
      '<h3 style="margin-bottom:var(--sp-3)">Automated assessment</h3>' +
      '<div class="row-wrap" style="margin-bottom:var(--sp-3)">' + window.PortalUI.verdictBadge(scan.classification) +
        '<span class="risk risk-' + (scan.risk_level || 'low').toLowerCase() + '">' + esc(scan.risk_level || '') + ' risk</span></div>' +
      '<div class="muted mono" style="font-size:.8rem;margin-bottom:var(--sp-3)">Report #' + report.id + ' — awaiting administrator review</div>' +
      (findings.length
        ? findings.map(window.PortalUI.findingHtml).join('')
        : '<div class="muted" style="font-size:.85rem">No specific risk signals detected.</div>') +
      '<a href="/app/reports/' + report.id + '" class="btn btn-primary btn-sm" style="margin-top:var(--sp-4)">View full report</a>';
  }

  uploadBtn.addEventListener('click', async () => {
    if (!selectedFile) return;
    uploadBtn.disabled = true;
    errorBox.classList.remove('show');
    progressBox.hidden = false;
    resultCard.hidden = true;
    setStep('validate', 'done');
    setStep('upload', 'active');
    try {
      const report = await SentinelAPI.reportUpload(selectedFile);
      setStep('upload', 'done');
      setStep('analyse', 'done');
      toast('Report submitted successfully', 'ok');
      renderResult(report);
      fileInput.value = ''; selectedFile = null; fileInfo.hidden = true;
    } catch (e) {
      setStep('upload', 'failed');
      errorBox.textContent = e.message || 'Upload failed';
      errorBox.classList.add('show');
      toast('Upload failed: ' + e.message, 'err');
    } finally {
      uploadBtn.disabled = !selectedFile;
    }
  });
})();
