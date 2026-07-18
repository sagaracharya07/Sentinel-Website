/* ==========================================================================
   SentinelAPI — thin fetch() wrapper around the real Flask backend.
   Replaces the old localStorage-backed SentinelStore (FR-DB-01..08 are now
   backed by an actual SQLite database, not the browser) and the old
   client-side heuristic classifier (FR-SE-05..08 are now a trained Random
   Forest model running server-side). Every call is same-origin, credentials
   included so the Flask session cookie is sent.
   ========================================================================== */
const SentinelAPI = (() => {

  // Fetched fresh for every state-changing request rather than cached --
  // simpler than tracking token expiry, and the extra GET is cheap next
  // to the request it's protecting. See backend/app.py's CSRFProtect
  // setup and GET /api/csrf-token.
  async function getCsrfToken() {
    const res = await fetch('/api/csrf-token', { credentials: 'same-origin' });
    const data = await res.json();
    return data.csrf_token;
  }

  async function request(path, opts = {}) {
    const method = (opts.method || 'GET').toUpperCase();
    const headers = { 'Content-Type': 'application/json' };
    if (method !== 'GET' && method !== 'HEAD') {
      headers['X-CSRFToken'] = await getCsrfToken();
    }
    const res = await fetch(path, {
      credentials: 'same-origin',
      ...opts,
      headers: { ...headers, ...(opts.headers || {}) },
    });
    let data = null;
    try { data = await res.json(); } catch (e) { /* no body */ }
    if (!res.ok) {
      const err = new Error((data && data.error) || `Request failed (${res.status})`);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  // ---- auth ----
  const login = (username, password) =>
    request('/api/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
  const logout = () => request('/api/auth/logout', { method: 'POST' });
  const me = () => request('/api/auth/me');
  const register = (username, email, password) =>
    request('/api/auth/register', { method: 'POST', body: JSON.stringify({ username, email, password }) });
  const forgotPassword = (email) =>
    request('/api/auth/forgot-password', { method: 'POST', body: JSON.stringify({ email }) });
  const resetPassword = (token, password) =>
    request('/api/auth/reset-password', { method: 'POST', body: JSON.stringify({ token, password }) });
  const changePassword = (current_password, new_password) =>
    request('/api/auth/change-password', { method: 'POST', body: JSON.stringify({ current_password, new_password }) });

  // ---- scanning ----
  const scan = (payload) => request('/api/scan', { method: 'POST', body: JSON.stringify(payload) });

  const all = (opts = {}) => {
    const params = new URLSearchParams();
    if (opts.mine) params.set('mine', 'true');
    if (opts.status) params.set('status', opts.status);
    if (opts.limit) params.set('limit', String(opts.limit));
    const qs = params.toString();
    return request('/api/history' + (qs ? '?' + qs : ''));
  };

  const getScan = (scanId) => request('/api/scan/' + encodeURIComponent(scanId));
  const stats = () => request('/api/stats');

  // ---- feedback / admin actions ----
  const submitFeedback = (scan_id, corrected_label) =>
    request('/api/feedback', { method: 'POST', body: JSON.stringify({ scan_id, corrected_label }) });

  const adminAction = (scan_id, action) =>
    request('/api/admin/action', { method: 'POST', body: JSON.stringify({ scan_id, action }) });

  // ---- model / retraining ----
  const modelInfo = () => request('/api/admin/model-info');
  // Retraining now runs on a background job queue (Celery) instead of
  // blocking the request -- this kicks it off and returns a job id.
  const retrain = () => request('/api/admin/retrain', { method: 'POST', body: JSON.stringify({}) });
  const retrainStatus = (jobId) => request('/api/admin/retrain/' + encodeURIComponent(jobId));
  // Makes `version` the one classify() actually serves -- also how a
  // rollback to an older version works, same endpoint either way.
  const promoteModelVersion = (version) =>
    request('/api/admin/model-version/' + encodeURIComponent(version) + '/promote', { method: 'POST' });
  const auditLog = (limit = 50) => request('/api/admin/audit-log?limit=' + limit);
  const resetDemoData = () => request('/api/admin/reset-demo-data', { method: 'POST' });

  // ---- live mailbox integration (legacy IMAP) ----
  const mailboxStatus = () => request('/api/admin/mailbox-status');
  const mailboxTest = () => request('/api/admin/mailbox-test', { method: 'POST' });
  const mailboxSync = () => request('/api/admin/mailbox-sync', { method: 'POST', body: JSON.stringify({}) });

  // ---- Gmail OAuth / connected mailboxes (primary integration) ----
  const gmailStatus = () => request('/api/admin/gmail/status');
  const gmailAuthorizeUrl = () => request('/api/admin/gmail/authorize-url');
  const gmailReconnect = () => request('/api/admin/gmail/reconnect', { method: 'POST', body: JSON.stringify({}) });
  const gmailDisconnect = () => request('/api/admin/gmail/disconnect', { method: 'POST', body: JSON.stringify({}) });
  const gmailPause = () => request('/api/admin/gmail/pause', { method: 'POST', body: JSON.stringify({}) });
  const gmailResume = () => request('/api/admin/gmail/resume', { method: 'POST', body: JSON.stringify({}) });
  const gmailTest = () => request('/api/admin/gmail/test', { method: 'POST', body: JSON.stringify({}) });
  const gmailScanNow = () => request('/api/admin/gmail/scan-now', { method: 'POST', body: JSON.stringify({}) });

  // ---- employee .eml reporting ----
  async function reportUpload(file) {
    const token = await getCsrfToken();
    const fd = new FormData();
    fd.append('file', file);
    const res = await fetch('/api/reports/upload', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-CSRFToken': token },  // no Content-Type: browser sets the multipart boundary
      body: fd,
    });
    let data = null;
    try { data = await res.json(); } catch (e) { /* no body */ }
    if (!res.ok) {
      const err = new Error((data && data.error) || `Upload failed (${res.status})`);
      err.status = res.status;
      throw err;
    }
    return data;
  }
  const reportsMine = () => request('/api/reports/mine');
  const reportDetail = (id) => request('/api/reports/' + encodeURIComponent(id));

  // ---- admin detections / incidents / reported queue ----
  const detectionList = (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request('/api/admin/detections' + (qs ? '?' + qs : ''));
  };
  const quarantineList = () => request('/api/admin/detections/quarantine');
  const needsReviewList = () => request('/api/admin/detections/needs-review');
  const incidentDetail = (scanId) => request('/api/admin/detections/' + encodeURIComponent(scanId));
  const relatedMessages = (scanId) => request('/api/admin/detections/' + encodeURIComponent(scanId) + '/related');
  const adminReports = (status) => request('/api/admin/reports' + (status ? '?status=' + status : ''));
  const reviewReport = (id, verdict) =>
    request('/api/admin/reports/' + encodeURIComponent(id) + '/review', { method: 'POST', body: JSON.stringify({ verdict }) });

  // ---- public (no login) ----
  const demoScan = () => request('/api/public/demo-scan');
  const submitContact = (payload) => request('/api/contact', { method: 'POST', body: JSON.stringify(payload) });

  // ---- users & roles (admin-only) ----
  const usersList = (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request('/api/admin/users' + (qs ? '?' + qs : ''));
  };
  const userChangeRole = (id, role) =>
    request('/api/admin/users/' + encodeURIComponent(id) + '/role', { method: 'POST', body: JSON.stringify({ role }) });
  const userSuspend = (id) => request('/api/admin/users/' + encodeURIComponent(id) + '/suspend', { method: 'POST' });
  const userActivate = (id) => request('/api/admin/users/' + encodeURIComponent(id) + '/activate', { method: 'POST' });

  // ---- system health (admin-only) ----
  const systemHealth = () => request('/api/admin/system-health');

  // ---- settings: detection policy (admin-only) ----
  const detectionPolicy = () => request('/api/admin/settings/detection-policy');
  const updateDetectionPolicy = (needsReviewThreshold, phishingThreshold) =>
    request('/api/admin/settings/detection-policy', {
      method: 'POST',
      body: JSON.stringify({ needs_review_threshold: needsReviewThreshold, phishing_threshold: phishingThreshold }),
    });

  return {
    login, logout, me, register, forgotPassword, resetPassword, changePassword,
    scan, all, getScan, stats,
    submitFeedback, adminAction, modelInfo, retrain, retrainStatus, promoteModelVersion, auditLog, resetDemoData, demoScan,
    mailboxStatus, mailboxTest, mailboxSync, submitContact,
    gmailStatus, gmailAuthorizeUrl, gmailReconnect, gmailDisconnect, gmailPause, gmailResume,
    gmailTest, gmailScanNow,
    reportUpload, reportsMine, reportDetail,
    detectionList, quarantineList, needsReviewList, incidentDetail, relatedMessages,
    adminReports, reviewReport,
    usersList, userChangeRole, userSuspend, userActivate,
    systemHealth, detectionPolicy, updateDetectionPolicy,
  };
})();
