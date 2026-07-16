/* ==========================================================================
   SentinelAPI — thin fetch() wrapper around the real Flask backend.
   Replaces the old localStorage-backed SentinelStore (FR-DB-01..08 are now
   backed by an actual SQLite database, not the browser) and the old
   client-side heuristic classifier (FR-SE-05..08 are now a trained Random
   Forest model running server-side). Every call is same-origin, credentials
   included so the Flask session cookie is sent.
   ========================================================================== */
const SentinelAPI = (() => {

  async function request(path, opts = {}) {
    const res = await fetch(path, {
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      ...opts,
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
  const auditLog = (limit = 50) => request('/api/admin/audit-log?limit=' + limit);
  const resetDemoData = () => request('/api/admin/reset-demo-data', { method: 'POST' });

  // ---- live mailbox integration ----
  const mailboxStatus = () => request('/api/admin/mailbox-status');
  const mailboxTest = () => request('/api/admin/mailbox-test', { method: 'POST' });
  const mailboxSync = () => request('/api/admin/mailbox-sync', { method: 'POST', body: JSON.stringify({}) });

  // ---- public (no login) ----
  const demoScan = () => request('/api/public/demo-scan');
  const submitContact = (payload) => request('/api/contact', { method: 'POST', body: JSON.stringify(payload) });

  return {
    login, logout, me, register, forgotPassword, resetPassword, changePassword,
    scan, all, getScan, stats,
    submitFeedback, adminAction, modelInfo, retrain, retrainStatus, auditLog, resetDemoData, demoScan,
    mailboxStatus, mailboxTest, mailboxSync, submitContact,
  };
})();
