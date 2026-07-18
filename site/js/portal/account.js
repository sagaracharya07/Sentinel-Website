/* Account — profile details + change password. Server-side route already
   enforces login (routes/pages.py); this only needs /api/auth/me for display. */
(function () {
  'use strict';
  const { esc } = window.SentinelUI;

  async function loadProfile() {
    try {
      const user = await SentinelAPI.me();
      document.getElementById('acctUsername').textContent = user.username;
      document.getElementById('acctRole').textContent = user.role;
      document.getElementById('acctEmail').textContent = user.email || '(none — demo account)';
      document.getElementById('acctVerified').textContent = user.email ? (user.email_verified ? 'Yes' : 'No') : '—';
    } catch (e) { /* guarded server-side; shouldn't happen */ }
  }

  const form = document.getElementById('changePasswordForm');
  const errMsg = document.getElementById('errMsg');
  const successMsg = document.getElementById('successMsg');
  const btn = document.getElementById('changePasswordBtn');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errMsg.classList.remove('show');
    successMsg.style.display = 'none';
    btn.disabled = true;
    try {
      await SentinelAPI.changePassword(
        document.getElementById('currentPassword').value,
        document.getElementById('newPassword').value
      );
      form.reset();
      successMsg.style.display = 'flex';
    } catch (err) {
      errMsg.textContent = err.message || 'Could not update password';
      errMsg.classList.add('show');
    } finally {
      btn.disabled = false;
    }
  });

  loadProfile();
})();
