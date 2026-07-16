(() => {
  const changePasswordForm = document.getElementById('changePasswordForm');
  const errMsg = document.getElementById('errMsg');
  const successMsg = document.getElementById('successMsg');
  const btn = document.getElementById('changePasswordBtn');

  (async function init() {
    const user = await SentinelAuth.requireLogin();
    if (!user) return; // redirected
    SentinelAuth.renderUserBadge(user);

    document.getElementById('acctUsername').textContent = user.username;
    document.getElementById('acctRole').textContent = user.role;
    document.getElementById('acctEmail').textContent = user.email || '(none -- demo account)';
    document.getElementById('acctVerified').textContent = user.email
      ? (user.email_verified ? 'Yes' : 'No')
      : '—';
  })();

  changePasswordForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    errMsg.classList.remove('show');
    successMsg.classList.remove('show');
    btn.setAttribute('disabled', 'disabled');
    btn.textContent = 'Updating…';
    try {
      await SentinelAPI.changePassword(
        document.getElementById('currentPassword').value,
        document.getElementById('newPassword').value
      );
      changePasswordForm.reset();
      successMsg.textContent = 'Password updated.';
      successMsg.classList.add('show');
    } catch (err) {
      errMsg.textContent = err.message || 'Could not update password';
      errMsg.classList.add('show');
    } finally {
      btn.removeAttribute('disabled');
      btn.textContent = 'Update password';
    }
  });
})();
