/* ==========================================================================
   Reset-password form. Reads the token from the query string (the link
   emailed by /api/auth/forgot-password points here as
   reset-password.html?token=...). If there's no token at all, the form
   is pointless -- show an error instead of letting it submit.
   ========================================================================== */
(() => {
  const form = document.getElementById('resetForm');
  const errMsg = document.getElementById('errMsg');
  const successMsg = document.getElementById('successMsg');
  const btn = document.getElementById('resetBtn');

  const token = new URLSearchParams(window.location.search).get('token');
  if (!token) {
    form.style.display = 'none';
    errMsg.textContent = 'This reset link is missing its token -- request a new one from the forgot password page.';
    errMsg.classList.add('show');
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errMsg.classList.remove('show');
    btn.setAttribute('disabled', 'disabled');
    btn.textContent = 'Resetting…';
    try {
      await SentinelAPI.resetPassword(token, document.getElementById('password').value);
      form.style.display = 'none';
      successMsg.textContent = 'Password reset -- you can now log in with your new password.';
      successMsg.classList.add('show');
      setTimeout(() => { window.location.href = '/login.html'; }, 1800);
    } catch (err) {
      errMsg.textContent = err.message || 'This reset link is invalid or has expired.';
      errMsg.classList.add('show');
      btn.removeAttribute('disabled');
      btn.textContent = 'Reset password';
    }
  });
})();
