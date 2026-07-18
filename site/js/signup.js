/* ==========================================================================
   Sign-up form -- same async-submit pattern as login.js. On success, the
   account is created but unverified (see /api/auth/register in app.py),
   so this shows a "check your email" message rather than redirecting
   straight to login, which would just fail the verification gate.
   ========================================================================== */
(() => {
  const form = document.getElementById('signupForm');
  const errMsg = document.getElementById('errMsg');
  const successMsg = document.getElementById('successMsg');
  const successText = document.getElementById('successText');
  const btn = document.getElementById('signupBtn');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errMsg.classList.remove('show');
    btn.setAttribute('disabled', 'disabled');
    btn.textContent = 'Creating account…';
    try {
      const res = await SentinelAPI.register(
        document.getElementById('username').value.trim(),
        document.getElementById('email').value.trim(),
        document.getElementById('password').value
      );
      form.style.display = 'none';
      successText.textContent = res.message || 'Account created — check your email to verify before signing in.';
      successMsg.style.display = 'flex';
    } catch (err) {
      errMsg.textContent = err.message || 'Could not create account';
      errMsg.classList.add('show');
      btn.removeAttribute('disabled');
      btn.textContent = 'Create account';
    }
  });
})();
