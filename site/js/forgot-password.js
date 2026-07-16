/* ==========================================================================
   Forgot-password form. The API always returns the same generic response
   regardless of whether the email exists (enumeration-safe -- see
   /api/auth/forgot-password in app.py), so this always shows the same
   success message too.
   ========================================================================== */
(() => {
  const form = document.getElementById('forgotForm');
  const errMsg = document.getElementById('errMsg');
  const successMsg = document.getElementById('successMsg');
  const btn = document.getElementById('forgotBtn');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errMsg.classList.remove('show');
    btn.setAttribute('disabled', 'disabled');
    btn.textContent = 'Sending…';
    try {
      const res = await SentinelAPI.forgotPassword(document.getElementById('email').value.trim());
      form.style.display = 'none';
      successMsg.textContent = res.message || 'If that email is registered, a reset link has been sent.';
      successMsg.classList.add('show');
    } catch (err) {
      errMsg.textContent = err.message || 'Something went wrong -- please try again.';
      errMsg.classList.add('show');
      btn.removeAttribute('disabled');
      btn.textContent = 'Send reset link';
    }
  });
})();
