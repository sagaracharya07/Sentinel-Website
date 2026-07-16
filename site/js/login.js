/* ==========================================================================
   Login page behavior — extracted from an inline <script> block so the
   Content-Security-Policy can use a strict script-src 'self' with no
   'unsafe-inline' (see backend/app.py's set_security_headers).
   ========================================================================== */
(() => {
  const form = document.getElementById('loginForm');
  const errMsg = document.getElementById('errMsg');
  const successMsg = document.getElementById('successMsg');
  const loginBtn = document.getElementById('loginBtn');

  function params() {
    return new URLSearchParams(window.location.search);
  }

  // GET /verify-email/<token> (app.py) redirects back here with one of
  // these two query params -- surface the outcome instead of silently
  // dropping it.
  if (params().get('verified') === '1') {
    successMsg.textContent = 'Email verified — you can now log in.';
    successMsg.classList.add('show');
  } else if (params().get('verify_error') === '1') {
    errMsg.textContent = 'That verification link is invalid or has expired.';
    errMsg.classList.add('show');
  }

  // If already logged in, skip straight to the right dashboard.
  SentinelAPI.me().then(user => {
    window.location.href = user.role === 'admin' ? '/admin.html' : '/scan.html';
  }).catch(() => { /* not logged in — show the form */ });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errMsg.classList.remove('show');
    loginBtn.setAttribute('disabled', 'disabled');
    loginBtn.textContent = 'Signing in…';
    try {
      const user = await SentinelAPI.login(
        document.getElementById('username').value.trim(),
        document.getElementById('password').value
      );
      const next = params().get('next');
      if (next && next !== 'login.html' && next !== '/login.html') {
        window.location.href = next;
      } else {
        window.location.href = user.role === 'admin' ? '/admin.html' : '/scan.html';
      }
    } catch (err) {
      errMsg.textContent = err.message || 'Login failed';
      errMsg.classList.add('show');
      loginBtn.removeAttribute('disabled');
      loginBtn.textContent = 'Log in';
    }
  });
})();
