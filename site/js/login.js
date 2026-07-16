/* ==========================================================================
   Login page behavior — extracted from an inline <script> block so the
   Content-Security-Policy can use a strict script-src 'self' with no
   'unsafe-inline' (see backend/app.py's set_security_headers).
   ========================================================================== */
(() => {
  const form = document.getElementById('loginForm');
  const errMsg = document.getElementById('errMsg');
  const loginBtn = document.getElementById('loginBtn');

  function paramsNext() {
    const p = new URLSearchParams(window.location.search);
    return p.get('next');
  }

  // If already logged in, skip straight to the right dashboard.
  SentinelAPI.me().then(user => {
    window.location.href = user.role === 'admin' ? 'admin.html' : 'scan.html';
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
      const next = paramsNext();
      if (next && next !== 'login.html') {
        window.location.href = next;
      } else {
        window.location.href = user.role === 'admin' ? 'admin.html' : 'scan.html';
      }
    } catch (err) {
      errMsg.textContent = err.message || 'Login failed';
      errMsg.classList.add('show');
      loginBtn.removeAttribute('disabled');
      loginBtn.textContent = 'Log in';
    }
  });
})();
