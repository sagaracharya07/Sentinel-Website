/* ==========================================================================
   Contact form -- same async-submit pattern as the auth forms (disable
   button + loading text, show/hide #errMsg, try/catch around the
   SentinelAPI call) for consistency across the site's forms.
   ========================================================================== */
(() => {
  const form = document.getElementById('contactForm');
  const errMsg = document.getElementById('errMsg');
  const successMsg = document.getElementById('successMsg');
  const btn = document.getElementById('contactBtn');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errMsg.classList.remove('show');
    btn.setAttribute('disabled', 'disabled');
    btn.textContent = 'Sending…';
    try {
      await SentinelAPI.submitContact({
        name: document.getElementById('nameInput').value.trim(),
        email: document.getElementById('emailInput').value.trim(),
        subject: document.getElementById('subjectInput').value.trim(),
        message: document.getElementById('messageInput').value.trim(),
      });
      form.reset();
      form.style.display = 'none';
      successMsg.style.display = 'flex';
    } catch (err) {
      errMsg.textContent = err.message || 'Something went wrong -- please try again.';
      errMsg.classList.add('show');
      btn.removeAttribute('disabled');
      btn.textContent = 'Send message';
    }
  });
})();
