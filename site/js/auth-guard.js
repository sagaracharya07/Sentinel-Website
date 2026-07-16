/* ==========================================================================
   Auth guard for protected pages (scan.html, admin.html).
   Real server-side authorisation already happens on every API call
   (401/403 from Flask) -- this just gives a fast, friendly client-side
   redirect instead of a page full of failed fetches, and renders the
   logged-in user's name + a logout control in the nav.
   ========================================================================== */
const SentinelAuth = (() => {

  async function requireLogin({ requireAdmin = false } = {}) {
    try {
      const user = await SentinelAPI.me();
      if (requireAdmin && user.role !== 'admin') {
        window.location.href = 'scan.html';
        return null;
      }
      return user;
    } catch (e) {
      const next = encodeURIComponent(window.location.pathname.split('/').pop() || 'scan.html');
      window.location.href = `login.html?next=${next}`;
      return null;
    }
  }

  function renderUserBadge(user, mountId = 'userBadge') {
    const el = document.getElementById(mountId);
    if (!el || !user) return;
    el.innerHTML = `
      <span class="user-chip">
        <span class="user-dot"></span>${SentinelAPI ? '' : ''}${escapeHtml(user.username)}
        <span class="role-tag">${escapeHtml(user.role)}</span>
      </span>
      <button class="btn btn-ghost btn-sm" id="logoutBtn" type="button">Log out</button>
    `;
    document.getElementById('logoutBtn').addEventListener('click', async () => {
      try { await SentinelAPI.logout(); } catch (e) { /* ignore */ }
      window.location.href = 'login.html';
    });
  }

  function escapeHtml(str) {
    return (str || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  return { requireLogin, renderUserBadge };
})();
