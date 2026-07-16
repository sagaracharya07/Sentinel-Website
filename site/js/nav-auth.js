/* ==========================================================================
   Populates the marketing-page nav's #userBadge when a visitor happens to
   be logged in while browsing public pages. base_marketing.html only
   renders the #userBadge element server-side when the session already
   has a username (see the `{% if session.get('username') %}` check), so
   this never needs to redirect on failure the way auth-guard.js's
   requireLogin() does for protected pages -- it's just cosmetic here.
   ========================================================================== */
(() => {
  const mount = document.getElementById('userBadge');
  if (!mount) return; // logged out -- server already rendered Log in/Sign up instead
  SentinelAPI.me()
    .then(user => SentinelAuth.renderUserBadge(user, 'userBadge'))
    .catch(() => { /* session expired between render and this fetch -- leave nav as-is */ });
})();
