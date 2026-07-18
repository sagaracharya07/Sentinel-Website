/* ==========================================================================
   SentinelUI — shared front-end helpers for every authenticated & public page.
   Vanilla, dependency-free, CSP-clean (no inline handlers, no eval).
   Exposes window.SentinelUI. Loaded on every page via the base templates.
   ========================================================================== */
(function () {
  'use strict';

  /* ---- escaping: the single safe way to put text into the DOM ----------- */
  function esc(value) {
    const s = value == null ? '' : String(value);
    return s.replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }

  /* ---- toast notifications ---------------------------------------------- */
  function toast(message, kind = 'ok', ms = 3200) {
    let region = document.getElementById('toast-region');
    if (!region) {
      region = document.createElement('div');
      region.id = 'toast-region';
      region.setAttribute('aria-live', 'polite');
      document.body.appendChild(region);
    }
    const el = document.createElement('div');
    el.className = 'toast ' + (kind === 'err' ? 'err' : kind === 'ok' ? 'ok' : '');
    el.setAttribute('role', 'status');
    el.innerHTML = '<span class="dot"></span><span></span>';
    el.querySelector('span:last-child').textContent = message;
    region.appendChild(el);
    requestAnimationFrame(() => el.classList.add('show'));
    setTimeout(() => {
      el.classList.remove('show');
      setTimeout(() => el.remove(), 300);
    }, ms);
  }

  /* ---- relative + absolute time ----------------------------------------- */
  function relTime(iso) {
    if (!iso) return '—';
    const then = new Date(iso);
    if (isNaN(then)) return '—';
    const secs = Math.round((Date.now() - then.getTime()) / 1000);
    if (secs < 45) return 'just now';
    const mins = Math.round(secs / 60);
    if (mins < 60) return mins + 'm ago';
    const hrs = Math.round(mins / 60);
    if (hrs < 24) return hrs + 'h ago';
    const days = Math.round(hrs / 24);
    if (days < 30) return days + 'd ago';
    return then.toLocaleDateString();
  }
  function absTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return isNaN(d) ? '—' : d.toLocaleString();
  }

  /* ---- fetch-state helpers (loading / empty / error) -------------------- */
  function setState(container, type, opts = {}) {
    if (!container) return;
    const icons = { loading: '', empty: '○', error: '!' };
    if (type === 'loading') {
      container.innerHTML =
        '<div class="state"><span class="spinner" aria-hidden="true"></span>' +
        '<div class="state-msg">' + esc(opts.msg || 'Loading…') + '</div></div>';
    } else if (type === 'empty') {
      container.innerHTML =
        '<div class="state"><div class="state-title">' + esc(opts.title || 'Nothing here yet') +
        '</div><div class="state-msg">' + esc(opts.msg || '') + '</div></div>';
    } else if (type === 'error') {
      container.innerHTML =
        '<div class="state state-error"><div class="state-title">' + esc(opts.title || 'Something went wrong') +
        '</div><div class="state-msg">' + esc(opts.msg || 'Please try again.') + '</div></div>';
    }
  }

  /* ---- overlay open/close (drawer, sidebar) with focus handling --------- */
  let lastFocused = null;
  function openOverlay(el, backdrop) {
    if (!el) return;
    lastFocused = document.activeElement;
    el.classList.add('show');
    if (backdrop) backdrop.classList.add('show');
    el.setAttribute('aria-hidden', 'false');
    const focusable = el.querySelector('a, button, input, [tabindex]');
    if (focusable) focusable.focus();
    document.addEventListener('keydown', escClose);
    function escClose(e) {
      if (e.key === 'Escape') { closeOverlay(el, backdrop); document.removeEventListener('keydown', escClose); }
    }
  }
  function closeOverlay(el, backdrop) {
    if (!el) return;
    el.classList.remove('show');
    if (backdrop) backdrop.classList.remove('show');
    el.setAttribute('aria-hidden', 'true');
    if (lastFocused && lastFocused.focus) lastFocused.focus();
  }

  /* ---- wire declarative toggles: [data-toggle="#id"] -------------------- */
  function wireToggles() {
    document.querySelectorAll('[data-toggle]').forEach((btn) => {
      const target = document.querySelector(btn.getAttribute('data-toggle'));
      const backdrop = btn.getAttribute('data-backdrop')
        ? document.querySelector(btn.getAttribute('data-backdrop')) : null;
      btn.addEventListener('click', () => {
        const open = target && target.classList.contains('show');
        if (open) closeOverlay(target, backdrop); else openOverlay(target, backdrop);
      });
    });
    document.querySelectorAll('[data-close]').forEach((btn) => {
      const target = document.querySelector(btn.getAttribute('data-close'));
      const backdrop = btn.getAttribute('data-backdrop')
        ? document.querySelector(btn.getAttribute('data-backdrop')) : null;
      btn.addEventListener('click', () => closeOverlay(target, backdrop));
    });
  }

  /* ---- motion preference (Preferences page can set localStorage) -------- */
  function initMotionPreference() {
    try {
      if (localStorage.getItem('sentinel:motion') === 'reduced') {
        document.documentElement.setAttribute('data-motion', 'reduced');
      }
    } catch (e) { /* storage may be blocked; ignore */ }
  }

  /* ---- user badge + sign-out (authenticated shells) --------------------- */
  async function mountUserBadge() {
    const el = document.getElementById('userBadge');
    if (!el) return;
    try {
      const res = await fetch('/api/auth/me', { credentials: 'same-origin' });
      if (!res.ok) return;
      const u = await res.json();
      const initial = (u.username || '?').charAt(0).toUpperCase();
      el.innerHTML =
        '<span class="avatar" aria-hidden="true">' + esc(initial) + '</span>' +
        '<span><span class="u-name">' + esc(u.username) + '</span> ' +
        '<span class="u-role">' + esc(u.role) + '</span></span>';
    } catch (e) { /* offline; leave empty */ }
  }
  function wireSignOut() {
    document.querySelectorAll('[data-signout]').forEach((btn) => {
      btn.addEventListener('click', async (e) => {
        e.preventDefault();
        try {
          const t = await (await fetch('/api/csrf-token', { credentials: 'same-origin' })).json();
          await fetch('/api/auth/logout', {
            method: 'POST', credentials: 'same-origin',
            headers: { 'X-CSRFToken': t.csrf_token },
          });
        } catch (err) { /* proceed to login anyway */ }
        window.location.href = '/login';
      });
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    initMotionPreference();
    wireToggles();
    mountUserBadge();
    wireSignOut();
  });

  window.SentinelUI = {
    esc, toast, relTime, absTime, setState, openOverlay, closeOverlay, mountUserBadge,
  };
})();
