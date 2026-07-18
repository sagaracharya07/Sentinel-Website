/* ==========================================================================
   reveal.js — lightweight scroll-reveal for public marketing sections.
   IntersectionObserver based, dependency-free, CSP-clean. Honours reduced
   motion: if the user prefers reduced motion (OS setting or the app's
   data-motion="reduced" flag), everything is shown immediately with no
   transform/opacity animation.
   ========================================================================== */
(function () {
  'use strict';

  function prefersReduced() {
    if (document.documentElement.getAttribute('data-motion') === 'reduced') return true;
    return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  document.addEventListener('DOMContentLoaded', () => {
    const items = Array.from(document.querySelectorAll('.reveal'));
    if (!items.length) return;

    if (prefersReduced() || !('IntersectionObserver' in window)) {
      items.forEach((el) => el.classList.add('in'));
      return;
    }

    const io = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const el = entry.target;
          const delay = el.getAttribute('data-reveal-delay');
          if (delay) el.style.transitionDelay = delay + 'ms';
          el.classList.add('in');
          io.unobserve(el);
        }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -8% 0px' });

    items.forEach((el) => io.observe(el));
  });
})();
