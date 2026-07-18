/* Preferences — client-side only (localStorage). No backend model exists for
   per-user preferences yet; per the frontend-direction plan this stays
   client-side rather than inventing a new database column for it. The
   reduced-motion choice is the one preference with an immediate visible
   effect, applied via documentElement's data-motion attribute (see
   foundation.css's reduced-motion override). */
(function () {
  'use strict';
  const KEY_MOTION = 'sentinel:motion';
  const KEY_LANDING = 'sentinel:landing';
  const KEY_PAGESIZE = 'sentinel:pagesize';

  const motionSel = document.getElementById('prefMotion');
  const landingSel = document.getElementById('prefLanding');
  const pageSizeSel = document.getElementById('prefPageSize');
  const saveBtn = document.getElementById('prefSaveBtn');
  const saved = document.getElementById('prefSaved');

  function load() {
    try {
      motionSel.value = localStorage.getItem(KEY_MOTION) === 'reduced' ? 'reduced' : 'normal';
      landingSel.value = localStorage.getItem(KEY_LANDING) || '/app';
      pageSizeSel.value = localStorage.getItem(KEY_PAGESIZE) || '25';
    } catch (e) { /* storage blocked; use defaults already in the <select> */ }
  }

  saveBtn.addEventListener('click', () => {
    try {
      localStorage.setItem(KEY_MOTION, motionSel.value);
      localStorage.setItem(KEY_LANDING, landingSel.value);
      localStorage.setItem(KEY_PAGESIZE, pageSizeSel.value);
      document.documentElement.setAttribute('data-motion', motionSel.value === 'reduced' ? 'reduced' : '');
      saved.style.display = 'flex';
      setTimeout(() => { saved.style.display = 'none'; }, 2500);
    } catch (e) {
      window.SentinelUI.toast('Could not save — storage may be disabled in this browser', 'err');
    }
  });

  load();
})();
