/* Settings -> Appearance. Client-side only (localStorage), same pattern as
   the user portal's Preferences page -- no backend model exists for
   per-admin appearance yet. */
(function () {
  'use strict';
  const motionSel = document.getElementById('apMotion');
  const densitySel = document.getElementById('apDensity');
  const saveBtn = document.getElementById('apSaveBtn');
  const saved = document.getElementById('apSaved');

  try {
    motionSel.value = localStorage.getItem('sentinel:motion') === 'reduced' ? 'reduced' : 'normal';
    densitySel.value = localStorage.getItem('sentinel:density') || 'comfortable';
  } catch (e) { /* defaults already selected */ }

  saveBtn.addEventListener('click', () => {
    try {
      localStorage.setItem('sentinel:motion', motionSel.value);
      localStorage.setItem('sentinel:density', densitySel.value);
      document.documentElement.setAttribute('data-motion', motionSel.value === 'reduced' ? 'reduced' : '');
      saved.style.display = 'flex';
      setTimeout(() => { saved.style.display = 'none'; }, 2500);
    } catch (e) {
      window.SentinelUI.toast('Could not save — storage may be disabled', 'err');
    }
  });
})();
