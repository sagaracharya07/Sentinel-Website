/* Homepage — "Pause animation" control for the hero's long-running flow
   diagram (required for any ambient effect that loops indefinitely; see
   foundation.css's global reduced-motion override for the OS-level
   equivalent, which already stops this animation for users who prefer it). */
(function () {
  'use strict';
  const btn = document.getElementById('pauseAnimBtn');
  const flow = document.getElementById('flowAnim');
  if (!btn || !flow) return;

  let paused = false;
  btn.addEventListener('click', () => {
    paused = !paused;
    flow.classList.toggle('paused', paused);
    btn.textContent = paused ? 'Resume animation' : 'Pause animation';
    btn.setAttribute('aria-pressed', String(paused));
  });
})();
