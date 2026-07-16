(() => {
  function applyFrames(){
    document.querySelectorAll('.hud-frame').forEach(el => {
      if(el.dataset.hudDone) return;
      el.dataset.hudDone = '1';
      const pos = getComputedStyle(el).position;
      if(pos === 'static') el.style.position = 'relative';
      ['tl','tr','bl','br'].forEach(p => {
        const s = document.createElement('span');
        s.className = 'hud-corner hud-' + p;
        el.appendChild(s);
      });
    });
  }
  if(document.readyState === 'loading'){
    document.addEventListener('DOMContentLoaded', applyFrames);
  } else {
    applyFrames();
  }
  window.SentinelHUD = { applyFrames };
})();
