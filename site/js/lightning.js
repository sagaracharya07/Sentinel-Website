/* ==========================================================================
   Boot-sequence lightning flash — plays once when the page loads,
   simulating power surging through the system before it comes online.
   Respects prefers-reduced-motion (falls back to a single soft flash).
   ========================================================================== */
(() => {
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const canvas = document.createElement('canvas');
  canvas.setAttribute('aria-hidden', 'true');
  Object.assign(canvas.style, {
    position: 'fixed', inset: '0', width: '100vw', height: '100vh',
    zIndex: '9999', pointerEvents: 'none', mixBlendMode: 'screen'
  });
  document.body.appendChild(canvas);
  const ctx = canvas.getContext('2d');

  function resize(){
    canvas.width = window.innerWidth * devicePixelRatio;
    canvas.height = window.innerHeight * devicePixelRatio;
    ctx.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
  }
  resize();
  window.addEventListener('resize', resize);

  function boltPath(x0, y0, x1, y1, displace){
    if(displace < 6){ return [[x0,y0],[x1,y1]]; }
    const mx = (x0+x1)/2 + (Math.random()-0.5)*displace;
    const my = (y0+y1)/2 + (Math.random()-0.5)*displace*0.5;
    return [
      ...boltPath(x0,y0,mx,my,displace/2),
      ...boltPath(mx,my,x1,y1,displace/2).slice(1)
    ];
  }

  function drawBolt(points, color, width, glow){
    ctx.save();
    ctx.strokeStyle = color;
    ctx.lineWidth = width;
    ctx.shadowBlur = glow;
    ctx.shadowColor = color;
    ctx.lineJoin = 'round';
    ctx.beginPath();
    ctx.moveTo(points[0][0], points[0][1]);
    for(let i=1;i<points.length;i++) ctx.lineTo(points[i][0], points[i][1]);
    ctx.stroke();
    ctx.restore();
  }

  function branchFrom(points, chance){
    points.forEach((pt, i) => {
      if(Math.random() < chance && i > 2 && i < points.length - 3){
        const len = 40 + Math.random()*80;
        const angle = (Math.random()-0.5) * 1.4 + Math.PI/2.2;
        const ex = pt[0] + Math.cos(angle)*len;
        const ey = pt[1] + Math.sin(angle)*len;
        drawBolt(boltPath(pt[0], pt[1], ex, ey, 30), 'rgba(139,124,255,.55)', 1, 8);
      }
    });
  }

  const w = window.innerWidth, h = window.innerHeight;
  const bolts = [];
  const boltCount = reduced ? 1 : (3 + Math.floor(Math.random()*2));
  for(let i=0;i<boltCount;i++){
    const x0 = Math.random()*w;
    const x1 = x0 + (Math.random()-0.5)*w*0.5;
    bolts.push(boltPath(x0, -10, Math.max(0,Math.min(w,x1)), h*(0.35+Math.random()*0.5), 90));
  }

  let frame = 0;
  const totalFrames = reduced ? 10 : 46;
  function drawBoltFrame(bolts, t, totalStrikes){
    ctx.clearRect(0,0,canvas.width, canvas.height);
    let intensity = 0;
    totalStrikes.forEach(s => {
      const d = Math.max(0, t - s);
      intensity = Math.max(intensity, Math.exp(-d*22));
    });
    if(intensity > 0.02){
      ctx.fillStyle = `rgba(58,168,255,${(intensity*0.06).toFixed(3)})`;
      ctx.fillRect(0,0,canvas.width,canvas.height);
      bolts.forEach(pts => {
        drawBolt(pts, `rgba(180,225,255,${Math.min(1,intensity*1.1).toFixed(3)})`, 2.2, 22*intensity);
        drawBolt(pts, `rgba(58,168,255,${Math.min(1,intensity).toFixed(3)})`, 1, 10*intensity);
        if(!reduced) branchFrom(pts, 0.10 * intensity);
      });
    }
    return intensity;
  }

  function tick(){
    frame++;
    const t = frame / totalFrames;
    drawBoltFrame(bolts, t, [0, 0.08, 0.22, 0.5]);
    if(frame < totalFrames){
      requestAnimationFrame(tick);
    } else {
      ctx.clearRect(0,0,canvas.width,canvas.height);
      if(!reduced) scheduleAmbient();
    }
  }
  requestAnimationFrame(tick);

  // ---- recurring low-intensity ambient strikes, forever, while the page is open ----
  function scheduleAmbient(){
    const delay = 5000 + Math.random()*6000;
    setTimeout(() => {
      if(document.hidden){ scheduleAmbient(); return; }
      const w = window.innerWidth, h = window.innerHeight;
      const x0 = Math.random()*w;
      const x1 = x0 + (Math.random()-0.5)*w*0.35;
      const bolt = [boltPath(x0, -10, Math.max(0,Math.min(w,x1)), h*(0.2+Math.random()*0.5), 60)];
      let f = 0;
      const total = 22;
      function ambientTick(){
        f++;
        drawBoltFrame(bolt, f/total, [0, 0.18]);
        if(f < total){ requestAnimationFrame(ambientTick); }
        else { ctx.clearRect(0,0,canvas.width,canvas.height); scheduleAmbient(); }
      }
      requestAnimationFrame(ambientTick);
    }, delay);
  }
})();
