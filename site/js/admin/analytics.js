/* Admin Analytics — derived entirely from real /api/admin/detections rows
   and /api/admin/model-info. No fabricated numbers, no external chart
   library: simple CSS bars/rows, same approach as the Overview panels. */
(function () {
  'use strict';
  const { esc } = window.SentinelUI;
  const A = window.AdminUI;
  const root = document.getElementById('analyticsRoot');
  let allRows = [];
  let rangeDays = 1;

  function withinRange(row) {
    if (rangeDays === 0) return true;
    const ts = new Date(row.scan_timestamp);
    if (isNaN(ts)) return false;
    const cutoff = Date.now() - rangeDays * 86400000;
    return ts.getTime() >= cutoff;
  }

  function groupBy(rows, keyFn) {
    const m = new Map();
    rows.forEach((r) => {
      const k = keyFn(r);
      m.set(k, (m.get(k) || 0) + 1);
    });
    return m;
  }

  function distRows(map, colorFn) {
    const total = Array.from(map.values()).reduce((a, b) => a + b, 0) || 1;
    return Array.from(map.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([label, n]) => {
        const w = Math.round((n / total) * 100);
        return '<div class="dist-row"><span class="muted">' + esc(label) + '</span>' +
          '<span class="dist-track"><span class="dist-fill" style="width:' + w + '%;background:' + colorFn(label) + '"></span></span>' +
          '<span class="mono" style="text-align:right">' + n + '</span></div>';
      }).join('');
  }

  function dayBars(rows) {
    const days = [];
    const now = new Date();
    const span = rangeDays === 0 ? 14 : Math.min(rangeDays, 14);
    for (let i = span - 1; i >= 0; i--) {
      const d = new Date(now); d.setDate(d.getDate() - i); d.setHours(0, 0, 0, 0);
      days.push(d);
    }
    const counts = days.map((d) => {
      const next = new Date(d); next.setDate(next.getDate() + 1);
      return rows.filter((r) => { const t = new Date(r.scan_timestamp); return t >= d && t < next; }).length;
    });
    const max = Math.max(...counts, 1);
    return '<div class="row" style="align-items:flex-end;gap:6px;height:140px;padding-top:10px">' +
      counts.map((c, i) => {
        const h = Math.round((c / max) * 120) + 4;
        return '<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px">' +
          '<div style="width:100%;max-width:22px;height:' + h + 'px;background:var(--cyan);border-radius:3px 3px 0 0;opacity:.85"></div>' +
          '<span class="mono" style="font-size:9px;color:var(--text-muted)">' + (days[i].getMonth() + 1) + '/' + days[i].getDate() + '</span></div>';
      }).join('') + '</div>';
  }

  function verdictColor(v) { return v === 'Phishing' ? 'var(--red)' : v === 'Needs Review' ? 'var(--amber)' : v === 'Legitimate' ? 'var(--green)' : 'var(--text-muted)'; }
  function neutralColor() { return 'var(--cyan)'; }

  function senderDomain(from) {
    const m = (from || '').match(/@([\w.\-]+)/);
    return m ? m[1] : 'unknown';
  }

  async function render() {
    const rows = allRows.filter(withinRange);
    // Only gmail/mailbox sources ever have a real mailbox quarantine action --
    // Quick Analysis/.eml uploads get the same status string from their
    // classification label alone, with nothing actually moved. Mirrors the
    // same source filter as /api/stats's quarantined count (app.py).
    const quarantined = rows.filter((r) => r.status === 'Quarantined' && (r.source === 'gmail' || r.source === 'mailbox')).length;
    const released = rows.filter((r) => (r.notes || '').startsWith('Released by admin')).length;
    const reported = rows.filter((r) => r.source === 'upload').length;
    const automatic = rows.length - reported;

    let modelHtml = '<div class="muted" style="font-size:.85rem">Could not load model info.</div>';
    try {
      const info = await SentinelAPI.modelInfo();
      modelHtml = '<div class="kv" style="grid-template-columns:140px 1fr">' +
        '<dt>Active version</dt><dd class="mono">' + esc(info.current.version) + '</dd>' +
        '<dt>Accuracy</dt><dd>' + Math.round((info.current.metrics?.accuracy || 0) * 100) + '%</dd>' +
        '<dt>Versions tracked</dt><dd>' + (info.versions || []).length + '</dd></div>';
    } catch (e) { /* leave fallback */ }

    root.innerHTML =
      '<div class="stack">' +
        '<section class="panel"><div class="panel-head"><h3>Detections over time</h3></div><div class="panel-body">' +
          (rows.length ? dayBars(rows) : '<div class="muted" style="font-size:.85rem">No detections in this range.</div>') + '</div></section>' +
        '<section class="panel"><div class="panel-head"><h3>Verdict distribution</h3></div><div class="panel-body">' +
          (rows.length ? distRows(groupBy(rows, (r) => r.classification || 'Unknown'), verdictColor) : '<div class="muted" style="font-size:.85rem">No data.</div>') + '</div></section>' +
        '<section class="panel"><div class="panel-head"><h3>Sender domains</h3></div><div class="panel-body">' +
          (rows.length ? distRows(groupBy(rows, (r) => senderDomain(r.from)), neutralColor) : '<div class="muted" style="font-size:.85rem">No data.</div>') + '</div></section>' +
      '</div>' +
      '<div class="stack">' +
        '<div class="metric-grid" style="grid-template-columns:1fr 1fr">' +
          '<div class="metric is-brand"><div class="metric-label">Total</div><div class="metric-value">' + rows.length + '</div></div>' +
          '<div class="metric is-threat"><div class="metric-label">Quarantined</div><div class="metric-value">' + quarantined + '</div></div>' +
          '<div class="metric is-safe"><div class="metric-label">Released</div><div class="metric-value">' + released + '</div></div>' +
          '<div class="metric is-review"><div class="metric-label">Reported (.eml)</div><div class="metric-value">' + reported + '</div></div>' +
        '</div>' +
        '<section class="panel"><div class="panel-head"><h3>Source distribution</h3></div><div class="panel-body">' +
          (rows.length ? distRows(groupBy(rows, (r) => A.sourceLabel(r.source)), neutralColor) : '<div class="muted" style="font-size:.85rem">No data.</div>') + '</div></section>' +
        '<section class="panel"><div class="panel-head"><h3>Reported vs. automatic</h3></div><div class="panel-body">' +
          distRows(new Map([['Automatic', automatic], ['Reported (.eml)', reported]]), neutralColor) + '</div></section>' +
        '<section class="panel"><div class="panel-head"><h3>Model</h3></div><div class="panel-body">' + modelHtml + '</div></section>' +
      '</div>';
  }

  document.querySelectorAll('[data-range]').forEach((chip) => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('[data-range]').forEach((c) => c.classList.remove('active'));
      chip.classList.add('active');
      rangeDays = parseInt(chip.getAttribute('data-range'), 10);
      render();
    });
  });

  async function load() {
    try {
      allRows = await SentinelAPI.detectionList({ limit: 500 });
      render();
    } catch (e) {
      window.SentinelUI.setState(root, 'error', { title: 'Could not load analytics', msg: e.message });
    }
  }
  load();
})();
