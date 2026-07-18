/* Admin Audit Log — /api/admin/audit-log, client-side search over the
   fetched batch (the API itself only supports `limit`). */
(function () {
  'use strict';
  const { esc, absTime, setState } = window.SentinelUI;
  const body = document.getElementById('listBody');
  const countEl = document.getElementById('resultCount');
  const search = document.getElementById('qSearch');
  let all = [];

  function render(rows) {
    countEl.textContent = rows.length + (rows.length === 1 ? ' entry' : ' entries');
    if (!rows.length) {
      setState(body, 'empty', { title: 'No matching entries' });
      return;
    }
    body.innerHTML = '<div class="table-wrap"><table class="data cards-on-mobile"><thead><tr>' +
      '<th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th></tr></thead><tbody>' +
      rows.map((r) =>
        '<tr>' +
        '<td data-label="Time" class="muted mono" style="font-size:.78rem">' + esc(absTime(r.timestamp)) + '</td>' +
        '<td data-label="Actor">' + esc(r.actor) + '</td>' +
        '<td data-label="Action" class="mono" style="font-size:.85rem">' + esc(r.action) + '</td>' +
        '<td data-label="Target" class="mono" style="font-size:.82rem">' + esc(r.target || '—') + '</td>' +
        '<td data-label="Details" class="muted" style="font-size:.82rem;max-width:320px">' + esc(r.details || '') + '</td></tr>'
      ).join('') + '</tbody></table></div>';
  }

  function apply() {
    const q = search.value.trim().toLowerCase();
    if (!q) { render(all); return; }
    render(all.filter((r) =>
      (r.actor || '').toLowerCase().includes(q) ||
      (r.action || '').toLowerCase().includes(q) ||
      (r.target || '').toLowerCase().includes(q)
    ));
  }
  let timer;
  search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(apply, 220); });

  async function load() {
    setState(body, 'loading');
    try { all = await SentinelAPI.auditLog(300); apply(); }
    catch (e) { setState(body, 'error', { title: 'Could not load audit log', msg: e.message }); }
  }
  load();
})();
