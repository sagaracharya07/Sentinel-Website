/* Admin Users & Roles — /api/admin/users (+ /role, /suspend, /activate).
   Every role change and suspension requires an inline confirm() -- the
   server independently refuses to touch the last remaining admin, so this
   confirm is a UX courtesy, not the actual safety guarantee. */
(function () {
  'use strict';
  const { esc, toast, relTime, setState } = window.SentinelUI;
  const body = document.getElementById('listBody');
  const countEl = document.getElementById('resultCount');
  const search = document.getElementById('qSearch');
  const roleFilter = document.getElementById('fRole');

  function roleLabel(r) { return r === 'admin' ? 'Security Administrator' : 'User / Employee'; }

  function render(rows) {
    countEl.textContent = rows.length + (rows.length === 1 ? ' user' : ' users');
    if (!rows.length) { setState(body, 'empty', { title: 'No users match' }); return; }
    body.innerHTML = '<div class="table-wrap"><table class="data cards-on-mobile"><thead><tr>' +
      '<th>User</th><th>Role</th><th>Status</th><th>Last login</th><th>Reports</th><th>Actions</th></tr></thead><tbody>' +
      rows.map((u) =>
        '<tr>' +
        '<td data-label="User">' + esc(u.username) + (u.email ? '<div class="muted mono" style="font-size:.75rem">' + esc(u.email) + '</div>' : '') + '</td>' +
        '<td data-label="Role">' + esc(roleLabel(u.role)) + '</td>' +
        '<td data-label="Status">' + (u.is_active ? '<span class="badge badge-legit">Active</span>' : '<span class="badge badge-phish">Suspended</span>') + '</td>' +
        '<td data-label="Last login" class="muted mono" style="font-size:.8rem">' + esc(relTime(u.last_login_at)) + '</td>' +
        '<td data-label="Reports" class="mono">' + u.report_count + '</td>' +
        '<td data-label="Actions"><div class="row" style="gap:6px;flex-wrap:wrap">' +
          (u.role === 'admin'
            ? '<button class="btn btn-sm btn-ghost" data-role="' + u.id + '" data-to="user">Make User</button>'
            : '<button class="btn btn-sm btn-ghost" data-role="' + u.id + '" data-to="admin">Make Admin</button>') +
          (u.is_active
            ? '<button class="btn btn-sm btn-danger" data-suspend="' + u.id + '">Suspend</button>'
            : '<button class="btn btn-sm btn-success" data-activate="' + u.id + '">Reactivate</button>') +
        '</div></td></tr>'
      ).join('') + '</tbody></table></div>';
    wire();
  }

  function wire() {
    body.querySelectorAll('[data-role]').forEach((b) => b.addEventListener('click', () => {
      const to = b.getAttribute('data-to');
      if (!confirm('Change this user\'s role to ' + roleLabel(to) + '?')) return;
      act(b, () => SentinelAPI.userChangeRole(b.getAttribute('data-role'), to), 'Role updated');
    }));
    body.querySelectorAll('[data-suspend]').forEach((b) => b.addEventListener('click', () => {
      if (!confirm('Suspend this account? They will be unable to sign in until reactivated.')) return;
      act(b, () => SentinelAPI.userSuspend(b.getAttribute('data-suspend')), 'Account suspended');
    }));
    body.querySelectorAll('[data-activate]').forEach((b) => b.addEventListener('click', () =>
      act(b, () => SentinelAPI.userActivate(b.getAttribute('data-activate')), 'Account reactivated')
    ));
  }

  async function act(btn, fn, okMsg) {
    btn.disabled = true;
    try { await fn(); toast(okMsg, 'ok'); load(); }
    catch (e) { toast(e.data?.error || e.message, 'err'); btn.disabled = false; }
  }

  async function load() {
    setState(body, 'loading');
    const params = {};
    if (roleFilter.value) params.role = roleFilter.value;
    if (search.value.trim()) params.search = search.value.trim();
    try {
      render(await SentinelAPI.usersList(params));
    } catch (e) { setState(body, 'error', { title: 'Could not load users', msg: e.message }); }
  }
  let timer;
  search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(load, 250); });
  roleFilter.addEventListener('change', load);
  load();
})();
