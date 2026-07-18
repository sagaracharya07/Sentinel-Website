/* Admin Incident Detail — full investigation view from
   /api/admin/detections/<id> (+ /related, + /api/admin/action, /api/feedback). */
(function () {
  'use strict';
  const { esc, toast, relTime, absTime, setState } = window.SentinelUI;
  const A = window.AdminUI;

  const root = document.getElementById('incRoot');
  const scanId = root.getAttribute('data-scan-id');

  function group(findings, cat) { return (findings || []).filter((f) => (A.normFinding(f).category) === cat); }
  function findingsHtml(list, emptyMsg) {
    if (!list.length) return '<div class="muted" style="font-size:.85rem">' + esc(emptyMsg) + '</div>';
    return list.map(A.findingHtml).join('');
  }

  function gaugeVars(classification, prob) {
    const p = Math.round((prob || 0) * 100);
    const g = classification === 'Phishing' ? 'var(--red)' : classification === 'Needs Review' ? 'var(--amber)' : 'var(--green)';
    return '--p:' + p + ';--g:' + g;
  }

  function render(d) {
    const findings = d.findings || [];
    const sender = group(findings, 'sender');
    const auth = group(findings, 'authentication');
    const links = group(findings, 'link');
    const attach = group(findings, 'attachment');
    const content = group(findings, 'content');

    const preview = d.body_purged
      ? '<div class="callout warn"><svg class="icon" aria-hidden="true"><use href="#i-alert"></use></svg><div>The message body was purged under the data-retention policy. Classification metadata is retained.</div></div>'
      : '<div class="preview">' + esc(d.body || '(no body captured)') + '</div>';

    root.innerHTML =
      // header
      '<div class="card" style="margin-bottom:var(--sp-4)"><div class="inc-header">' +
        '<div class="inc-gauge" style="' + gaugeVars(d.classification, d.phishing_probability) + '"><span class="g-val">' + A.pct(d.phishing_probability) + '</span></div>' +
        '<div><div class="row-wrap" style="margin-bottom:8px">' + A.verdictBadge(d.classification) + A.riskBadge(d.risk_level) +
          '<span class="badge badge-muted mono">' + esc(d.scan_id) + '</span></div>' +
          '<div class="inc-meta">' +
            '<div><span>Received</span>' + esc(absTime(d.scan_timestamp)) + '</div>' +
            '<div><span>Mailbox action</span>' + esc(d.mailbox_action || 'none') + '</div>' +
            '<div><span>Prediction confidence</span>' + A.pct(d.prediction_confidence) + '</div>' +
            '<div><span>Source</span>' + esc(A.sourceLabel(d.source)) + '</div>' +
          '</div></div>' +
      '</div></div>' +

      // actions
      '<div class="inc-actions">' +
        '<button class="btn btn-danger btn-sm" data-act="confirm">Confirm Phishing</button>' +
        '<button class="btn btn-success btn-sm" data-act="release">Release to Inbox</button>' +
        '<button class="btn btn-ghost btn-sm" data-act="legit">Mark Legitimate</button>' +
        '<button class="btn btn-ghost btn-sm" data-act="related">Find Related (' + (d.related_count || 0) + ')</button>' +
      '</div>' +
      (d.mailbox_action_error ? '<div class="callout warn" style="margin-bottom:var(--sp-4)"><svg class="icon" aria-hidden="true"><use href="#i-alert"></use></svg><div>' + esc(d.mailbox_action_error) + '</div></div>' : '') +

      // columns
      '<div class="grid-2col">' +
        '<div>' +
          '<section class="card sec"><h3><svg class="icon" aria-hidden="true"><use href="#i-mail"></use></svg> Safe email preview</h3>' +
            '<div class="kv" style="margin-bottom:var(--sp-3)">' +
              '<dt>Subject</dt><dd>' + esc(d.subject || '(no subject)') + '</dd>' +
              '<dt>From</dt><dd>' + esc(d.from || '—') + '</dd></div>' + preview + '</section>' +
          '<section class="card sec"><h3>Sender identity</h3>' + findingsHtml(sender, 'No sender anomalies detected.') + '</section>' +
          '<section class="card sec"><h3>Authentication</h3>' + findingsHtml(auth, 'No authentication findings (SPF/DKIM/DMARC not present or all passed).') + '</section>' +
        '</div>' +
        '<div>' +
          '<section class="card sec"><h3><svg class="icon" aria-hidden="true"><use href="#i-pulse"></use></svg> AI analysis</h3>' +
            '<div class="kv" style="margin-bottom:var(--sp-3)">' +
              '<dt>Model verdict</dt><dd>' + esc(d.classification) + '</dd>' +
              '<dt>Model version</dt><dd class="mono">' + esc(d.model_version || '—') + '</dd>' +
              '<dt>Phishing prob.</dt><dd>' + A.pct(d.phishing_probability) + '</dd>' +
              '<dt>Confidence</dt><dd>' + A.pct(d.prediction_confidence) + '</dd></div>' +
              findingsHtml(content, 'No additional content signals.') + '</section>' +
          '<section class="card sec"><h3>Links</h3>' + findingsHtml(links, 'No suspicious links detected.') + '</section>' +
          '<section class="card sec"><h3>Attachments</h3>' + findingsHtml(attach, 'No attachment findings.') + '</section>' +
          '<section class="card sec" id="relatedSec"><h3>Related detections</h3><div class="muted" style="font-size:.85rem">' +
            (d.related_count ? d.related_count + ' related message(s). Use “Find Related”.' : 'No related messages found.') + '</div></section>' +
          '<section class="card sec"><h3>Event timeline</h3>' + timelineHtml(d.timeline) + '</section>' +
        '</div>' +
      '</div>';

    wireActions(d);
  }

  function timelineHtml(events) {
    if (!events || !events.length) return '<div class="muted" style="font-size:.85rem">No recorded events.</div>';
    return events.map((e) =>
      '<div class="row" style="justify-content:space-between;padding:7px 0;border-bottom:1px solid var(--border)">' +
      '<span><span class="mono" style="font-size:.82rem">' + esc(e.action) + '</span> <span class="muted" style="font-size:.8rem">' + esc(e.actor) + '</span></span>' +
      '<span class="muted mono" style="font-size:.75rem">' + esc(relTime(e.timestamp)) + '</span></div>'
    ).join('');
  }

  function wireActions(d) {
    root.querySelectorAll('[data-act]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const act = btn.getAttribute('data-act');
        btn.disabled = true;
        try {
          if (act === 'confirm') { await SentinelAPI.adminAction(scanId, 'confirm'); toast('Confirmed as phishing', 'ok'); reload(); }
          else if (act === 'release') { await SentinelAPI.adminAction(scanId, 'release'); toast('Released to inbox', 'ok'); reload(); }
          else if (act === 'legit') { await SentinelAPI.submitFeedback(scanId, 'Legitimate'); toast('Marked legitimate', 'ok'); reload(); }
          else if (act === 'related') { await showRelated(); }
        } catch (err) {
          toast('Action failed: ' + err.message, 'err');
        } finally { btn.disabled = false; }
      });
    });
  }

  async function showRelated() {
    const sec = document.getElementById('relatedSec');
    sec.innerHTML = '<h3>Related detections</h3><div class="state"><span class="spinner" aria-hidden="true"></span></div>';
    try {
      const res = await SentinelAPI.relatedMessages(scanId);
      if (!res.count) { sec.innerHTML = '<h3>Related detections</h3><div class="muted" style="font-size:.85rem">No related messages found.</div>'; return; }
      sec.innerHTML = '<h3>Related detections (' + res.count + ')</h3>' + res.related.map((r) =>
        '<a href="/admin/detections/' + encodeURIComponent(r.scan_id) + '" class="row" style="justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border)">' +
        '<span>' + esc(r.subject || '(no subject)') + '<br><span class="muted" style="font-size:.78rem">' + esc(r.from) + '</span></span>' +
        A.verdictBadge(r.classification) + '</a>'
      ).join('');
    } catch (err) { toast('Could not load related: ' + err.message, 'err'); }
  }

  async function reload() {
    try {
      render(await SentinelAPI.incidentDetail(scanId));
      A.refreshSidebarCounts();
    } catch (e) {
      setState(root, 'error', { title: 'Could not load incident', msg: e.message });
    }
  }

  reload();
})();
