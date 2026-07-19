/* ==========================================================================
   AdminUI — shared helpers for the administrator console.
   Verdict/risk/status badges, finding normalisation, and the two pieces of
   chrome every admin page shows: sidebar queue counts + the top-bar
   protection pill. Depends on window.SentinelUI (ui.js) + SentinelAPI (api.js).
   ========================================================================== */
(function () {
  'use strict';
  const esc = window.SentinelUI.esc;

  /* verdict badge from a classification string */
  function verdictBadge(classification) {
    const map = {
      'Legitimate':   ['badge-legit', 'Legitimate'],
      'Needs Review': ['badge-review', 'Needs Review'],
      'Phishing':     ['badge-phish', 'Phishing'],
    };
    const [cls, label] = map[classification] || ['badge-muted', classification || 'Unknown'];
    return '<span class="badge ' + cls + '"><span class="dot"></span>' + esc(label) + '</span>';
  }

  function riskBadge(risk) {
    const cls = risk === 'High' ? 'risk-high' : risk === 'Medium' ? 'risk-medium' : 'risk-low';
    return '<span class="risk ' + cls + '">' + esc(risk || '—') + '</span>';
  }

  /* mailbox action / status label */
  function statusBadge(status) {
    const map = {
      'Quarantined': 'badge-phish',
      'Flagged': 'badge-review',
      'Delivered': 'badge-legit',
    };
    const cls = map[status] || 'badge-muted';
    return '<span class="badge ' + cls + '">' + esc(status || '—') + '</span>';
  }

  const SOURCE_LABEL = {
    gmail: 'Gmail', upload: '.eml Upload', mailbox: 'IMAP', manual: 'Quick Analysis',
  };
  function sourceLabel(s) { return SOURCE_LABEL[s] || s || '—'; }

  /* Operational status for a detection row. `status` (Quarantined/Flagged/
     Delivered) is only a real mailbox fact for gmail/mailbox sources -- Quick
     Analysis and .eml uploads get the same string from their classification
     label alone, with nothing ever actually moved anywhere, so showing
     "Quarantined" for them overstates what happened. */
  function operationalStatus(row) {
    if (row.source === 'gmail' || row.source === 'mailbox') return row.status || '—';
    return 'Analysed';
  }

  /* 0..1 float -> "87%" */
  function pct(x) {
    if (x === null || x === undefined || isNaN(x)) return '—';
    return Math.round(x * 100) + '%';
  }

  /* Normalise the two finding shapes into one.
       - security analysis (analysis.py): {category, indicator, severity, summary, evidence}
         — its `evidence` is ALREADY HTML-escaped server-side (analysis _safe()).
       - ML signals (features.py): {type, detail, weight, severity} — raw text. */
  function normFinding(f) {
    return {
      category: f.category || 'content',
      title: f.summary || f.type || f.indicator || 'Signal',
      severity: (f.severity || 'low').toLowerCase(),
    };
  }
  function findingHtml(f) {
    const n = normFinding(f);
    // title fields (summary/type/indicator) are raw -> escape here.
    let html = '<div class="finding"><span class="sev ' + esc(n.severity) + '"></span><div>';
    html += '<div class="f-title">' + esc(n.title) + '</div>';
    // evidence: analysis findings carry a pre-escaped `evidence`; ML findings a
    // raw `detail`. Escape only the raw one to avoid double-escaping.
    let evidenceHtml = '';
    if (f.evidence != null && f.evidence !== '') evidenceHtml = f.evidence; // already escaped
    else if (f.detail) evidenceHtml = esc(f.detail);
    if (evidenceHtml) html += '<div class="f-evidence">' + evidenceHtml + '</div>';
    html += '</div></div>';
    return html;
  }

  /* ---- sidebar queue counts --------------------------------------------- */
  async function refreshSidebarCounts() {
    try {
      const [nr, q] = await Promise.all([
        SentinelAPI.needsReviewList().catch(() => []),
        SentinelAPI.quarantineList().catch(() => []),
      ]);
      setCount('navNeedsReview', nr.length);
      setCount('navQuarantine', q.length);
    } catch (e) { /* non-fatal chrome */ }
  }
  function setCount(id, n) {
    const el = document.getElementById(id);
    if (!el) return;
    if (n > 0) { el.textContent = n; el.hidden = false; }
    else { el.hidden = true; }
  }

  /* ---- top-bar protection pill ------------------------------------------ */
  async function refreshProtectionPill() {
    const pill = document.getElementById('protectionPill');
    if (!pill) return;
    const dot = document.getElementById('protectionDot');
    const text = document.getElementById('protectionText');
    try {
      const data = await SentinelAPI.gmailStatus();
      const conn = data.connection;
      pill.hidden = false;
      if (!conn) {
        dot.className = 'status-dot off';
        text.textContent = 'No mailbox connected';
      } else if (conn.connection_status === 'connected' && conn.protection_enabled) {
        dot.className = 'status-dot ok';
        text.textContent = 'Protection active';
      } else if (conn.connection_status === 'paused' || !conn.protection_enabled) {
        dot.className = 'status-dot warn';
        text.textContent = 'Protection paused';
      } else {
        dot.className = 'status-dot bad';
        text.textContent = 'Attention needed';
      }
    } catch (e) {
      pill.hidden = true; /* not admin / offline — stay quiet */
    }
  }

  /* ---- Gmail sync result -> a toast the user can actually trust --------- */
  /* SentinelAPI.gmailScanNow() resolves to the raw summary dict from
     sync.sync_connection() (integrations/gmail/sync.py). Three distinct
     shapes, previously not distinguished at any call site -- every one of
     them showed a generic "Scan complete: 0 new" regardless of what
     actually happened (partly because the field name checked, `new` /
     `new_detections`, doesn't exist on the response at all; the real field
     is `new_messages`):
       { ran: false, reason: "sync_already_in_progress" }  -- another sync
         (Beat, or a concurrent click) holds the per-connection lock.
       { ran: true, error: "GmailRetryableError", ... }    -- the sync
         started but failed before processing any mail (e.g. label setup).
       { ran: true, new_messages: N, ... }                  -- genuine result. */
  function describeSyncResult(r) {
    if (!r.ran) {
      if (r.reason === 'sync_already_in_progress') {
        return { kind: 'warn', message: 'A Gmail sync is already running — try again shortly.' };
      }
      return { kind: 'warn', message: 'Sync did not run (' + (r.reason || 'unknown reason') + ').' };
    }
    if (r.error) {
      return { kind: 'err', message: 'Sync failed: ' + r.error };
    }
    return { kind: 'ok', message: 'Scan complete: ' + (r.new_messages ?? 0) + ' new' };
  }

  document.addEventListener('DOMContentLoaded', () => {
    refreshSidebarCounts();
    refreshProtectionPill();
    // Live operational updates: queue counts and the protection pill are
    // chrome on every admin page, so they poll independently of whatever
    // page-specific refresh a given page does. Pauses automatically when
    // the tab isn't visible (see SentinelUI.startPolling).
    window.SentinelUI.startPolling(() => {
      refreshSidebarCounts();
      refreshProtectionPill();
    }, 30000);
  });

  window.AdminUI = {
    verdictBadge, riskBadge, statusBadge, sourceLabel, operationalStatus, pct,
    normFinding, findingHtml, refreshSidebarCounts, refreshProtectionPill,
    describeSyncResult,
  };
})();
