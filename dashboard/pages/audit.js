/**
 * audit.js — Cryptographic Audit Log Module
 */
window.HYDRA_PAGES = window.HYDRA_PAGES || {};

window.HYDRA_PAGES.audit = {
  cleanup: () => HYDRA.pollStop('audit'),

  render: (container) => {
    container.innerHTML = `
      <div class="card">
        <div class="card-title flex justify-between items-center">
          <span>◎ IMMUTABLE AUDIT CHAIN</span>
          <div>
            <button class="btn btn-ghost btn-sm" onclick="HYDRA_PAGES.audit.verify()">✓ Verify Chain</button>
            <button class="btn btn-primary btn-sm" onclick="HYDRA_PAGES.audit.refresh()">↻ Refresh</button>
          </div>
        </div>

        <div class="mt-16">
          <div class="form-label">CHAIN INTEGRITY VERIFICATION</div>
          <div class="chain-bar" id="audit-chain-bar">
            <div class="loading-spinner"></div>
          </div>
        </div>

        <div class="audit-summary stats-grid mb-16" id="audit-summary-grid"></div>

        <div class="audit-container" id="audit-feed">
          <div class="loading-row">Loading audit log...</div>
        </div>
      </div>
    `;

    HYDRA_PAGES.audit.refresh();
    HYDRA.pollStart('audit', HYDRA_PAGES.audit.refresh, 3000);
  },

  refresh: async () => {
    try {
      const data = await HYDRA.apiGet('/audit');
      if (data?.entries) {
        HYDRA_PAGES.audit.renderFeed(data.entries);
      }
      // Fetch summary separately
      try {
        const summary = await HYDRA.apiGet('/audit/summary');
        HYDRA_PAGES.audit.renderSummary(summary);
      } catch { /* ignore */ }
    } catch (e) {
      const feed = document.getElementById('audit-feed');
      if (feed) {
        feed.innerHTML = `
          <div class="empty-state text-red">Failed to load audit log: ${e.message}</div>
        `;
      }
    }
  },

  verify: async () => {
    HYDRA.toast('Verifying cryptographic hash chain...', 'info');
    try {
      const data = await HYDRA.apiGet('/audit/verify');
      if (data?.valid) {
        HYDRA.toast('Audit chain verified intact. ' + (data.message || ''), 'success');
      } else {
        HYDRA.toast('AUDIT CHAIN BROKEN! ' + (data?.message || 'Tampering detected.'), 'error', 10000);
      }
    } catch (e) {
      HYDRA.toast('Verification failed: ' + e.message, 'error');
    }
  },

  renderFeed: (entries) => {
    const feed = document.getElementById('audit-feed');
    if (!feed) return;

    if (!entries || entries.length === 0) {
      feed.innerHTML = `<div class="empty-state">No audit events yet.</div>`;
      return;
    }

    // Render in reverse chronological order
    // Audit entries use "event" field (not "event_type")
    const html = entries.slice().reverse().map(e => {
      const eventType = e.event_type || e.event || 'UNKNOWN';
      const meta = HYDRA.AUDIT_META[eventType] || { cls: '', label: eventType, icon: '◆' };
      
      let timeStr;
      try {
        // Timestamp may be a unix float
        const ts = typeof e.timestamp === 'number' && e.timestamp < 1e12
          ? e.timestamp * 1000
          : e.timestamp * 1000;
        timeStr = new Date(ts).toISOString().replace('T', ' ').substring(0, 19);
      } catch {
        timeStr = String(e.timestamp || '??');
      }

      let badge = '';
      if (e.data?.epoch) badge = `<span class="ae-badge">EPOCH ${e.data.epoch}</span>`;
      if (e.data?.server) badge += `<span class="ae-badge">${e.data.server}</span>`;

      const dataStr = Object.entries(e.data || {})
        .filter(([k]) => k !== 'epoch' && k !== 'server')
        .map(([k, v]) => {
          if (typeof v === 'number' && v % 1 !== 0) return `${k}=${v.toFixed(3)}`;
          return `${k}=${v}`;
        })
        .join(' ');

      return `
        <div class="audit-entry" title="Hash: ${e.this_hash}\nPrev: ${e.prev_hash}">
          <div class="ae-seq">#${e.seq}</div>
          <div class="ae-time">${timeStr}</div>
          <div class="ae-type text-${meta.cls}">${meta.icon} ${meta.label}</div>
          <div class="ae-data flex items-center gap-8">
            ${badge}
            <span>${dataStr}</span>
          </div>
        </div>
      `;
    }).join('');

    feed.innerHTML = html;

    // Render chain bar (visualise the hash links)
    const bar = document.getElementById('audit-chain-bar');
    if (bar) {
      const blocks = entries.slice(-40).map((e, i, arr) => {
        const isRecent = i >= arr.length - 3;
        return `<div class="chain-block valid ${isRecent ? 'recent' : ''}" title="Seq ${e.seq}\nHash: ${(e.this_hash || '').substring(0, 16)}..."></div>`;
      });
      bar.innerHTML = blocks.join('<div class="chain-arrow">→</div>');
      // Scroll to end (right)
      bar.scrollLeft = bar.scrollWidth;
    }
  },

  renderSummary: (summary) => {
    const grid = document.getElementById('audit-summary-grid');
    if (!grid) return;

    if (!summary) return;

    grid.innerHTML = `
      <div class="stat-box">
        <div class="stat-box-label">Total Events</div>
        <div class="stat-box-val">${summary.total || 0}</div>
      </div>
      <div class="stat-box">
        <div class="stat-box-label">Ratchets Triggered</div>
        <div class="stat-box-val orange">${summary.ratchets || 0}</div>
      </div>
      <div class="stat-box">
        <div class="stat-box-label">Failovers</div>
        <div class="stat-box-val purple">${summary.failovers || 0}</div>
      </div>
      <div class="stat-box">
        <div class="stat-box-label">Chain Integrity</div>
        <div class="stat-box-val ${summary.chain_valid ? 'green' : 'red'}">${summary.chain_valid ? 'INTACT' : 'BROKEN'}</div>
      </div>
    `;
  }
};
