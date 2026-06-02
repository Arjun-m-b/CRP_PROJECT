/**
 * app.js — HYDRA Dashboard Core
 * ══════════════════════════════
 * Responsibilities:
 *   - API layer with auto-failover (Server A → Server B)
 *   - Polling manager (register/unregister intervals)
 *   - Hash-based client-side router
 *   - Dashboard "home" page (breach gauges, epoch tracker, live feed)
 *   - Global UI: clock, toasts, modal, sidebar server status
 */

'use strict';

/* ═══════════════════════════════════════════════════
   CONFIGURATION
   ═══════════════════════════════════════════════════ */

const CFG = {
  SERVER_A: 'http://127.0.0.1:5001',
  SERVER_B: 'http://127.0.0.1:5002',
  POLL_INTERVAL: 2000,    // ms — breach score refresh
  THETA: 0.55,    // breach threshold (must match Python)
  FETCH_TIMEOUT: 4000,    // ms per API call
};

/* ═══════════════════════════════════════════════════
   GLOBAL STATE
   ═══════════════════════════════════════════════════ */

const STATE = {
  // 'a', 'b', or null when both unreachable
  activeServer: 'a',
  // Last status snapshots
  statusA: null,
  statusB: null,
  // Whether the system has been initialised (key ceremony done)
  online: false,
  // Current epoch
  epoch: null,
  // Breach state for styling
  breach: false,
  // Number of audit entries seen (for badge)
  auditCount: 0,
};

/* ═══════════════════════════════════════════════════
   API LAYER
   ═══════════════════════════════════════════════════ */

/**
 * Fetch with a hard timeout. Returns the Response or throws.
 */
async function fetchTimeout(url, opts = {}, ms = CFG.FETCH_TIMEOUT) {
  const ctrl = new AbortController();
  const tid = setTimeout(() => ctrl.abort(), ms);
  try {
    const resp = await fetch(url, { ...opts, signal: ctrl.signal });
    return resp;
  } finally {
    clearTimeout(tid);
  }
}

/**
 * apiGet — GET from the active server with failover.
 * If the active server returns 503 (isolated) or times out, tries the other.
 */
async function apiGet(path) {
  const servers = STATE.activeServer === 'b'
    ? [CFG.SERVER_B, CFG.SERVER_A]
    : [CFG.SERVER_A, CFG.SERVER_B];

  for (let i = 0; i < servers.length; i++) {
    const base = servers[i];
    try {
      const resp = await fetchTimeout(`${base}${path}`);
      if (resp.status === 503) continue;  // server isolated, try other
      const data = await resp.json();
      // Promote the successful server to active
      STATE.activeServer = (base === CFG.SERVER_A) ? 'a' : 'b';
      return data;
    } catch {
      // Timeout or network error — try the other server
    }
  }
  throw new Error('Both servers unreachable');
}

/**
 * apiPost — POST JSON to the active server with failover.
 */
async function apiPost(path, body = {}) {
  const servers = STATE.activeServer === 'b'
    ? [CFG.SERVER_B, CFG.SERVER_A]
    : [CFG.SERVER_A, CFG.SERVER_B];

  for (let i = 0; i < servers.length; i++) {
    const base = servers[i];
    try {
      const resp = await fetchTimeout(base + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (resp.status === 503) continue;
      const data = await resp.json();
      STATE.activeServer = (base === CFG.SERVER_A) ? 'a' : 'b';
      return data;
    } catch {
      // Try other
    }
  }
  throw new Error('Both servers unreachable');
}

/**
 * apiGetServer — GET from a specific server (A or B), no failover.
 */
async function apiGetServer(server, path) {
  const base = server === 'a' ? CFG.SERVER_A : CFG.SERVER_B;
  const resp = await fetchTimeout(`${base}${path}`);
  return resp.json();
}

/* ═══════════════════════════════════════════════════
   POLLING MANAGER
   ═══════════════════════════════════════════════════ */

const polls = new Map();   // name → intervalId

function pollStart(name, fn, ms = CFG.POLL_INTERVAL) {
  pollStop(name);
  fn();  // immediate first call
  polls.set(name, setInterval(fn, ms));
}

function pollStop(name) {
  if (polls.has(name)) {
    clearInterval(polls.get(name));
    polls.delete(name);
  }
}

function pollStopAll() {
  polls.forEach((id) => clearInterval(id));
  polls.clear();
}

/* ═══════════════════════════════════════════════════
   ROUTER
   ═══════════════════════════════════════════════════ */

const PAGE_TITLES = {
  dashboard: 'Live Dashboard',
  patients: 'Patient Records',
  audit: 'Audit Chain',
  breach: 'Breach Simulator',
  crypto: 'Crypto Inspector',
};

let currentPage = null;

function navigateTo(page) {
  // Clean up previous page
  if (currentPage && window.HYDRA_PAGES?.[currentPage]?.cleanup) {
    window.HYDRA_PAGES[currentPage].cleanup();
  }
  pollStop('page');  // Stop page-specific polls

  currentPage = page;
  window.location.hash = page;

  // Update nav active state
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page);
  });

  // Update page title
  document.getElementById('page-title').textContent = PAGE_TITLES[page] || page;

  // Render page
  const container = document.getElementById('content');
  if (page === 'dashboard') {
    renderDashboard(container);
  } else if (window.HYDRA_PAGES?.[page]) {
    window.HYDRA_PAGES[page].render(container);
  } else {
    container.innerHTML = `<div class="empty-state">
      <div class="empty-icon">◈</div>
      <div class="empty-msg">Page not found: ${page}</div>
    </div>`;
  }
}

/* ═══════════════════════════════════════════════════
   TOAST NOTIFICATIONS
   ═══════════════════════════════════════════════════ */

function toast(msg, type = 'info', duration = 4000) {
  const icons = { success: '✓', error: '✕', warn: '⚠', info: '◈' };
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span class="toast-icon">${icons[type] || '◈'}</span>
                  <span class="toast-msg">${msg}</span>`;
  document.getElementById('toasts').appendChild(el);
  setTimeout(() => {
    el.classList.add('dying');
    setTimeout(() => el.remove(), 350);
  }, duration);
}

/* ═══════════════════════════════════════════════════
   MODAL
   ═══════════════════════════════════════════════════ */

function modalOpen(title, html) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-content').innerHTML = html;
  document.getElementById('modal-overlay').classList.remove('hidden');
}

function modalClose() {
  document.getElementById('modal-overlay').classList.add('hidden');
  document.getElementById('modal-content').innerHTML = '';
}

/* ═══════════════════════════════════════════════════
   GAUGE SVG BUILDER
   ═══════════════════════════════════════════════════ */

/** Compute SVG arc path for gauge (270° sweep, starts at 135°). */
function gaugePath(cx, cy, r, score) {
  const toRad = d => d * Math.PI / 180;
  const start = toRad(135);
  const total = toRad(270);
  const s = Math.max(0, Math.min(0.9999, score));
  const end = start + total * s;

  const x1 = cx + r * Math.cos(start), y1 = cy + r * Math.sin(start);
  const x2 = cx + r * Math.cos(end), y2 = cy + r * Math.sin(end);
  const large = total * s > Math.PI ? 1 : 0;

  if (s <= 0.0001) return `M ${x1.toFixed(1)} ${y1.toFixed(1)}`;
  return `M ${x1.toFixed(1)} ${y1.toFixed(1)} A ${r} ${r} 0 ${large} 1 ${x2.toFixed(1)} ${y2.toFixed(1)}`;
}

/** Full background track path (270°). */
function gaugeTrackPath(cx, cy, r) {
  return gaugePath(cx, cy, r, 0.9999);
}

/** Color based on breach score. */
function scoreColor(score) {
  if (score >= CFG.THETA) return 'var(--red)';
  if (score >= CFG.THETA * 0.7) return 'var(--orange)';
  if (score >= CFG.THETA * 0.45) return 'var(--yellow)';
  return 'var(--green)';
}

/** Status label based on score. */
function scoreLabel(score) {
  if (score >= CFG.THETA) return 'BREACH';
  if (score >= CFG.THETA * 0.7) return 'WARNING';
  if (score >= CFG.THETA * 0.45) return 'ELEVATED';
  return 'NOMINAL';
}

/** Build a gauge SVG string. */
function buildGaugeSVG(idPrefix, serverLabel, score, role) {
  const cx = 110, cy = 115, r = 85;
  const track = gaugeTrackPath(cx, cy, r);
  const arc = gaugePath(cx, cy, r, score);
  const color = scoreColor(score);
  const label = scoreLabel(score);
  const pct = (score * 100).toFixed(1);

  return `
  <svg viewBox="0 0 220 210" class="gauge-svg" role="img" aria-label="${serverLabel} threat score ${pct}%">
    <defs>
      <filter id="fg-${idPrefix}" x="-50%" y="-50%" width="200%" height="200%">
        <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="blur"/>
        <feComposite in="SourceGraphic" in2="blur" operator="over"/>
      </filter>
    </defs>
    <!-- Track -->
    <path class="gauge-track" d="${track}" stroke="rgba(0,200,255,0.08)" stroke-width="10"/>
    <!-- Glow layer -->
    <path class="gauge-glow" d="${arc}"
          stroke="${color}" stroke-width="18" fill="none"
          stroke-linecap="round" opacity="0.2"
          filter="url(#fg-${idPrefix})"/>
    <!-- Score arc -->
    <path class="gauge-fill" id="${idPrefix}-arc" d="${arc}"
          stroke="${color}" fill="none" stroke-width="9"
          stroke-linecap="round"/>
    <!-- Theta tick at 55% -->
    <line x1="${(cx + 92 * Math.cos((135 + 270 * CFG.THETA) * Math.PI / 180)).toFixed(1)}"
          y1="${(cy + 92 * Math.sin((135 + 270 * CFG.THETA) * Math.PI / 180)).toFixed(1)}"
          x2="${(cx + 76 * Math.cos((135 + 270 * CFG.THETA) * Math.PI / 180)).toFixed(1)}"
          y2="${(cy + 76 * Math.sin((135 + 270 * CFG.THETA) * Math.PI / 180)).toFixed(1)}"
          stroke="rgba(255,59,85,0.6)" stroke-width="2"/>
    <!-- Score text -->
    <text x="${cx}" y="${cy - 8}" class="gauge-score-text" fill="${color}">${pct}%</text>
    <!-- Status -->
    <text x="${cx}" y="${cy + 18}" class="gauge-status-text" fill="${color}">${label}</text>
    <!-- Server label -->
    <text x="${cx}" y="${cy + 65}" class="gauge-label-text">${serverLabel}</text>
    <!-- Role badge -->
    <text x="${cx}" y="${cy + 80}" class="gauge-server-text"
          fill="${role === 'primary' ? 'var(--cyan)' : 'var(--purple)'}">${role ? role.toUpperCase() : '—'}</text>
  </svg>`;
}

/** Update an existing gauge in-place (no full re-render). */
function updateGauge(idPrefix, score, role) {
  const cx = 110, cy = 115, r = 85;
  const arc = gaugePath(cx, cy, r, score);
  const color = scoreColor(score);
  const label = scoreLabel(score);
  const pct = (score * 100).toFixed(1);

  const arcEl = document.getElementById(`${idPrefix}-arc`);
  const glowEl = arcEl?.previousElementSibling;
  const scoreEl = arcEl?.parentElement?.querySelector('.gauge-score-text');
  const statusEl = arcEl?.parentElement?.querySelector('.gauge-status-text');
  const roleEl = arcEl?.parentElement?.querySelector('.gauge-server-text');

  if (!arcEl) return;
  arcEl.setAttribute('d', color);
  arcEl.setAttribute('stroke', color);
  arcEl.setAttribute('d', arc);
  if (glowEl) { glowEl.setAttribute('d', arc); glowEl.setAttribute('stroke', color); }
  if (scoreEl) { scoreEl.textContent = `${pct}%`; scoreEl.setAttribute('fill', color); }
  if (statusEl) { statusEl.textContent = label; statusEl.setAttribute('fill', color); }
  if (roleEl && role) {
    roleEl.textContent = role.toUpperCase();
    roleEl.setAttribute('fill', role === 'primary' ? 'var(--cyan)' : 'var(--purple)');
  }
}

/* ═══════════════════════════════════════════════════
   SIDEBAR SERVER STATUS (runs always)
   ═══════════════════════════════════════════════════ */

async function refreshSidebarStatus() {
  // Query both servers in parallel
  const [ra, rb] = await Promise.allSettled([
    apiGetServer('a', '/status'),
    apiGetServer('b', '/status'),
  ]);

  const sa = ra.status === 'fulfilled' ? ra.value : null;
  const sb = rb.status === 'fulfilled' ? rb.value : null;

  STATE.statusA = sa;
  STATE.statusB = sb;
  STATE.online = !!(sa || sb);
  STATE.epoch = sa?.epoch ?? sb?.epoch ?? null;
  STATE.breach = (sa?.score >= CFG.THETA) || (sb?.score >= CFG.THETA);

  // ── Sidebar dots ──
  function updateDot(id, tagId, st) {
    const dot = document.getElementById(id);
    const tag = document.getElementById(tagId);
    if (!dot || !tag) return;
    if (!st) {
      dot.className = 'srv-dot offline';
      tag.textContent = 'OFFLINE';
      tag.className = 'srv-tag';
    } else {
      dot.className = `srv-dot ${st.role}`;
      tag.textContent = st.role;
      tag.className = `srv-tag ${st.role}`;
    }
  }
  updateDot('srv-a-dot', 'srv-a-tag', sa);
  updateDot('srv-b-dot', 'srv-b-tag', sb);

  // ── Epoch ──
  const ep = STATE.epoch;
  document.getElementById('sidebar-epoch').textContent = ep ?? '—';
  document.getElementById('topbar-epoch').textContent = ep ?? '—';

  // ── System status pill ──
  const pill = document.getElementById('sys-status-pill');
  const txt = document.getElementById('sys-status-text');
  if (!STATE.online) {
    pill.className = 'topbar-pill';
    txt.textContent = 'OFFLINE';
  } else if (STATE.breach) {
    pill.className = 'topbar-pill breach';
    txt.textContent = 'BREACH DETECTED';
  } else {
    pill.className = 'topbar-pill online';
    txt.textContent = 'OPERATIONAL';
  }

  // ── Audit badge ──
  try {
    const ad = await apiGet('/audit/summary');
    if (ad?.total > STATE.auditCount) {
      STATE.auditCount = ad.total;
      const badge = document.getElementById('audit-badge');
      if (badge) badge.textContent = ad.total;
    }
  } catch { /* ignore */ }
}

/* ═══════════════════════════════════════════════════
   DASHBOARD PAGE
   ═══════════════════════════════════════════════════ */

function renderDashboard(container) {
  container.innerHTML = `
  <div class="dash-grid">

    <!-- ── Breach gauges ── -->
    <div class="card gauges-card">
      <div class="card-title">⚡ REAL-TIME THREAT ANALYSIS — <span>θ = ${CFG.THETA}</span></div>
      <div class="gauges-row">
        <div class="gauge-box" id="gauge-a-box">
          <div class="loading-row"><span class="loading-spinner"></span></div>
        </div>
        <div class="gauge-divider">
          <div style="text-align:center;padding:20px 10px;color:var(--text-3);font-family:'JetBrains Mono',monospace;font-size:10px;line-height:2.2">
            <div style="color:var(--cyan);font-size:18px;margin-bottom:8px">◈</div>
            SHAMIR<br>SPLIT<br>3-of-2<br>
            <div style="margin-top:12px;color:var(--text-3)">S1 ── A</div>
            <div style="color:var(--text-3)">S2 ── B</div>
            <div style="color:var(--text-3)">S3 ── 🔑</div>
          </div>
        </div>
        <div class="gauge-box" id="gauge-b-box">
          <div class="loading-row"><span class="loading-spinner"></span></div>
        </div>
      </div>
    </div>

    <!-- ── Epoch tracker ── -->
    <div class="card epoch-card">
      <div class="card-title">🔄 ENCRYPTION EPOCH</div>
      <div class="epoch-display">
        <div class="epoch-number" id="dash-epoch">—</div>
        <div class="epoch-label">Current Epoch</div>
        <div class="epoch-ratchet" id="dash-ratchet">Last ratchet: <span>—</span></div>
      </div>
      <div id="ratchet-mini-timeline" style="margin-top:12px"></div>
    </div>

    <!-- ── Server stats ── -->
    <div class="card stats-card">
      <div class="card-title">◉ SERVER METRICS</div>
      <div class="stats-grid">
        <div class="stat-box">
          <div class="stat-box-label">Records (A)</div>
          <div class="stat-box-val cyan" id="stat-rec-a">—</div>
        </div>
        <div class="stat-box">
          <div class="stat-box-label">Records (B)</div>
          <div class="stat-box-val cyan" id="stat-rec-b">—</div>
        </div>
        <div class="stat-box">
          <div class="stat-box-label">Score A</div>
          <div class="stat-box-val" id="stat-score-a">—</div>
        </div>
        <div class="stat-box">
          <div class="stat-box-label">Score B</div>
          <div class="stat-box-val" id="stat-score-b">—</div>
        </div>
        <div class="stat-box">
          <div class="stat-box-label">Uptime A</div>
          <div class="stat-box-val green" id="stat-up-a">—</div>
        </div>
        <div class="stat-box">
          <div class="stat-box-label">Uptime B</div>
          <div class="stat-box-val green" id="stat-up-b">—</div>
        </div>
      </div>
      <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn btn-primary btn-sm" onclick="triggerRatchet()">⚡ Manual Ratchet</button>
        <button class="btn btn-ghost btn-sm" onclick="navigateTo('breach')">Simulate Breach</button>
      </div>
    </div>

    <!-- ── Live audit feed ── -->
    <div class="card feed-card">
      <div class="card-title flex justify-between items-center">
        <span>◎ LIVE AUDIT FEED</span>
        <button class="btn btn-ghost btn-sm" onclick="navigateTo('audit')">Full log →</button>
      </div>
      <div class="mini-feed" id="dash-feed">
        <div class="loading-row"><span class="loading-spinner"></span> Waiting for events…</div>
      </div>
    </div>

  </div>`;

  // Start polling
  pollStart('dashboard', refreshDashboard, CFG.POLL_INTERVAL);
}

/* Event type → CSS class + display name */
const AUDIT_META = {
  SERVER_STARTED: { cls: 'server', label: 'SERVER STARTED', icon: '▶' },
  KEY_CEREMONY: { cls: 'key', label: 'KEY CEREMONY', icon: '🔑' },
  SHARE_ISSUED: { cls: 'key', label: 'SHARE ISSUED', icon: '◈' },
  RATCHET_TRIGGERED: { cls: 'ratchet', label: 'RATCHET TRIGGERED', icon: '⚡' },
  RATCHET_COMPLETE: { cls: 'ratchet', label: 'RATCHET COMPLETE', icon: '✓' },
  BREACH_SCORE_HIGH: { cls: 'breach', label: 'BREACH DETECTED', icon: '🚨' },
  FAILOVER_INITIATED: { cls: 'failover', label: 'FAILOVER INIT', icon: '↻' },
  FAILOVER_COMPLETE: { cls: 'failover', label: 'FAILOVER DONE', icon: '⬡' },
  RE_ENCRYPT_START: { cls: 'ratchet', label: 'RE-ENCRYPT START', icon: '🔄' },
  RE_ENCRYPT_COMPLETE: { cls: 'ratchet', label: 'RE-ENCRYPT DONE', icon: '✓' },
  RECORD_STORED: { cls: 'record', label: 'RECORD STORED', icon: '◉' },
  RECORD_FETCHED: { cls: 'record', label: 'RECORD FETCHED', icon: '◎' },
  SERVER_ISOLATED: { cls: 'breach', label: 'SERVER ISOLATED', icon: '⛔' },
  ZK_PROOF_PASSED: { cls: 'key', label: 'ZKP PASSED', icon: '✓' },
  ZK_PROOF_FAILED: { cls: 'breach', label: 'ZKP FAILED', icon: '✕' },
};

function formatTime(ts) {
  if (!ts) return '??:??:??';
  try {
    const d = new Date(ts);
    return d.toISOString().substr(11, 8);
  } catch { return ts; }
}

async function refreshDashboard() {
  // Both servers in parallel
  const [ra, rb] = await Promise.allSettled([
    apiGetServer('a', '/status'),
    apiGetServer('b', '/status'),
  ]);
  const sa = ra.status === 'fulfilled' ? ra.value : null;
  const sb = rb.status === 'fulfilled' ? rb.value : null;

  // ── Gauges ──
  const scoreA = sa?.score ?? 0;
  const scoreB = sb?.score ?? 0;
  const roleA = sa?.role ?? '—';
  const roleB = sb?.role ?? '—';

  const gba = document.getElementById('gauge-a-box');
  const gbb = document.getElementById('gauge-b-box');
  if (gba && !document.getElementById('ga-arc')) {
    gba.innerHTML = buildGaugeSVG('ga', 'SERVER A', scoreA, roleA);
  } else {
    updateGauge('ga', scoreA, roleA);
  }
  if (gbb && !document.getElementById('gb-arc')) {
    gbb.innerHTML = buildGaugeSVG('gb', 'SERVER B', scoreB, roleB);
  } else {
    updateGauge('gb', scoreB, roleB);
  }

  // ── Epoch ──
  const ep = sa?.epoch ?? sb?.epoch ?? '—';
  const epEl = document.getElementById('dash-epoch');
  if (epEl) epEl.textContent = ep;

  // ── Stats ──
  function setEl(id, val, cls) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = val ?? '—';
    if (cls) el.className = `stat-box-val ${cls}`;
  }
  setEl('stat-rec-a', sa?.record_count, 'cyan');
  setEl('stat-rec-b', sb?.record_count, 'cyan');

  function scoreClass(s) {
    if (s == null) return '';
    if (s >= CFG.THETA) return 'red';
    if (s >= CFG.THETA * 0.7) return 'orange';
    return 'green';
  }
  setEl('stat-score-a', sa ? sa.score.toFixed(3) : '—', scoreClass(sa?.score));
  setEl('stat-score-b', sb ? sb.score.toFixed(3) : '—', scoreClass(sb?.score));

  function fmtUptime(s) {
    if (s == null) return '—';
    const m = Math.floor(s / 60), sec = Math.floor(s % 60);
    return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
  }
  setEl('stat-up-a', sa ? fmtUptime(sa.uptime_seconds) : '—', 'green');
  setEl('stat-up-b', sb ? fmtUptime(sb.uptime_seconds) : '—', 'green');

  // ── Mini audit feed ──
  try {
    const ad = await apiGet('/audit');
    if (ad?.entries) {
      const feed = document.getElementById('dash-feed');
      if (!feed) return;
      const entries = ad.entries.slice(-8).reverse();
      feed.innerHTML = entries.map(e => {
        const eventType = e.event_type || e.event || 'UNKNOWN';
        const meta = AUDIT_META[eventType] || { cls: '', label: eventType, icon: '◆' };
        const dataStr = Object.entries(e.data || {})
          .filter(([k]) => !['server'].includes(k))
          .map(([k, v]) => `${k}=${v}`)
          .join(' ').substring(0, 60);
        return `<div class="feed-entry ${meta.cls}">
          <span class="feed-time">${formatTime(e.timestamp)}</span>
          <span class="feed-type">${meta.icon} ${meta.label}</span>
          <span class="feed-data">${dataStr}</span>
        </div>`;
      }).join('') || '<div class="loading-row">No events yet…</div>';

      // Update ratchet info
      const ratchets = ad.entries.filter(e => e.event_type === 'RATCHET_COMPLETE');
      const lastRatchet = ratchets[ratchets.length - 1];
      const rEl = document.getElementById('dash-ratchet');
      if (rEl) {
        rEl.innerHTML = lastRatchet
          ? `Last ratchet: <span>${formatTime(lastRatchet.timestamp)} (epoch ${lastRatchet.data?.new_epoch})</span>`
          : 'Last ratchet: <span>None (epoch 1)</span>';
      }
    }
  } catch { /* offline */ }
}

async function triggerRatchet() {
  try {
    const r = await apiPost('/ratchet', { reason: 'manual — dashboard' });
    if (r?.status === 'ok') {
      toast('Ratchet initiated! Deriving new key…', 'warn');
    } else {
      toast(r?.message || 'Ratchet failed', 'error');
    }
  } catch (e) {
    toast('Cannot reach server: ' + e.message, 'error');
  }
}

/* ═══════════════════════════════════════════════════
   CLOCK
   ═══════════════════════════════════════════════════ */

function updateClock() {
  const d = new Date();
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mm = String(d.getUTCMinutes()).padStart(2, '0');
  const ss = String(d.getUTCSeconds()).padStart(2, '0');
  const el = document.getElementById('clock');
  if (el) el.textContent = `${hh}:${mm}:${ss}`;
}

/* ═══════════════════════════════════════════════════
   INIT
   ═══════════════════════════════════════════════════ */

// Expose helpers to page modules
window.HYDRA = {
  apiGet, apiPost, apiGetServer,
  toast, modalOpen, modalClose,
  pollStart, pollStop, pollStopAll,
  CFG, STATE, AUDIT_META,
  scoreColor, scoreLabel, formatTime, gaugePath,
  navigateTo,
};

document.addEventListener('DOMContentLoaded', () => {

  // ── Nav click handlers ──
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => navigateTo(item.dataset.page));
    item.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') navigateTo(item.dataset.page);
    });
  });

  // ── Sidebar toggle (mobile) ──
  document.getElementById('sidebar-toggle')?.addEventListener('click', () => {
    document.getElementById('sidebar').classList.toggle('open');
  });

  // ── Modal close ──
  document.getElementById('modal-close')?.addEventListener('click', modalClose);
  document.getElementById('modal-overlay')?.addEventListener('click', e => {
    if (e.target === document.getElementById('modal-overlay')) modalClose();
  });

  // ── Clock ──
  updateClock();
  setInterval(updateClock, 1000);

  // ── Always-on sidebar refresh ──
  pollStart('sidebar', refreshSidebarStatus, 3000);

  // ── Route to initial page ──
  const hash = window.location.hash.replace('#', '') || 'dashboard';
  navigateTo(hash);

  // ── Hash change ──
  window.addEventListener('hashchange', () => {
    const p = window.location.hash.replace('#', '') || 'dashboard';
    if (p !== currentPage) navigateTo(p);
  });
});
