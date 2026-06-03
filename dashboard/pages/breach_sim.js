/**
 * breach_sim.js — Breach Simulation Module
 */
window.HYDRA_PAGES = window.HYDRA_PAGES || {};

window.HYDRA_PAGES.breach = {
  cleanup: () => {
    HYDRA.pollStop('breach-status');
    if (window.breachAnim) cancelAnimationFrame(window.breachAnim);
  },

  render: (container) => {
    container.innerHTML = `
      <div class="card">
        <div class="card-title text-red">⚡ THREAT SIMULATION ENGINE</div>
        
        <div class="sim-panel mt-16">
          
          <!-- Controls -->
          <div>
            <p class="text-dim mb-16" style="font-size:12px; line-height:1.5;">
              Use the sliders below to simulate anomalous signals. The BreachDetector runs continuously, scoring these signals using exponential decay. When the combined score crosses θ=${HYDRA.CFG.THETA}, the cryptographic ratchet will fire automatically.
            </p>
            
            <div class="form-group">
              <label class="form-label flex justify-between">
                <span>Request Rate Anomaly (λ)</span>
                <span id="val-rate">0</span>
              </label>
              <input type="range" id="sim-rate" min="0" max="100" value="0" oninput="HYDRA_PAGES.breach.updateSim()">
            </div>
            
            <div class="form-group">
              <label class="form-label flex justify-between">
                <span>Geo-Velocity Anomaly (Δkm/h)</span>
                <span id="val-geo">0</span>
              </label>
              <input type="range" id="sim-geo" min="0" max="100" value="0" oninput="HYDRA_PAGES.breach.updateSim()">
            </div>
            
            <div class="form-group">
              <label class="form-label flex justify-between">
                <span>Auth Failure Burst</span>
                <span id="val-auth">0</span>
              </label>
              <input type="range" id="sim-auth" min="0" max="100" value="0" oninput="HYDRA_PAGES.breach.updateSim()">
            </div>

            <div class="form-group">
              <label class="form-label flex justify-between">
                <span>Timing Anomaly (Jitter)</span>
                <span id="val-timing">0</span>
              </label>
              <input type="range" id="sim-timing" min="0" max="100" value="0" oninput="HYDRA_PAGES.breach.updateSim()">
            </div>
            
            <div class="mt-16 pt-16" style="border-top:1px solid var(--border);">
              <button class="btn btn-danger w-full justify-between" id="btn-fire" onclick="HYDRA_PAGES.breach.fireSimulation()">
                <span>INJECT THREAT SIGNALS</span>
                <span>⚡</span>
              </button>
            </div>
            <div class="mt-8">
              <button class="btn btn-ghost w-full justify-between" onclick="HYDRA_PAGES.breach.resetSystem()">
                <span>RESET ENTIRE SYSTEM</span>
                <span>↻</span>
              </button>
            </div>
          </div>
          
          <!-- Monitor -->
          <div style="display:flex; flex-direction:column; gap: 16px;">
            <div class="sim-graph-wrap">
              <canvas id="sim-canvas"></canvas>
              <div class="theta-line" style="bottom: ${(HYDRA.CFG.THETA * 100)}%;"></div>
              <div class="theta-label" style="bottom: ${(HYDRA.CFG.THETA * 100)}%;">θ = ${HYDRA.CFG.THETA}</div>
            </div>
            
            <div class="stat-box" style="flex:1; justify-content:center; align-items:center;">
              <div class="stat-box-label text-center mb-8">LIVE THREAT SCORE</div>
              <div class="big-score safe" id="sim-score">0.000</div>
              <div class="tag mt-8" id="sim-state">NOMINAL</div>
            </div>
          </div>
          
        </div>
      </div>
    `;

    HYDRA_PAGES.breach.initGraph();
    HYDRA.pollStart('breach-status', HYDRA_PAGES.breach.pollScore, 1000);
  },

  updateSim: () => {
    ['rate', 'geo', 'auth', 'timing'].forEach(id => {
      document.getElementById(`val-${id}`).textContent = document.getElementById(`sim-${id}`).value;
    });
  },

  fireSimulation: async () => {
    const rate   = parseInt(document.getElementById('sim-rate').value,   10);
    const geo    = parseInt(document.getElementById('sim-geo').value,    10);
    const auth   = parseInt(document.getElementById('sim-auth').value,   10);
    const timing = parseInt(document.getElementById('sim-timing').value, 10);

    const intensity = Math.max(1, Math.ceil((rate + geo + auth + timing) / 50));

    const btn = document.getElementById('btn-fire');
    btn.disabled = true;
    btn.innerHTML = '<span>DETECTING PRIMARY...</span> <span class="loading-spinner"></span>';

    // ── Auto-detect primary server ────────────────────────────────
    // Query both servers and target whichever is currently primary.
    // This allows re-injection after failover without manual switching.
    let targetUrl  = HYDRA.CFG.SERVER_A;
    let targetName = 'Server A';
    try {
      const [sa, sb] = await Promise.allSettled([
        fetch(HYDRA.CFG.SERVER_A + '/status').then(r => r.json()),
        fetch(HYDRA.CFG.SERVER_B + '/status').then(r => r.json()),
      ]);
      const aRole = sa.status === 'fulfilled' ? sa.value?.role : null;
      const bRole = sb.status === 'fulfilled' ? sb.value?.role : null;

      if (aRole === 'primary' && !sa.value?.isolated) {
        targetUrl  = HYDRA.CFG.SERVER_A;
        targetName = 'Server A';
      } else if (bRole === 'primary' && !sb.value?.isolated) {
        targetUrl  = HYDRA.CFG.SERVER_B;
        targetName = 'Server B';
      } else if (aRole === 'primary') {
        targetUrl  = HYDRA.CFG.SERVER_A;
        targetName = 'Server A';
      }
      // else: default stays Server A
    } catch (_) { /* fallback to Server A */ }

    btn.innerHTML = `<span>INJECTING → ${targetName}...</span> <span class="loading-spinner"></span>`;

    try {
      const resp = await fetch(targetUrl + '/simulate_breach', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ intensity, rate, geo, auth, timing }),
      }).then(r => r.json());

      if (resp?.status === 'ok') {
        const scoreStr = resp.score !== undefined ? ` (score: ${resp.score.toFixed(3)})` : '';
        if (resp.breach) {
          HYDRA.toast(`BREACH on ${targetName}! Ratchet firing…${scoreStr}`, 'error');
        } else {
          HYDRA.toast(`Threat signals injected → ${targetName}.${scoreStr}`, 'warn');
        }
      } else {
        throw new Error(resp?.message || 'Unknown error');
      }
    } catch (e) {
      HYDRA.toast('Failed to inject signals: ' + e.message, 'error');
    } finally {
      setTimeout(() => {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = '<span>INJECT THREAT SIGNALS</span> <span>⚡</span>';
        }
      }, 1000);
    }
  },

  resetSystem: async () => {
    if (!confirm('Reset the entire system? This generates a new encryption key and restarts the key ceremony on both servers.')) return;

    HYDRA.toast('Initiating full system reset…', 'warn');
    try {
      // Server A’s /reset drives the full ceremony:
      //   1. Generates a fresh 32-byte master key
      //   2. Re-initialises itself as primary at epoch 1
      //   3. POSTs the new key to Server B via /init
      // Calling Server B’s /reset separately is NOT needed —
      // and would wipe the key A just pushed.
      const resp = await fetch(HYDRA.CFG.SERVER_A + '/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await resp.json();

      if (resp.ok && data.status === 'ok') {
        HYDRA.toast(`System reset — new epoch ${data.epoch ?? 1}. Both servers ready.`, 'success');
        setTimeout(() => HYDRA.navigateTo('dashboard'), 2000);
      } else {
        HYDRA.toast('Reset returned unexpected response: ' + (data.message ?? resp.status), 'error');
      }
    } catch (e) {
      HYDRA.toast('Reset failed: ' + e.message, 'error');
    }
  },

  // ── Graph ──
  history: Array(50).fill(0),

  initGraph: () => {
    const canvas = document.getElementById('sim-canvas');
    if (!canvas) return;

    // Fix resolution
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width * 2;
    canvas.height = rect.height * 2;
    const ctx = canvas.getContext('2d');

    const draw = () => {
      if (!document.getElementById('sim-canvas')) return; // Cleaned up

      ctx.clearRect(0, 0, canvas.width, canvas.height);

      const w = canvas.width;
      const h = canvas.height;
      const step = w / (HYDRA_PAGES.breach.history.length - 1);

      ctx.beginPath();
      ctx.moveTo(0, h);

      HYDRA_PAGES.breach.history.forEach((val, i) => {
        const x = i * step;
        const y = h - (Math.min(1, val) * h);
        ctx.lineTo(x, y);
      });

      ctx.lineTo(w, h);

      // Gradient fill
      const grad = ctx.createLinearGradient(0, 0, 0, h);
      grad.addColorStop(0, 'rgba(255, 59, 85, 0.5)'); // Red at top
      grad.addColorStop(1, 'rgba(0, 200, 255, 0.0)'); // Transparent at bottom
      ctx.fillStyle = grad;
      ctx.fill();

      // Line
      ctx.beginPath();
      HYDRA_PAGES.breach.history.forEach((val, i) => {
        const x = i * step;
        const y = h - (Math.min(1, val) * h);
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.strokeStyle = 'rgba(0, 200, 255, 0.8)';
      ctx.lineWidth = 4;
      ctx.stroke();

      window.breachAnim = requestAnimationFrame(draw);
    };

    draw();
  },

  pollScore: async () => {
    try {
      const data = await HYDRA.apiGet('/score');
      if (data?.score !== undefined) {
        const s = data.score;
        HYDRA_PAGES.breach.history.shift();
        HYDRA_PAGES.breach.history.push(s);

        const scoreEl = document.getElementById('sim-score');
        const stateEl = document.getElementById('sim-state');
        if (scoreEl) {
          scoreEl.textContent = s.toFixed(3);
          if (s >= HYDRA.CFG.THETA) {
            scoreEl.className = 'big-score breach';
            stateEl.className = 'tag tag-danger mt-8';
            stateEl.textContent = 'BREACH DETECTED - RATCHETING';
          } else if (s >= HYDRA.CFG.THETA * 0.7) {
            scoreEl.className = 'big-score warn';
            stateEl.className = 'tag tag-warn mt-8';
            stateEl.textContent = 'ELEVATED THREAT';
          } else {
            scoreEl.className = 'big-score safe';
            stateEl.className = 'tag tag-success mt-8';
            stateEl.textContent = 'NOMINAL';
          }
        }
      }
    } catch (e) {
      // offline
    }
  }
};
