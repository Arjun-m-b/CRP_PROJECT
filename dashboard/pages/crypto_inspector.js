/**
 * crypto_inspector.js — Cryptographic Visualisation Module
 */
window.HYDRA_PAGES = window.HYDRA_PAGES || {};

window.HYDRA_PAGES.crypto = {
  cleanup: () => { },

  render: (container) => {
    container.innerHTML = `
      <div class="card">
        <div class="card-title text-cyan">⬢ CRYPTO INSPECTOR</div>
        
        <div class="tab-bar mt-16" id="crypto-tabs">
          <button class="tab-btn active" data-target="tab-chacha">XChaCha20 Matrix</button>
          <button class="tab-btn" data-target="tab-hkdf">HKDF Ratchet</button>
          <button class="tab-btn" data-target="tab-shamir">Shamir (3,2)</button>
        </div>
        
        <!-- XChaCha20 -->
        <div id="tab-chacha" class="tab-panel active">
          <div class="text-center mb-16 text-dim" style="font-size:11px;">
            The 4x4 ChaCha state matrix (512 bits) before Quarter Round permutations.
          </div>
          <div class="chacha-matrix" id="chacha-grid"></div>
          
          <div class="mt-16 flex justify-center gap-16" style="font-size:10px; font-family:'JetBrains Mono',monospace;">
            <div class="flex items-center gap-8"><div style="width:10px;height:10px;background:rgba(0,200,255,0.2);border:1px solid var(--cyan)"></div> Constants</div>
            <div class="flex items-center gap-8"><div style="width:10px;height:10px;background:rgba(167,139,250,0.2);border:1px solid var(--purple)"></div> Key (256-bit)</div>
            <div class="flex items-center gap-8"><div style="width:10px;height:10px;background:rgba(249,115,22,0.2);border:1px solid var(--orange)"></div> Counter</div>
            <div class="flex items-center gap-8"><div style="width:10px;height:10px;background:rgba(251,191,36,0.2);border:1px solid var(--yellow)"></div> Nonce</div>
          </div>
          <div class="mt-16 text-center">
            <button class="btn btn-ghost btn-sm" onclick="HYDRA_PAGES.crypto.animateChaCha()">Simulate Quarter Round</button>
          </div>
        </div>
        
        <!-- HKDF -->
        <div id="tab-hkdf" class="tab-panel">
          <div class="text-center mb-16 text-dim" style="font-size:11px;">
            HMAC-based Extract-and-Expand Key Derivation Function (using BLAKE2s)
          </div>
          <div class="hkdf-flow">
            <div class="hkdf-node extract">
              <div class="hkdf-label">Input Key Material (IKM)</div>
              <div class="hkdf-val text-dim">K<sub>n</sub> (Current Master Key)</div>
            </div>
            <div class="hkdf-arrow">↓</div>
            <div class="hkdf-node extract" style="border-color:var(--cyan);">
              <div class="hkdf-label">HKDF Extract</div>
              <div class="hkdf-val text-dim">PRK = HMAC-BLAKE2s(Salt, IKM)</div>
            </div>
            <div class="hkdf-arrow">↓</div>
            <div class="hkdf-node expand">
              <div class="hkdf-label">HKDF Expand</div>
              <div class="hkdf-val text-dim">OKM = HMAC-BLAKE2s(PRK, Info | 0x01)</div>
            </div>
            <div class="hkdf-arrow">↓</div>
            <div class="hkdf-node output">
              <div class="hkdf-label">Output Key Material (OKM)</div>
              <div class="hkdf-val text-dim">K<sub>n+1</sub> (New Master Key)</div>
            </div>
          </div>
          <div class="mt-16 text-center text-red" style="font-size:10px; font-family:'JetBrains Mono',monospace;">
            FORWARD SECRECY: K<sub>n</sub> is erased from memory immediately after derivation.
          </div>
        </div>
        
        <!-- Shamir -->
        <div id="tab-shamir" class="tab-panel">
          <div class="text-center mb-16 text-dim" style="font-size:11px;">
            Shamir's Secret Sharing over GF(p) where p = 2^256 - 189.<br>
            Threshold (k) = 2, Total Shares (n) = 3
          </div>
          <div class="shamir-canvas-wrap">
            <canvas id="shamir-canvas" height="240"></canvas>
            <div class="shamir-legend">
              <div class="shamir-legend-item"><div class="legend-dot" style="background:var(--cyan)"></div> Secret (x=0)</div>
              <div class="shamir-legend-item"><div class="legend-dot" style="background:var(--purple)"></div> S1 (Server A)</div>
              <div class="shamir-legend-item"><div class="legend-dot" style="background:var(--green)"></div> S2 (Server B)</div>
              <div class="shamir-legend-item"><div class="legend-dot" style="background:var(--orange)"></div> S3 (Token)</div>
            </div>
          </div>
          <div class="mt-16 text-center text-dim" style="font-size:10px; font-family:'JetBrains Mono',monospace;">
            f(x) = S + a_1*x (mod p)<br>
            Any 2 points can uniquely reconstruct the line to find f(0).
          </div>
        </div>
        
      </div>
    `;

    // Tabs logic
    document.querySelectorAll('#crypto-tabs .tab-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        document.querySelectorAll('#crypto-tabs .tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        e.target.classList.add('active');
        document.getElementById(e.target.dataset.target).classList.add('active');

        if (e.target.dataset.target === 'tab-shamir') HYDRA_PAGES.crypto.drawShamir();
      });
    });

    HYDRA_PAGES.crypto.renderChaCha();
  },

  renderChaCha: () => {
    const grid = document.getElementById('chacha-grid');
    if (!grid) return;

    // Initial State (RFC 8439)
    const vals = [
      'expa', 'nd 3', '2-by', 'te k', // 0-3 constants
      'key0', 'key1', 'key2', 'key3', // 4-7 key
      'key4', 'key5', 'key6', 'key7', // 8-11 key
      'cnt0', 'non0', 'non1', 'non2'  // 12 counter, 13-15 nonce
    ];

    const types = [
      'constant', 'constant', 'constant', 'constant',
      'key-word', 'key-word', 'key-word', 'key-word',
      'key-word', 'key-word', 'key-word', 'key-word',
      'counter', 'nonce', 'nonce', 'nonce'
    ];

    grid.innerHTML = vals.map((v, i) => `
      <div class="chacha-cell ${types[i]}" id="cc-${i}">
        <div class="chacha-cell-idx">${i}</div>
        <div class="chacha-cell-val">${v}</div>
      </div>
    `).join('');
  },

  animateChaCha: () => {
    // Highlight a quarter round: 0, 4, 8, 12
    const indices = [0, 4, 8, 12];
    indices.forEach((idx, i) => {
      setTimeout(() => {
        const el = document.getElementById(`cc-${idx}`);
        if (el) {
          el.classList.add('changed');
          setTimeout(() => el.classList.remove('changed'), 500);
        }
      }, i * 150);
    });
  },

  drawShamir: () => {
    const canvas = document.getElementById('shamir-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width, h = canvas.height;

    // Clear
    ctx.clearRect(0, 0, w, h);

    // Grid
    ctx.strokeStyle = 'rgba(0, 200, 255, 0.1)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    for (let x = 0; x < w; x += 40) { ctx.moveTo(x, 0); ctx.lineTo(x, h); }
    for (let y = 0; y < h; y += 40) { ctx.moveTo(0, y); ctx.lineTo(w, y); }
    ctx.stroke();

    // Axes
    const ox = 40, oy = h - 30;
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.3)';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(ox, 10); ctx.lineTo(ox, oy); // Y
    ctx.lineTo(w - 10, oy); // X
    ctx.stroke();

    // Line (f(x) = 150 - 20x) (visual approx)
    const sy = oy - 140; // Secret at x=0
    const slope = 30;    // going down/up

    ctx.strokeStyle = 'rgba(0, 200, 255, 0.4)';
    ctx.lineWidth = 2;
    ctx.setLineDash([5, 5]);
    ctx.beginPath();
    ctx.moveTo(ox, sy);
    ctx.lineTo(ox + 4 * 40, sy - 4 * slope);
    ctx.stroke();
    ctx.setLineDash([]);

    // Draw points
    const drawPoint = (x, y, color, label) => {
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(ox + x * 40, sy - x * slope, 6, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 10;
      ctx.shadowColor = color;
      ctx.fill();
      ctx.shadowBlur = 0;

      ctx.fillStyle = 'white';
      ctx.font = '10px JetBrains Mono';
      ctx.fillText(label, ox + x * 40 - 5, sy - x * slope - 15);
    };

    drawPoint(0, sy, 'var(--cyan)', 'S (0)');
    drawPoint(1, sy - slope, 'var(--purple)', 'S1 (1)');
    drawPoint(2, sy - 2 * slope, 'var(--green)', 'S2 (2)');
    drawPoint(3, sy - 3 * slope, 'var(--orange)', 'S3 (3)');
  }
};
