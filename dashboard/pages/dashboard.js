// Live Dashboard Module

export function render() {
    return `
        <div class="dashboard-grid">
            <div class="panel">
                <h3 class="gauge-label">Server A (Primary Base)</h3>
                <div class="gauge-role" id="dash-role-a">Status: Unknown</div>
                <div class="gauge-container" style="margin-top: 20px;">
                    <div id="dash-gauge-a" class="gauge-circle safe">0.00</div>
                    <div class="mono" style="color: var(--text-muted)">Anomaly Score</div>
                </div>
                <div id="dash-signals-a" class="mono" style="font-size: 0.8rem; margin-top: 15px; color: var(--text-muted)"></div>
            </div>
            <div class="panel">
                <h3 class="gauge-label">Server B (Standby Base)</h3>
                <div class="gauge-role" id="dash-role-b">Status: Unknown</div>
                <div class="gauge-container" style="margin-top: 20px;">
                    <div id="dash-gauge-b" class="gauge-circle safe">0.00</div>
                    <div class="mono" style="color: var(--text-muted)">Anomaly Score</div>
                </div>
                <div id="dash-signals-b" class="mono" style="font-size: 0.8rem; margin-top: 15px; color: var(--text-muted)"></div>
            </div>
        </div>
        <div class="panel dashboard-full">
            <h3 class="gauge-label">System Meta</h3>
            <div class="mono" style="margin-top: 15px; font-size: 0.9rem;">
                <p><strong>Threat Threshold (Theta):</strong> 0.55</p>
                <p><strong>XChaCha20 Keystream:</strong> Reactive Ratcheting Enabled</p>
                <p><strong>Record Count:</strong> <span id="dash-records">0</span></p>
            </div>
        </div>
    `;
}

export function init() {
    // Listen for global ticks
    document.addEventListener('hydra:tick', handleTick);
}

function handleTick(e) {
    // Ensure we are still on this page
    const gaugeA = document.getElementById('dash-gauge-a');
    if (!gaugeA) {
        document.removeEventListener('hydra:tick', handleTick);
        return;
    }

    const { statusA, statusB } = e.detail;

    updateServerUI('a', statusA);
    updateServerUI('b', statusB);

    const records = (statusA && statusA.record_count) || (statusB && statusB.record_count) || 0;
    document.getElementById('dash-records').textContent = records;
}

function updateServerUI(id, status) {
    const gauge = document.getElementById(`dash-gauge-${id}`);
    const roleEl = document.getElementById(`dash-role-${id}`);
    const signalsEl = document.getElementById(`dash-signals-${id}`);

    if (!status) {
        gauge.textContent = '---';
        gauge.className = 'gauge-circle';
        roleEl.textContent = 'Status: OFFLINE';
        return;
    }

    const score = status.score.toFixed(2);
    gauge.textContent = score;

    // Update color based on score (Theta = 0.55)
    if (status.is_breach || status.ratcheting) {
        gauge.className = 'gauge-circle breach';
    } else if (status.score >= 0.35) {
        gauge.className = 'gauge-circle warn';
    } else {
        gauge.className = 'gauge-circle safe';
    }

    let roleText = `Role: ${status.role.toUpperCase()}`;
    if (status.isolated) roleText += ' (ISOLATED)';
    roleEl.textContent = roleText;

    signalsEl.innerHTML = `Epoch: ${status.epoch} | Uptime: ${Math.floor(status.uptime_seconds)}s`;
}
