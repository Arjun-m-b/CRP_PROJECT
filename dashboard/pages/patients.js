/**
 * patients.js — Patient Records Module
 */
window.HYDRA_PAGES = window.HYDRA_PAGES || {};

window.HYDRA_PAGES.patients = {
  cleanup: () => HYDRA.pollStop('patients'),

  render: (container) => {
    container.innerHTML = `
      <div class="card">
        <div class="card-title flex justify-between items-center">
          <span>◉ ENCRYPTED PATIENT RECORDS</span>
          <div>
            <button class="btn btn-primary btn-sm" onclick="HYDRA_PAGES.patients.addRecord()">➕ Add Record</button>
            <button class="btn btn-primary btn-sm" onclick="HYDRA_PAGES.patients.refresh()">↻ Refresh</button>
            <button class="btn btn-ghost btn-sm" onclick="HYDRA.navigateTo('crypto')">Key Explorer →</button>
          </div>
        </div>
        
        <div class="search-bar mt-16">
          <span class="search-icon">⚲</span>
          <input type="text" id="patient-search" placeholder="Search by Record ID or tag prefix..." oninput="HYDRA_PAGES.patients.filter()">
        </div>

        <div style="overflow-x: auto;">
          <table class="data-table">
            <thead>
              <tr>
                <th>Record ID</th>
                <th>Epoch</th>
                <th>Timestamp</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="patients-tbody">
              <tr><td colspan="4" class="text-center" style="padding: 40px; color: var(--text-3);">Loading records...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    `;

    HYDRA_PAGES.patients.refresh();
    HYDRA.pollStart('patients', HYDRA_PAGES.patients.refresh, 5000);
  },

  addRecord: async () => {
    const text = prompt("Enter patient record JSON or text:");
    if (!text) return;
    try {
      const b64 = btoa(text);
      const res = await HYDRA.apiPost('/store_payload', { payload_b64: b64 });
      if (res.status === 'ok') {
        alert(`Record added successfully! ID: ${res.record_id}`);
        HYDRA_PAGES.patients.refresh();
      } else {
        alert(`Error adding record: ${res.error}`);
      }
    } catch (e) {
      alert(`Failed to add record: ${e.message}`);
    }
  },

  deleteRecord: async (recordId) => {
    if (!confirm(`Are you sure you want to delete ${recordId}?`)) return;
    try {
      const res = await HYDRA.apiPost('/delete_record', { record_id: recordId });
      if (res.status === 'ok') {
        alert(`Deleted ${recordId}`);
        HYDRA_PAGES.patients.refresh();
      } else {
        alert(`Error deleting record: ${res.error}`);
      }
    } catch (e) {
      alert(`Failed to delete record: ${e.message}`);
    }
  },

  refresh: async () => {
    try {
      const data = await HYDRA.apiGet('/fetch/all');
      if (data?.status === 'ok') {
        window.HYDRA_PATIENTS_CACHE = data.records;
        HYDRA_PAGES.patients.renderTable(data.records);
      }
    } catch (e) {
      document.getElementById('patients-tbody').innerHTML = `
        <tr><td colspan="4" class="text-center text-red" style="padding: 40px;">Failed to load records: ${e.message}</td></tr>
      `;
    }
  },

  filter: () => {
    const q = document.getElementById('patient-search').value.toLowerCase();
    const cache = window.HYDRA_PATIENTS_CACHE || [];
    if (!q) {
      HYDRA_PAGES.patients.renderTable(cache);
      return;
    }
    const filtered = cache.filter(r =>
      (r.id || '').toLowerCase().includes(q)
    );
    HYDRA_PAGES.patients.renderTable(filtered);
  },

  renderTable: (records) => {
    const tbody = document.getElementById('patients-tbody');
    if (!tbody) return;

    if (!records || records.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" class="text-center text-dim" style="padding: 40px;">No encrypted records found.</td></tr>`;
      return;
    }

    // Sort by timestamp desc
    records.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));

    tbody.innerHTML = records.map(r => `
      <tr>
        <td class="mono" style="color:var(--text-1); font-weight:600;">${r.id}</td>
        <td>
          <span class="tag tag-primary">EPOCH ${r.epoch}</span>
        </td>
        <td class="mono text-dim" style="font-size:10px;">${HYDRA.formatTime(r.created_at * 1000)}</td>
        <td>
          <button class="btn btn-ghost btn-sm" onclick="HYDRA_PAGES.record.openModal('${r.id}')">Inspect</button>
          <button class="btn btn-ghost btn-sm text-red" style="color: #ff4444;" onclick="HYDRA_PAGES.patients.deleteRecord('${r.id}')">Delete</button>
        </td>
      </tr>
    `).join('');
  }
};
