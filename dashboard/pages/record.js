/**
 * record.js — Single Record Inspector Modal
 */
window.HYDRA_PAGES = window.HYDRA_PAGES || {};

window.HYDRA_PAGES.record = {

  openModal: async (recordId) => {
    HYDRA.modalOpen(`Record: ${recordId}`, `<div class="loading-row"><span class="loading-spinner"></span> Retrieving encrypted blob...</div>`);

    try {
      const data = await HYDRA.apiGet(`/fetch/${recordId}`);
      if (data?.status === 'ok') {
        // API returns fields flat in the response (not nested under .record)
        const rec = data;

        // Format hex dumps beautifully
        const formatHex = (hex) => {
          if (!hex) return '';
          let out = '';
          for (let i = 0; i < hex.length; i += 32) {
            const chunk = hex.substr(i, 32);
            const offset = (i / 2).toString(16).padStart(4, '0');
            let hexBytes = '';
            for (let j = 0; j < chunk.length; j += 2) {
              hexBytes += `<span class="hex-byte">${chunk.substr(j, 2)}</span> `;
            }
            out += `<span class="hex-offset">0x${offset}</span> <span class="hex-sep">|</span> ${hexBytes}\n`;
          }
          return out;
        };

        const html = `
          <div style="display:flex; gap: 20px; flex-wrap: wrap;">
            
            <div style="flex: 1; min-width: 280px;">
              <div class="section-header">
                <span class="section-title">METADATA</span>
                <span class="tag tag-primary">EPOCH ${rec.epoch}</span>
              </div>
              
              <div class="stat-box mb-16">
                <div class="stat-box-label">Record ID</div>
                <div class="stat-box-val mono" style="font-size:14px;">${rec.record_id}</div>
              </div>
              
              <div class="stat-box mb-16">
                <div class="stat-box-label">Created At</div>
                <div class="stat-box-val mono" style="font-size:14px;">${new Date(rec.created_at * 1000).toLocaleString()}</div>
              </div>
              
              <div class="stat-box mb-16">
                <div class="stat-box-label">XChaCha20 Nonce (24 bytes)</div>
                <div class="hex-dump mt-8" style="min-height:auto;">${formatHex(rec.nonce)}</div>
              </div>

              <div class="stat-box">
                <div class="stat-box-label">BLAKE2s MAC Tag (32 bytes)</div>
                <div class="hex-dump mt-8" style="min-height:auto; color:var(--purple);">${formatHex(rec.mac_tag).replace(/hex-byte/g, 'hex-byte text-purple')}</div>
              </div>
            </div>
            
            <div style="flex: 2; min-width: 320px;">
              <div class="section-header">
                <span class="section-title">CIPHERTEXT PAYLOAD</span>
                <span class="section-badge">${(rec.ciphertext.length / 2).toLocaleString()} bytes</span>
              </div>
              
              <div class="hex-dump" style="height: 400px; max-height: 50vh;">${formatHex(rec.ciphertext)}</div>
            </div>
            
          </div>
          
          <div class="mt-16" style="padding-top:16px; border-top:1px solid var(--border); text-align:right;">
            <button class="btn btn-ghost" onclick="HYDRA.modalClose()">Close</button>
            <button class="btn btn-primary" onclick="HYDRA_PAGES.record.simulateDecrypt('${rec.record_id}')">Simulate Decryption (Token Req)</button>
          </div>
        `;
        HYDRA.modalOpen(`INSPECT: ${recordId}`, html);
      } else {
        throw new Error(data?.message || 'Failed to fetch');
      }
    } catch (e) {
      HYDRA.modalOpen(`Error: ${recordId}`, `
        <div class="empty-state">
          <div class="empty-icon text-red">✕</div>
          <div class="empty-msg text-red">${e.message}</div>
        </div>
      `);
    }
  },

  simulateDecrypt: (recordId) => {
    HYDRA.toast('Decryption requires client token (Share 3). Simulation only.', 'warn');
  }
};
