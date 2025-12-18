const ATTRIBUTES = {
    "MA": ["DOCTOR", "NURSE", "RESEARCHER", "CARDIOLOGY", "ONCOLOGY", "SURGERY"],
    "HA": ["STAFF", "NOSTAFF", "CARDIO_DEPT", "ONCO_DEPT", "EMERGENCY", "GEN_HOSP"]
};

document.addEventListener('DOMContentLoaded', () => {
    const log = document.getElementById('log');
    
    // Selectors for Issue Key
    const issueAuth = document.getElementById('key-authority');
    const issueAttr = document.getElementById('key-attribute');
    
    // Selectors for Revoke Key
    const revokeAuth = document.getElementById('revoke-authority');
    const revokeAttr = document.getElementById('revoke-attribute');

    // Populate dropdowns function
    function setupDropdowns(authSelect, attrSelect) {
        authSelect.innerHTML = '<option value="MA">Medical Authority (MA)</option><option value="HA">Hospital Authority (HA)</option>';
        
        function updateAttrs() {
            const selected = authSelect.value;
            const attrs = ATTRIBUTES[selected];
            attrSelect.innerHTML = '';
            attrs.forEach(a => {
                const opt = document.createElement('option');
                opt.value = a;
                opt.textContent = a;
                attrSelect.appendChild(opt);
            });
        }
        authSelect.addEventListener('change', updateAttrs);
        updateAttrs(); // Init
    }

    // Setup both panels
    setupDropdowns(issueAuth, issueAttr);
    setupDropdowns(revokeAuth, revokeAttr);

    function logMessage(msg, type = 'info') {
        const color = type === 'error' ? '#ff8a8a' : '#0f0';
        log.innerHTML += `<span style="color: ${color};">[${new Date().toLocaleTimeString()}] ${msg}</span>\n`;
        log.scrollTop = log.scrollHeight;
    }

    // 1. Register
    document.getElementById('form-register').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('reg-username').value;
        const gid = document.getElementById('reg-gid').value;
        try {
            const res = await fetch('/api/register_user', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ username, gid })
            });
            const d = await res.json();
            if(!res.ok) throw new Error(d.error);
            logMessage(d.message);
        } catch(err) { logMessage(err.message, 'error'); }
    });

    // 2. Issue Key
    document.getElementById('form-issue-key').addEventListener('submit', async (e) => {
        e.preventDefault();
        const gid = document.getElementById('key-gid').value;
        const auth = issueAuth.value;
        const attr = issueAttr.value;
        logMessage(`Issuing key '${attr}' from ${auth}...`);
        try {
            const res = await fetch('/api/issue_key', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ gid, authority_id: auth, attribute: attr })
            });
            const d = await res.json();
            if(!res.ok) throw new Error(d.error);
            logMessage(d.message);
        } catch(err) { logMessage(err.message, 'error'); }
    });

    // 3. Upload
    document.getElementById('form-upload').addEventListener('submit', async (e) => {
        e.preventDefault();
        const fileInput = document.getElementById('upload-file');
        if(fileInput.files.length === 0) return;
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('policy', document.getElementById('upload-policy').value);
        formData.append('filename', fileInput.files[0].name);
        logMessage("Uploading and Encrypting...");
        try {
            const res = await fetch('/api/upload_ehr', { method: 'POST', body: formData });
            const d = await res.json();
            if(!res.ok) throw new Error(d.error);
            logMessage(`SUCCESS: File ID is ${d.file_id}`);
            document.getElementById('download-file-id').value = d.file_id;
        } catch(err) { logMessage(err.message, 'error'); }
    });

    // 4. Download
    document.getElementById('form-download').addEventListener('submit', async (e) => {
        e.preventDefault();
        const fid = document.getElementById('download-file-id').value;
        const gid = document.getElementById('download-gid').value;
        logMessage(`Attempting download for File ${fid}...`);
        try {
            const res = await fetch(`/api/download_ehr/${fid}`, {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ gid })
            });
            if(!res.ok) { const d = await res.json(); throw new Error(d.error); }
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; 
            // Try to get filename from header or default
            a.download = 'downloaded_file'; 
            document.body.appendChild(a); a.click(); a.remove();
            logMessage("SUCCESS: Download started.");
        } catch(err) { logMessage(err.message, 'error'); }
    });

    // 5. Revoke (NEW)
    document.getElementById('form-revoke').addEventListener('submit', async (e) => {
        e.preventDefault();
        const gid = document.getElementById('revoke-gid').value;
        const auth = revokeAuth.value;
        const attr = revokeAttr.value;
        logMessage(`REVOKING key '${attr}' from ${gid}...`, 'error');
        try {
            const res = await fetch('/api/revoke_key', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ gid, authority_id: auth, attribute: attr })
            });
            const d = await res.json();
            if(!res.ok) throw new Error(d.error);
            logMessage(d.message);
        } catch(err) { logMessage(err.message, 'error'); }
    });
});
