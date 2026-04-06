// admin.js — served from /api/admin/ui.js (authentication required)
// Authentication is handled entirely via httpOnly cookie.
// No token is stored in localStorage or any JS-accessible storage.
// All PGP decryption happens server-side — this file never handles key material.
'use strict';

// ── Constants ──────────────────────────────────────────────────────────────
const CSRF_COOKIE = 'csrf_token';
const CSRF_HEADER = 'x-csrf-token';

// ── State ──────────────────────────────────────────────────────────────────
let currentFile   = null;
let currentReport = null; // parsed JSON from decrypted text

// ── CSRF token helper ─────────────────────────────────────────────────────
function getCsrfToken() {
    const match = document.cookie.split(';')
        .map(c => c.trim())
        .find(c => c.startsWith(CSRF_COOKIE + '='));
    return match ? match.split('=')[1] : null;
}

// ── Status bar helper ─────────────────────────────────────────────────────
function setStatus(msg, color) {
    const bar = document.getElementById('status-bar');
    bar.textContent = msg;
    bar.style.color = color || '#555';
}

// ── Auth redirect helper ──────────────────────────────────────────────────
function handleUnauth(status) {
    if (status === 401 || status === 403) {
        window.location.href = '/login.html';
        return true;
    }
    return false;
}

// ── Bytes formatter ───────────────────────────────────────────────────────
function fmtBytes(n) {
    if (!n) return '';
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
}

// ── Extract report ID from filename ──────────────────────────────────────
function extractReportId(filename) {
    // filename format: report_<uuid>.asc
    const match = filename.match(/^report_([0-9a-f-]{36})\.asc$/i);
    return match ? match[1] : null;
}

// =============================================================================
// LOGOUT
// =============================================================================
document.getElementById('logoutBtn').addEventListener('click', async () => {
    const csrf = getCsrfToken();
    try {
        await fetch('/api/logout', {
            method:      'POST',
            credentials: 'include',
            headers:     csrf ? { [CSRF_HEADER]: csrf } : {},
        });
    } catch (_) { /* best-effort */ }
    window.location.href = '/login.html';
});

// =============================================================================
// REPORT LIST
// =============================================================================
async function loadList() {
    try {
        const res = await fetch('/api/admin/list-reports', { credentials: 'include' });
        if (handleUnauth(res.status)) return;

        const files = await res.json();
        const listPanel = document.getElementById('reportList');

        // Preserve header
        const header = listPanel.querySelector('.list-header');
        listPanel.innerHTML = '';
        if (header) listPanel.appendChild(header);

        if (!Array.isArray(files) || !files.length) {
            const empty = document.createElement('div');
            empty.style.cssText = 'padding:20px; color:#444; font-size:0.8rem;';
            empty.textContent = 'NO_REPORTS_FOUND';
            listPanel.appendChild(empty);
            return;
        }

        files.forEach(f => {
            const div = document.createElement('div');
            div.className = 'report-item';
            div.id = 'item-' + CSS.escape(f);
            // textContent — never innerHTML — prevents XSS from filenames
            div.textContent = f;

            const meta = document.createElement('div');
            meta.className = 'report-item-meta';
            // Show only the UUID portion as a short identifier
            const uid = extractReportId(f);
            meta.textContent = uid ? uid.substring(0, 8).toUpperCase() + '...' : '';
            div.appendChild(meta);

            div.addEventListener('click', () => viewReport(f));
            listPanel.appendChild(div);
        });

        setStatus(`${files.length} report(s) in archive. Last refreshed: ${new Date().toLocaleTimeString()}`);
    } catch (err) {
        const errDiv = document.createElement('div');
        errDiv.style.cssText = 'padding:20px; color:red; font-size:0.75rem;';
        errDiv.textContent = 'UPLINK_ERROR: ' + err.message; // textContent — not innerHTML
        const listPanel = document.getElementById('reportList');
        const header = listPanel.querySelector('.list-header');
        listPanel.innerHTML = '';
        if (header) listPanel.appendChild(header);
        listPanel.appendChild(errDiv);
    }
}

// =============================================================================
// VIEW & DECRYPT REPORT
// =============================================================================
async function viewReport(filename) {
    // Highlight active item
    document.querySelectorAll('.report-item').forEach(el => el.classList.remove('active'));
    const activeEl = document.getElementById('item-' + CSS.escape(filename));
    if (activeEl) activeEl.classList.add('active');

    currentFile   = filename;
    currentReport = null;

    const welcomeMsg  = document.getElementById('welcome-msg');
    const contentArea = document.getElementById('content-area');
    const panelTitle  = document.getElementById('view-panel-title');

    welcomeMsg.textContent  = 'DECRYPTING...';
    welcomeMsg.style.display = 'block';
    contentArea.style.display = 'none';
    panelTitle.textContent   = '// DECRYPTING...';
    document.getElementById('adminNotes').value = '';
    document.getElementById('attachment-list').innerHTML =
        '<div style="color:#444; font-size:0.75rem;">LOADING...</div>';

    try {
        const res = await fetch(
            '/api/admin/get-report/' + encodeURIComponent(filename),
            { credentials: 'include' }
        );
        if (handleUnauth(res.status)) return;

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'ACCESS_DENIED');

        welcomeMsg.style.display = 'none';
        contentArea.style.display = 'block';

        // textContent — never innerHTML — prevents XSS from report content
        document.getElementById('meta-info').textContent = 'FILE: ' + filename;
        panelTitle.textContent = '// REPORT: ' + (extractReportId(filename) || filename).toUpperCase();

        // Pretty-print if JSON, otherwise show raw plaintext
        try {
            currentReport = JSON.parse(data.decrypted);
            document.getElementById('decrypted-text').textContent =
                JSON.stringify(currentReport, null, 4);
        } catch (_) {
            document.getElementById('decrypted-text').textContent = data.decrypted;
        }

        // Load attachments
        const reportId = extractReportId(filename);
        if (reportId) {
            await loadAttachments(reportId);
        } else {
            document.getElementById('attachment-list').innerHTML =
                '<div style="color:#444; font-size:0.75rem;">NO_ATTACHMENTS</div>';
        }

    } catch (err) {
        welcomeMsg.textContent = 'ERROR: ' + err.message;
        panelTitle.textContent = '// ERROR';
    }
}

// =============================================================================
// ATTACHMENTS
// =============================================================================
async function loadAttachments(reportId) {
    const container = document.getElementById('attachment-list');
    container.innerHTML = '<div style="color:#444; font-size:0.75rem;">LOADING...</div>';

    try {
        const res = await fetch(
            '/api/admin/list-attachments/' + encodeURIComponent(reportId),
            { credentials: 'include' }
        );
        if (handleUnauth(res.status)) return;

        const files = await res.json();

        if (!Array.isArray(files) || !files.length) {
            container.innerHTML = '<div style="color:#444; font-size:0.75rem;">NO_ATTACHMENTS</div>';
            return;
        }

        container.innerHTML = '';

        files.forEach(f => {
            const entry = document.createElement('div');
            entry.className = 'attachment-entry';

            const info = document.createElement('div');

            const nameEl = document.createElement('div');
            nameEl.className = 'attachment-name';
            nameEl.textContent = f.filename; // textContent — not innerHTML

            const sizeEl = document.createElement('div');
            sizeEl.className = 'attachment-size';
            sizeEl.textContent = fmtBytes(f.size) + ' — ENCRYPTED ON DISK';

            info.appendChild(nameEl);
            info.appendChild(sizeEl);

            const dlBtn = document.createElement('button');
            dlBtn.className = 'download-btn';
            dlBtn.textContent = 'DECRYPT & DOWNLOAD';
            dlBtn.setAttribute('aria-label', 'Download ' + f.filename);
            dlBtn.addEventListener('click', () => downloadAttachment(reportId, f.filename, dlBtn));

            entry.appendChild(info);
            entry.appendChild(dlBtn);
            container.appendChild(entry);
        });

    } catch (err) {
        container.innerHTML =
            '<div style="color:red; font-size:0.75rem;">ATTACHMENT_LOAD_ERROR: ' + err.message + '</div>';
    }
}

async function downloadAttachment(reportId, filename, btn) {
    btn.disabled   = true;
    btn.textContent = 'DECRYPTING...';

    try {
        const res = await fetch(
            '/api/admin/get-attachment/' +
            encodeURIComponent(reportId) + '/' +
            encodeURIComponent(filename),
            { credentials: 'include' }
        );
        if (handleUnauth(res.status)) return;

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || 'DOWNLOAD_FAILED');
        }

        // Stream the response blob and trigger browser download
        const blob = await res.blob();
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');

        // Extract original filename from attachment filename metadata
        // Format: <originalname>_<uuid>.asc
        const metaPart   = filename.replace(/\.asc$/, '');
        const lastUndIdx = metaPart.lastIndexOf('_');
        const origName   = lastUndIdx > 0 ? metaPart.substring(0, lastUndIdx) : metaPart;

        a.href     = url;
        a.download = origName;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);

        // Revoke the object URL after a short delay
        setTimeout(() => URL.revokeObjectURL(url), 3000);

        btn.textContent = 'DOWNLOADED ✓';
        setStatus('Attachment decrypted and downloaded: ' + origName, '#00aa00');
    } catch (err) {
        btn.textContent = 'ERROR';
        setStatus('Attachment download failed: ' + err.message, 'red');
    } finally {
        setTimeout(() => {
            btn.disabled   = false;
            btn.textContent = 'DECRYPT & DOWNLOAD';
        }, 3000);
    }
}

// =============================================================================
// DELETE REPORT (and all attachments)
// =============================================================================
document.getElementById('deleteBtn').addEventListener('click', async () => {
    if (!currentFile) return;
    if (!confirm('CONFIRM PURGE: ' + currentFile + '\n\nThis will permanently delete the report and all associated attachments.')) return;

    const csrf = getCsrfToken();
    const btn  = document.getElementById('deleteBtn');
    btn.disabled   = true;
    btn.textContent = 'PURGING...';

    try {
        const res = await fetch(
            '/api/admin/reports/' + encodeURIComponent(currentFile),
            {
                method:      'DELETE',
                credentials: 'include',
                headers:     csrf ? { [CSRF_HEADER]: csrf } : {},
            }
        );
        if (handleUnauth(res.status)) return;
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || 'DELETE_FAILED');
        }
        setStatus('Report purged: ' + currentFile, 'orange');
        currentFile   = null;
        currentReport = null;
        await loadList();

        // Reset view panel
        document.getElementById('welcome-msg').textContent  = 'SELECT_REPORT_FOR_DECRYPTION';
        document.getElementById('welcome-msg').style.display = 'block';
        document.getElementById('content-area').style.display = 'none';
        document.getElementById('view-panel-title').textContent = '// SELECT REPORT';
    } catch (err) {
        setStatus('Purge failed: ' + err.message, 'red');
        btn.disabled   = false;
        btn.textContent = 'PURGE_REPORT';
    }
});

// =============================================================================
// NOTES (session-only — no persistence to disk unless endpoint added)
// =============================================================================
document.getElementById('saveNotesBtn').addEventListener('click', () => {
    // Notes intentionally session-only. Do not persist to disk without an
    // authenticated, CSRF-protected server endpoint.
    setStatus('NOTES_COMMITTED (session only — ' + new Date().toISOString() + ')', '#555');
});

// =============================================================================
// AUTO-REFRESH every 5 minutes
// =============================================================================
setInterval(loadList, 5 * 60 * 1000);

// =============================================================================
// INIT
// =============================================================================
loadList();