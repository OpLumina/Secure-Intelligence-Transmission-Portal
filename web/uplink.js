'use strict';
// ============================================================================
// DIRMAP UPLINK — Client-Side Report Submission Script
// STIG SRG-APP-000251: Input validation on all fields before encryption.
// STIG V-222397:       Prevent double-submission.
// ============================================================================

// ---- Constants ----
const MAX_TEXT_LEN    = 20000;
const MAX_FILES       = 3;
const MAX_FILE_BYTES  = 10 * 1024 * 1024;
const CSRF_COOKIE     = 'csrf_token';
const CSRF_HEADER     = 'x-csrf-token';

// ---- State ----
let myPubKey      = null;
let selectedFiles = []; // Array<File>

// ---- DOM refs (assigned after DOMContentLoaded) ----
let submitBtn, encStatus, fileInput, fileDropZone, fileList,
    intelArea, intelCounter, progressWrap, progressFill,
    progressLabel, attachNotice;

// ---- Helpers ----

/**
 * Sanitize a string against XSS (HTML entity encoding).
 * STIG SRG-APP-000251.
 */
function sanitize(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;')
        .trim();
}

/** Read the CSRF token from the cookie set by the server. */
function getCsrfToken() {
    const match = document.cookie.split(';')
        .map(c => c.trim())
        .find(c => c.startsWith(CSRF_COOKIE + '='));
    return match ? match.split('=')[1] : null;
}

/** Format bytes as human-readable string. */
function fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
}

/** Allowed file extensions (enforced client-side — server also validates). */
const ALLOWED_EXT = new Set(['.pdf','.jpg','.jpeg','.png','.gif','.webp','.txt','.zip','.7z','.tar','.gz']);

function getExt(name) {
    const idx = name.lastIndexOf('.');
    return idx >= 0 ? name.substring(idx).toLowerCase() : '';
}

// ============================================================================
// PGP KEY LOADING
// ============================================================================
async function loadPublicKey() {
    try {
        const res = await fetch('/pgp/pub/dirtmap_public.asc');
        if (!res.ok) throw new Error('Key fetch failed: ' + res.status);
        myPubKey = await res.text();
        if (!myPubKey.includes('BEGIN PGP PUBLIC KEY')) {
            throw new Error('Response is not a PGP public key block');
        }
        encStatus.textContent = 'ENC: READY \u2713';
        encStatus.classList.add('ready');
        submitBtn.disabled = false;
        submitBtn.textContent = 'TRANSMIT ENCRYPTED REPORT';
        console.log('[STIG_AUDIT] PGP Public Key loaded and verified.');
    } catch (err) {
        encStatus.textContent = 'ENC: OFFLINE \u2717';
        submitBtn.textContent = 'ENCRYPTION OFFLINE \u2014 CANNOT SUBMIT';
        console.error('[SECURITY_ALERT] Could not load encryption key:', err.message);
    }
}

// ============================================================================
// CHARACTER COUNTER
// ============================================================================
function initCharCounter() {
    intelArea.addEventListener('input', () => {
        const len = intelArea.value.length;
        intelCounter.textContent = len.toLocaleString() + ' / ' + MAX_TEXT_LEN.toLocaleString();
        intelCounter.className = 'char-counter';
        if (len > MAX_TEXT_LEN * 0.9) intelCounter.classList.add('warn');
        if (len >= MAX_TEXT_LEN)       intelCounter.classList.add('over');
    });
}

// ============================================================================
// DYNAMIC SUBJECT ENTITY FIELDS
// ============================================================================
function addSubjectField() {
    if (document.querySelectorAll('.dynamic-item').length >= 20) {
        alert('Maximum 20 subject entities per report.');
        return;
    }
    const container = document.getElementById('dynamic-list');
    const div = document.createElement('div');
    div.className = 'dynamic-item';
    div.setAttribute('role', 'listitem');

    // Build with individual elements — no innerHTML with user data
    const select = document.createElement('select');
    select.className = 'item-type';
    select.setAttribute('aria-label', 'Entity type');
    [
        ['AGENCY',        'AGENCY NAME'],
        ['INDIVIDUAL',    'INDIVIDUAL NAME'],
        ['ADDRESS',       'PHYSICAL ADDRESS'],
        ['VEHICLE',       'VEHICLE / ASSET'],
        ['ORGANIZATION',  'ORGANIZATION'],
        ['PHONE',         'PHONE NUMBER'],
        ['EMAIL',         'EMAIL ADDRESS'],
        ['USERNAME',      'USERNAME / HANDLE'],
    ].forEach(([val, lbl]) => {
        const opt = document.createElement('option');
        opt.value = val;
        opt.textContent = lbl;
        select.appendChild(opt);
    });

    const valInput = document.createElement('input');
    valInput.type = 'text';
    valInput.className = 'item-value';
    valInput.placeholder = 'Identity / Details';
    valInput.maxLength = 512;
    valInput.setAttribute('aria-label', 'Entity value');

    const ctxInput = document.createElement('input');
    ctxInput.type = 'text';
    ctxInput.className = 'item-context';
    ctxInput.placeholder = 'Context';
    ctxInput.maxLength = 512;
    ctxInput.setAttribute('aria-label', 'Entity context');

    const removeBtn = document.createElement('button');
    removeBtn.type = 'button';
    removeBtn.className = 'remove-btn';
    removeBtn.textContent = '\u00d7';
    removeBtn.setAttribute('aria-label', 'Remove entity');
    removeBtn.addEventListener('click', () => div.remove());

    div.appendChild(select);
    div.appendChild(valInput);
    div.appendChild(ctxInput);
    div.appendChild(removeBtn);
    container.appendChild(div);
}

// ============================================================================
// FILE DROP ZONE
// ============================================================================
function initFileDropZone() {
    fileDropZone.addEventListener('click', (e) => {
        if (e.target !== fileInput) fileInput.click();
    });

    fileInput.addEventListener('change', () => {
        addFiles(Array.from(fileInput.files));
        fileInput.value = '';
    });

    fileDropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        fileDropZone.classList.add('drag-over');
    });
    fileDropZone.addEventListener('dragleave', () => {
        fileDropZone.classList.remove('drag-over');
    });
    fileDropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        fileDropZone.classList.remove('drag-over');
        addFiles(Array.from(e.dataTransfer.files));
    });
}

function addFiles(incoming) {
    const warnings = [];
    for (const file of incoming) {
        if (selectedFiles.length >= MAX_FILES) {
            warnings.push('Maximum ' + MAX_FILES + ' files \u2014 "' + file.name + '" skipped.');
            continue;
        }
        if (file.size > MAX_FILE_BYTES) {
            warnings.push('"' + file.name + '" exceeds 10 MB size limit and was skipped.');
            continue;
        }
        const ext = getExt(file.name);
        if (!ALLOWED_EXT.has(ext)) {
            warnings.push('"' + file.name + '" has a disallowed extension (' + (ext || 'none') + ') and was skipped.');
            continue;
        }
        if (selectedFiles.some(f => f.name === file.name && f.size === file.size)) {
            warnings.push('"' + file.name + '" is already in the list.');
            continue;
        }
        selectedFiles.push(file);
    }
    renderFileList();
    if (warnings.length) alert(warnings.join('\n'));
}

function removeFile(idx) {
    selectedFiles.splice(idx, 1);
    renderFileList();
}

function renderFileList() {
    fileList.innerHTML = '';
    if (selectedFiles.length === 0) {
        fileList.classList.remove('visible');
        fileDropZone.classList.remove('has-files');
        attachNotice.style.display = 'none';
        return;
    }

    fileList.classList.add('visible');
    fileDropZone.classList.add('has-files');
    attachNotice.style.display = 'block';

    const heading = document.createElement('h4');
    heading.textContent = 'STAGED ATTACHMENTS (' + selectedFiles.length + '/' + MAX_FILES + ') \u2014 ENCRYPTED BEFORE TRANSMISSION';
    fileList.appendChild(heading);

    selectedFiles.forEach((file, idx) => {
        const entry = document.createElement('div');
        entry.className = 'file-entry';
        entry.setAttribute('role', 'listitem');

        const info = document.createElement('div');
        info.className = 'file-entry-info';

        const nameEl = document.createElement('div');
        nameEl.className = 'file-entry-name';
        nameEl.textContent = file.name; // textContent prevents XSS

        const metaEl = document.createElement('div');
        metaEl.className = 'file-entry-meta';
        metaEl.textContent = fmtBytes(file.size) + ' \u00b7 ' + (file.type || 'unknown type');

        info.appendChild(nameEl);
        info.appendChild(metaEl);

        const removeBtn = document.createElement('button');
        removeBtn.type = 'button';
        removeBtn.className = 'file-entry-remove';
        removeBtn.textContent = '\u2715';
        removeBtn.setAttribute('aria-label', 'Remove ' + file.name);
        removeBtn.addEventListener('click', () => removeFile(idx));

        entry.appendChild(info);
        entry.appendChild(removeBtn);
        fileList.appendChild(entry);
    });

    if (selectedFiles.length < MAX_FILES) {
        const remaining = document.createElement('div');
        remaining.className = 'file-warn';
        remaining.textContent = (MAX_FILES - selectedFiles.length) + ' attachment slot(s) remaining';
        fileList.appendChild(remaining);
    }
}

// ============================================================================
// FORM SUBMISSION & ENCRYPTION
// ============================================================================
async function handleEncryption() {
    if (submitBtn.disabled) return;
    if (!myPubKey) {
        alert('SECURITY ERROR: Encryption module offline. Refresh and try again.');
        return;
    }

    // ---- Validation ----
    const rawIntel   = intelArea.value.trim();
    const rawCountry = document.getElementById('country').value.trim();
    const rawCity    = document.getElementById('city').value.trim();
    const rawCat     = document.getElementById('category').value;

    if (!rawCountry) { document.getElementById('country').focus(); alert('REQUIRED: Country of Report'); return; }
    if (!rawCity)    { document.getElementById('city').focus();    alert('REQUIRED: City / Locality');   return; }
    if (!rawCat)     { document.getElementById('category').focus();alert('REQUIRED: Report Category');   return; }
    if (!rawIntel)   { intelArea.focus();                          alert('REQUIRED: Intel Briefing');     return; }
    if (rawIntel.length > MAX_TEXT_LEN) {
        alert('Intel briefing exceeds ' + MAX_TEXT_LEN.toLocaleString() + ' character limit.');
        return;
    }

    // ---- Lock UI ----
    submitBtn.disabled    = true;
    submitBtn.textContent = 'PROCESSING...';
    progressWrap.classList.add('visible');
    setProgress(10, 'READING ENCRYPTION KEY...');

    try {
        // ---- Build report data object ----
        const reportID = 'REP-' + crypto.getRandomValues(new Uint8Array(6))
            .reduce((acc, b) => acc + b.toString(16).padStart(2, '0'), '')
            .toUpperCase();

        const urgency = (document.querySelector('input[name="urgency"]:checked') || {}).value || 'ROUTINE';

        const data = {
            report_no: reportID,
            urgency,
            category:  sanitize(rawCat),
            metadata: {
                name:            sanitize(document.getElementById('name').value) || 'ANON',
                phone:           sanitize(document.getElementById('phone').value),
                email:           sanitize(document.getElementById('email').value),
                other:           sanitize(document.getElementById('other').value),
                location: {
                    country: sanitize(rawCountry),
                    city:    sanitize(rawCity),
                },
                subject:         sanitize(document.getElementById('subject').value),
                previous_ref:    sanitize(document.getElementById('prev_report').value),
                src_reliability: sanitize(document.getElementById('src-reliability').value),
                src_credibility: sanitize(document.getElementById('src-credibility').value),
            },
            intel_body:        sanitize(rawIntel),
            subject_entities:  [],
            attachments_count: selectedFiles.length,
            timestamp:         new Date().toISOString(),
        };

        // Collect subject entities
        document.querySelectorAll('.dynamic-item').forEach(item => {
            const val = item.querySelector('.item-value') && item.querySelector('.item-value').value.trim();
            const ctx = item.querySelector('.item-context') && item.querySelector('.item-context').value.trim();
            if (val) {
                data.subject_entities.push({
                    category: (item.querySelector('.item-type') || {}).value || 'OTHER',
                    identity: sanitize(val),
                    context:  sanitize(ctx) || 'No additional context',
                });
            }
        });

        // ---- Encrypt report JSON with server's public key ----
        setProgress(30, 'ENCRYPTING REPORT...');
        const publicKey = await openpgp.readKey({ armoredKey: myPubKey });
        const encrypted = await openpgp.encrypt({
            message:        await openpgp.createMessage({ text: JSON.stringify(data, null, 2) }),
            encryptionKeys: publicKey,
        });

        // ---- Encrypt attachments client-side before transmission ----
        // Each file is encrypted in-browser with the server's public key.
        // Node never receives plaintext file data \u2014 same trust model as report text.
        setProgress(60, 'ENCRYPTING ATTACHMENTS...');
        const csrf = getCsrfToken();
        if (!csrf) throw new Error('CSRF_TOKEN_MISSING \u2014 refresh and retry');

        const formData = new FormData();
        formData.append('payload', encrypted);

        for (const file of selectedFiles) {
            // Read file as binary and encrypt with server public key
            const fileBuffer = await file.arrayBuffer();
            const uint8 = new Uint8Array(fileBuffer);
            const encryptedAttachment = await openpgp.encrypt({
                message:        await openpgp.createMessage({ binary: uint8 }),
                encryptionKeys: publicKey,
                format:         'armored',
            });
            // Send as .asc blob \u2014 server validates it is a valid PGP message
            const ascBlob = new Blob([encryptedAttachment], { type: 'application/octet-stream' });
            formData.append('files[]', ascBlob, file.name + '.asc');
        }

        setProgress(75, 'TRANSMITTING...');
        const response = await fetch('/api/submit-intel', {
            method:      'POST',
            credentials: 'same-origin',
            headers:     { [CSRF_HEADER]: csrf },
            body:        formData,
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || 'SERVER_REJECTED (' + response.status + ')');
        }

        setProgress(100, 'TRANSMISSION COMPLETE');

        // ---- Scrub form ----
        document.getElementById('pgpForm').reset();
        document.getElementById('dynamic-list').innerHTML = '';
        selectedFiles = [];
        renderFileList();
        intelCounter.textContent = '0 / 20,000';

        // ---- Show confirmation ----
        document.getElementById('report-num-display').textContent = reportID;
        document.getElementById('report-modal').classList.add('visible');

        submitBtn.textContent = 'TRANSMISSION SUCCESSFUL';
        setTimeout(() => {
            submitBtn.disabled    = false;
            submitBtn.textContent = 'TRANSMIT ENCRYPTED REPORT';
            progressWrap.classList.remove('visible');
        }, 4000);

        console.log('[STIG_AUDIT] Secure transmission successful. Report ID:', reportID);

    } catch (err) {
        console.error('[STIG_AUDIT] UPLINK FAILURE:', err.message);
        progressWrap.classList.remove('visible');
        alert('UPLINK FAILURE: ' + err.message);
        submitBtn.disabled    = false;
        submitBtn.textContent = 'TRANSMIT ENCRYPTED REPORT';
    }
}

function setProgress(pct, label) {
    progressFill.style.width  = pct + '%';
    progressLabel.textContent = label;
}

// ============================================================================
// INIT
// ============================================================================
window.addEventListener('DOMContentLoaded', () => {
    // Assign DOM refs
    submitBtn    = document.getElementById('submitBtn');
    encStatus    = document.getElementById('enc-status');
    fileInput    = document.getElementById('file-input');
    fileDropZone = document.getElementById('file-drop-zone');
    fileList     = document.getElementById('file-list');
    intelArea    = document.getElementById('intel');
    intelCounter = document.getElementById('intel-counter');
    progressWrap = document.getElementById('progress-bar-wrap');
    progressFill = document.getElementById('progress-fill');
    progressLabel = document.getElementById('progress-label');
    attachNotice = document.getElementById('attach-enc-notice');

    // Wire up modal acknowledge button
    document.getElementById('modalAcknowledge').addEventListener('click', () => {
        document.getElementById('report-modal').classList.remove('visible');
    });

    // Wire up add subject button
    document.getElementById('addSubjectBtn').addEventListener('click', addSubjectField);

    // Wire up submit button
    submitBtn.addEventListener('click', handleEncryption);

    // Init subsystems
    initCharCounter();
    initFileDropZone();

    // Ensure CSRF token cookie is set before any submission attempt
    fetch('/api/csrf', { credentials: 'include' }).catch(() => {
        console.warn('[SECURITY] Could not fetch CSRF token.');
    });

    // Load the public key
    loadPublicKey();
});