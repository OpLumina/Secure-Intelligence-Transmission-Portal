// login.js — loaded as an external script so CSP can drop 'unsafe-inline'
// Token is delivered as an httpOnly cookie by the server.
// This script never touches, stores, or reads any token value.

'use strict';

const CSRF_COOKIE = 'csrf_token';
const CSRF_HEADER = 'x-csrf-token';

function getCsrfToken() {
    const match = document.cookie.split(';')
        .map(c => c.trim())
        .find(c => c.startsWith(CSRF_COOKIE + '='));
    return match ? match.split('=')[1] : null;
}

// Ensure CSRF cookie is set before the user can submit.
// Calls /api/csrf which issues the cookie if not already present.
async function ensureCsrfToken() {
    try {
        await fetch('/api/csrf', { credentials: 'include' });
    } catch (_) {
        // Non-fatal — submission will fail with CSRF error if cookie missing
        console.warn('[SECURITY] Could not fetch CSRF token.');
    }
}

document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const status   = document.getElementById('status');
    const btn      = document.getElementById('authBtn');
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    if (!username || !password) {
        status.textContent = 'ERROR: CREDENTIALS_REQUIRED';
        return;
    }

    status.textContent = 'VERIFYING_CREDENTIALS...';
    btn.disabled = true;

    const csrf = getCsrfToken();
    if (!csrf) {
        status.textContent = 'ERROR: CSRF_TOKEN_MISSING — REFRESH AND RETRY';
        btn.disabled = false;
        return;
    }

    try {
        const response = await fetch('/api/login', {
            method:      'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                [CSRF_HEADER]:  csrf,
            },
            body: JSON.stringify({ username, password }),
        });

        if (response.ok) {
            status.textContent = 'ACCESS_GRANTED. REDIRECTING...';
            window.location.href = '/admin';
        } else {
            const data = await response.json().catch(() => ({}));
            if (data.error === 'ACCOUNT_LOCKED_TEMPORARY') {
                status.textContent = 'ERROR: ACCOUNT_LOCKED. TRY_AGAIN_LATER.';
            } else {
                status.textContent = 'ERROR: UNAUTHORIZED_ACCESS_DENIED';
            }
            btn.disabled = false;
        }
    } catch (_) {
        status.textContent = 'ERROR: GATEWAY_OFFLINE';
        btn.disabled = false;
    }
});

// Fetch CSRF token immediately on page load
window.addEventListener('DOMContentLoaded', ensureCsrfToken);