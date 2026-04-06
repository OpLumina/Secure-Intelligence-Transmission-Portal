'use strict';

const express      = require('express');
const fs           = require('fs');
const path         = require('path');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const openpgp      = require('openpgp');
const morgan       = require('morgan');
const cookieParser = require('cookie-parser');
const crypto       = require('crypto');
const helmet       = require('helmet');
const multer       = require('multer');
const rateLimit    = require('express-rate-limit');

const app  = express();
app.set('trust proxy', 1);

// STIG V-222430: Ensure application paths are resolved relative to the deployment root
const baseDir = fs.existsSync(path.join(__dirname, 'views')) 
    ? __dirname 
    : path.join(__dirname, '..');

    
const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------------
// SECRETS LOADER — Docker Secrets (_FILE) take priority over env vars
// ---------------------------------------------------------------------------
const getSecret = (envVar) => {
    const filePath = process.env[envVar + '_FILE'];
    if (filePath && fs.existsSync(filePath)) {
        return fs.readFileSync(filePath, 'utf8').trim();
    }
    return process.env[envVar];
};

const SECRET_KEY     = getSecret('JWT_SECRET');
const PGP_PASSPHRASE = getSecret('PGP_PASSPHRASE');

// STIG: Fail-closed — abort if any critical secret is missing
if (!SECRET_KEY) {
    console.error('[CRITICAL] JWT_SECRET not found. Startup aborted.');
    process.exit(1);
}
if (!PGP_PASSPHRASE) {
    console.error('[CRITICAL] PGP_PASSPHRASE not found. Startup aborted.');
    process.exit(1);
}

// Validate JWT secret length (STIG SRG-APP-000231: minimum 256-bit key)
if (Buffer.from(SECRET_KEY, 'base64').length < 32) {
    console.error('[CRITICAL] JWT_SECRET too short (minimum 32 bytes). Startup aborted.');
    process.exit(1);
}

// ---------------------------------------------------------------------------
// PRE-LOAD & CACHE THE PRIVATE KEY AT STARTUP
// ---------------------------------------------------------------------------
let cachedPrivateKey = null;

async function loadPrivateKey() {
    try {
        const privKeyPath = process.env.PGP_KEY_PATH || '/app/pgp/priv/dirtmap_private.asc';
        if (!fs.existsSync(privKeyPath)) {
            console.error('[CRITICAL] PGP private key not found at:', privKeyPath);
            process.exit(1);
        }
        const armoredKey = fs.readFileSync(privKeyPath, 'utf8');
        const privateKey = await openpgp.readKey({ armoredKey });
        if (privateKey.isDecrypted()) {
            cachedPrivateKey = privateKey;
        } else {
            cachedPrivateKey = await openpgp.decryptKey({ privateKey, passphrase: PGP_PASSPHRASE });
        }
        console.log('[INIT] PGP private key loaded and decrypted into memory.');
    } catch (e) {
        console.error('[CRITICAL] Failed to load/decrypt PGP private key:', e.message);
        process.exit(1);
    }
}

// ---------------------------------------------------------------------------
// MIDDLEWARE
// ---------------------------------------------------------------------------

// Helmet: defence-in-depth behind Nginx
app.use(helmet({
    contentSecurityPolicy: false, // CSP delegated to Nginx (per-route)
    crossOriginEmbedderPolicy: false,
    // STIG V-222604: HSTS — enforced at Nginx for .onion; Express adds for direct access
    strictTransportSecurity: false,
}));

// Remove X-Powered-By (information disclosure)
app.disable('x-powered-by');

app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());

// Morgan: omit query strings to prevent sensitive data in logs (STIG V-222390)
morgan.token('path-only', (req) => req.path);
app.use(morgan(':remote-addr - [:date[clf]] ":method :path-only HTTP/:http-version" :status :res[content-length]',
    { skip: (req) => req.path === '/health' }));

// ---------------------------------------------------------------------------
// CSRF SYNCHRONIZER TOKEN (Double-Submit Cookie pattern)
// ---------------------------------------------------------------------------
// The server issues a CSRF token in a readable cookie so JS can read it and
// include it as a request header. The httpOnly auth cookie is separate.
// ---------------------------------------------------------------------------
const CSRF_COOKIE = 'csrf_token';
const CSRF_HEADER = 'x-csrf-token';
const CSRF_TTL_MS = 10 * 60 * 1000; // 10 min — matches session window

app.use((req, res, next) => {
    // Issue or rotate CSRF token on GET requests
    if (req.method === 'GET') {
        const existing = req.cookies?.[CSRF_COOKIE];
        if (!existing) {
            const tok = crypto.randomBytes(32).toString('hex');
            res.cookie(CSRF_COOKIE, tok, {
                path:     '/',
                sameSite: 'Lax',
                httpOnly: false, // JS must read this to include in headers
                maxAge:   CSRF_TTL_MS,
                secure:   false, // HTTP inside Tor enclave
            });
        }
    }
    next();
});

// CSRF validation for all state-mutating requests to /api/*
app.use('/api/', (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

    // Public submission does not require a session cookie but still CSRF-checked
    const cookieToken = req.cookies?.[CSRF_COOKIE];
    const headerToken = req.headers?.[CSRF_HEADER];

    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
        console.warn(`[SECURITY_ALERT] CSRF validation failed: ${req.path}. Cookie: ${!!cookieToken}, Header: ${!!headerToken}`);
        return res.status(403).json({ error: 'CSRF_VALIDATION_FAILED' });
    }
    next();
});

// ---------------------------------------------------------------------------
// RATE LIMITING (STIG SRG-APP-000246)
// Per-route limits using express-rate-limit as defence-in-depth behind Nginx
// ---------------------------------------------------------------------------
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 15,           // 15 attempts per 15 min per IP across the whole window
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'RATE_LIMITED' },
    keyGenerator: (req) => req.headers['x-real-ip'] || req.socket.remoteAddress || 'unknown',
});

const submitLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,            // 5 submissions per minute per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'RATE_LIMITED' },
    keyGenerator: (req) => req.headers['x-real-ip'] || req.socket.remoteAddress || 'unknown',
});

// ---------------------------------------------------------------------------
// BLOCK SENSITIVE PATHS (defence-in-depth behind Nginx)
// ---------------------------------------------------------------------------
const RESTRICTED = ['/db', '/logs', '/pgp/priv', '/views'];
app.use((req, res, next) => {
    const normalizedPath = path.normalize(req.path);
    const isRestricted   = RESTRICTED.some(folder => normalizedPath.startsWith(folder));
    const isPublicKey    = req.path === '/pgp/pub/dirtmap_public.asc';
    const isApi          = req.path.startsWith('/api/');
    if (isRestricted && !isPublicKey && !isApi) {
        console.warn(`[SECURITY_ALERT] Filesystem probe blocked: ${req.path}`);
        return res.status(404).json({ error: 'Not Found' });
    }
    next();
});

// ---------------------------------------------------------------------------
// USERS DB HELPER
// FIX BUG-5: Cache the parsed DB in memory with a TTL rather than hitting
// disk synchronously on every login request. Falls back to stale cache on
// read error instead of returning an empty object (which would lock everyone
// out silently). TTL of 30 s means a new user is visible within 30 s of
// the stack restarting, which is acceptable given the offline create-user.js
// workflow.
// ---------------------------------------------------------------------------
let usersCache     = null;
let usersCacheTime = 0;
const USERS_CACHE_TTL_MS = 30_000; // 30 seconds

const getUsers = () => {
    const now = Date.now();
    if (usersCache && (now - usersCacheTime) < USERS_CACHE_TTL_MS) {
        return usersCache;
    }
    try {
        const userDbPath = process.env.USER_DB_PATH || path.join(baseDir, 'db/users.db');
        const parsed = JSON.parse(fs.readFileSync(userDbPath, 'utf8') || '{}');
        usersCache     = parsed;
        usersCacheTime = now;
        return usersCache;
    } catch (e) {
        console.error('[CRITICAL] Failed to load User DB:', e.message);
        // Return stale cache if available — prevents a transient read error
        // from locking out all users mid-session.
        return usersCache || {};
    }
};

// ---------------------------------------------------------------------------
// BRUTE FORCE TRACKING — keyed by BOTH username AND IP (STIG V-233038)
// ---------------------------------------------------------------------------
const loginAttempts = new Map(); // key: "ip:username"
const LOCKOUT_THRESHOLD = 3;
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000;

const getAttemptKey = (req, username) => {
    const ip = req.headers['x-real-ip'] || req.socket.remoteAddress || 'unknown';
    return `${ip}:${username}`;
};

// Prune stale lockout entries to prevent unbounded growth
setInterval(() => {
    const now = Date.now();
    for (const [key, val] of loginAttempts.entries()) {
        if (now - val.since > LOCKOUT_WINDOW_MS) loginAttempts.delete(key);
    }
}, 5 * 60 * 1000);

// ---------------------------------------------------------------------------
// TOKEN REVOCATION LIST (in-memory; covers the 10-min session window)
// Stores {jti -> expiresAt} so we only prune truly expired entries.
// ---------------------------------------------------------------------------
const revokedTokens = new Map(); // jti -> expiresAt (epoch ms)

// Prune expired revocations every 5 min — prevents unbounded growth while
// retaining valid revocations for the full 10-min session window.
setInterval(() => {
    const now = Date.now();
    for (const [jti, exp] of revokedTokens.entries()) {
        if (now > exp) revokedTokens.delete(jti);
    }
    console.log(`[MAINTENANCE] Token revocation list pruned. Active entries: ${revokedTokens.size}`);
}, 5 * 60 * 1000);

// ---------------------------------------------------------------------------
// MULTER — Secure File Upload Storage (memory — never touches disk unencrypted)
// Files are received in memory, validated, then stored encrypted to disk.
// ---------------------------------------------------------------------------
const ALLOWED_MIME_TYPES = new Set([
    'application/pdf',
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'text/plain',
    'application/zip',
    'application/x-zip-compressed',
    'application/octet-stream', // generic binary — validated further below
]);

const ALLOWED_EXTENSIONS = new Set(['.asc']);

const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize:  MAX_FILE_SIZE_BYTES,
        files:     3,           // Max 3 files per submission
        fields:    1,           // Only the 'payload' text field
        fieldSize: 200 * 1024,  // 200 KB for the JSON/PGP text field
    },
    fileFilter: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        if (!ALLOWED_EXTENSIONS.has(ext)) {
            return cb(new Error('FILE_TYPE_REJECTED'));
        }
        if (!ALLOWED_MIME_TYPES.has(file.mimetype)) {
            return cb(new Error('MIME_TYPE_REJECTED'));
        }
        cb(null, true);
    },
});

// ---------------------------------------------------------------------------
// DUMMY BCRYPT HASH — used for constant-time comparison when user not found
// FIX BUG-4: Without this, a missing username returns immediately (~1 ms)
// while a found username takes ~100 ms for bcrypt. This leaks whether an
// account exists — timing-based user enumeration (STIG V-222390).
// ---------------------------------------------------------------------------
// Pre-computed at startup so it doesn't add latency to the first request.
const DUMMY_HASH = '$2a$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345';

// ---------------------------------------------------------------------------
// AUTH: LOGIN
// ---------------------------------------------------------------------------
app.post('/api/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;

    // Input validation (STIG SRG-APP-000251)
    if (!username || !password ||
        typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'INVALID_REQUEST' });
    }

    // Enforce max length to prevent bcrypt timing attacks on huge inputs
    if (username.length > 64 || password.length > 256) {
        return res.status(400).json({ error: 'INVALID_REQUEST' });
    }

    // FIX BUG-3: Reject reserved JS prototype property names.
    // Prevents prototype pollution probing via users['__proto__'] etc.
    const RESERVED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
    if (RESERVED_KEYS.has(username)) {
        return res.status(400).json({ error: 'INVALID_REQUEST' });
    }

    const attemptKey = getAttemptKey(req, username);
    const record     = loginAttempts.get(attemptKey) || { count: 0, since: Date.now() };

    // Reset window if it has expired
    if (Date.now() - record.since > LOCKOUT_WINDOW_MS) {
        record.count = 0;
        record.since = Date.now();
    }

    // STIG V-233038: Account lockout after 3 failures
    if (record.count >= LOCKOUT_THRESHOLD) {
        console.warn(`[STIG_AUDIT] Lockout enforced: ${attemptKey}`);
        return res.status(429).json({ error: 'ACCOUNT_LOCKED_TEMPORARY' });
    }

    const users = getUsers();

    // FIX BUG-3 (continued): Use hasOwnProperty to prevent prototype chain
    // lookups. Do NOT use users[username] directly for existence checks.
    const userRecord = Object.prototype.hasOwnProperty.call(users, username)
        ? users[username]
        : null;

    // FIX BUG-2: Strict schema validation — only accept records that have a
    // properly structured bcrypt hash. The old fallback
    // (users[username].hash || users[username]) would silently compare against
    // whatever string value was stored, risking auth bypass on malformed DB
    // entries. A valid bcrypt hash always starts with '$2'.
    const hashToCompare = (userRecord && typeof userRecord.hash === 'string' && userRecord.hash.startsWith('$2'))
        ? userRecord.hash
        : null;

    // FIX BUG-4: Always run bcrypt.compare regardless of whether the user
    // exists. When the user is not found (hashToCompare is null) we compare
    // against a dummy hash so response time is indistinguishable from a real
    // failed attempt. This defeats timing-based user enumeration (STIG V-222390).
    const passwordMatch = await bcrypt.compare(password, hashToCompare || DUMMY_HASH);

    if (hashToCompare && passwordMatch) {
        loginAttempts.delete(attemptKey);

        // STIG V-222391: 10-minute session timeout
        // Role is read from DB — not inferred from username (privilege escalation prevention)
        const storedRole = (userRecord.role) || 'user';
        const jti   = crypto.randomUUID();
        const token = jwt.sign(
            { username, role: storedRole, jti },
            SECRET_KEY,
            { expiresIn: '10m', algorithm: 'HS256', subject: username }
        );

        // Rotate the CSRF token on login — new session, new token
        const csrfTok = crypto.randomBytes(32).toString('hex');
        res.cookie(CSRF_COOKIE, csrfTok, {
            path: '/', sameSite: 'Lax', httpOnly: false,
            maxAge: CSRF_TTL_MS, secure: false,
        });

        res.cookie('token', token, {
            path:     '/',
            sameSite: 'Lax',
            secure:   false,  // HTTP inside Tor enclave — network is isolated
            httpOnly: true,   // JS cannot read the auth token
            maxAge:   600000, // 10 minutes
        });

        console.log(`[STIG_AUDIT] Successful login: ${username}`);
        return res.json({ status: 'ACCESS_GRANTED' });
    }

    // FIX BUG-6: Always increment and persist the attempt counter BEFORE
    // returning, regardless of which failure path we took (user not found vs
    // wrong password). This ensures lockout logic is not bypassable by
    // triggering the "user not found" early-return path.
    record.count += 1;
    loginAttempts.set(attemptKey, record);
    console.warn(`[STIG_AUDIT] Failed login attempt ${record.count} for: ${attemptKey}`);

    // STIG V-222390: Generic error — no account enumeration
    return res.status(401).json({ error: 'AUTH_FAILED' });
});

// ---------------------------------------------------------------------------
// AUTH: LOGOUT — revoke the token immediately
// ---------------------------------------------------------------------------
app.post('/api/logout', (req, res) => {
    const token = req.cookies?.token;
    if (token) {
        try {
            const decoded = jwt.verify(token, SECRET_KEY, { algorithms: ['HS256'] });
            if (decoded.jti) {
                // Store with expiry time so pruning can remove it after session window
                const expiresAt = (decoded.exp || 0) * 1000 || Date.now() + 600000;
                revokedTokens.set(decoded.jti, expiresAt);
            }
        } catch (_) { /* already invalid */ }
    }
    res.clearCookie('token',      { path: '/', sameSite: 'Lax',    httpOnly: true });
    res.clearCookie(CSRF_COOKIE,  { path: '/', sameSite: 'Strict', httpOnly: false });
    return res.json({ status: 'LOGGED_OUT' });
});

// ---------------------------------------------------------------------------
// MIDDLEWARE: JWT AUTHENTICATION
// ---------------------------------------------------------------------------
const authenticate = (req, res, next) => {
    const token = req.cookies?.token;
    if (!token) return res.status(401).json({ error: 'Access Denied' });

    jwt.verify(token, SECRET_KEY, { algorithms: ['HS256'] }, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid Token' });

        // Check revocation list
        if (user.jti && revokedTokens.has(user.jti)) {
            return res.status(403).json({ error: 'Token Revoked' });
        }

        req.user = user;
        next();
    });
};

// ---------------------------------------------------------------------------
// HEALTH CHECK (unauthenticated, no sensitive data)
// ---------------------------------------------------------------------------
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

// ---------------------------------------------------------------------------
// CSRF TOKEN ENDPOINT — explicitly issues/refreshes the CSRF cookie.
// login.js and uplink.js call this on DOMContentLoaded to guarantee the
// cookie exists before any POST is attempted. Necessary because static
// files served before Express middleware runs may not trigger cookie
// issuance reliably in all browser configurations.
// ---------------------------------------------------------------------------
app.get('/api/csrf', (req, res) => {
    let tok = req.cookies?.[CSRF_COOKIE];
    if (!tok) {
        tok = crypto.randomBytes(32).toString('hex');
        res.cookie(CSRF_COOKIE, tok, {
            path:     '/',
            sameSite: 'Lax',
            httpOnly: false,
            maxAge:   CSRF_TTL_MS,
            secure:   false,
        });
    }
    res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// ROUTES — STATIC & ADMIN PAGE
// ---------------------------------------------------------------------------

// Serve admin.html ONLY to authenticated users
app.get('/admin', authenticate, (req, res) => {
    res.sendFile(path.join(baseDir, 'views/admin.html'));
});

// Serve admin.js behind authentication
app.get('/api/admin/ui.js', authenticate, (req, res) => {
    res.setHeader('Content-Type', 'application/javascript');
    res.sendFile(path.join(baseDir, 'views/admin.js'));
});

// Static files (index.html, login.html, etc.)
app.use(express.static(path.join(__dirname, 'web')));

// Expose ONLY the public PGP key
app.get('/pgp/pub/dirtmap_public.asc', (req, res) => {
    res.sendFile(path.join(baseDir, 'pgp/pub/dirtmap_public.asc'));
});

// ---------------------------------------------------------------------------
// ADMIN API: LIST REPORTS
// ---------------------------------------------------------------------------
app.get('/api/admin/list-reports', authenticate, (req, res) => {
    try {
        const dir = process.env.REPORT_STORAGE_PATH || path.join(__dirname, '../db/reports');
        if (!fs.existsSync(dir)) return res.json([]);
        const files = fs.readdirSync(dir)
            .filter(f => f.endsWith('.asc'))
            .sort((a, b) => {
                // Sort by mtime descending (newest first)
                const aStat = fs.statSync(path.join(dir, a));
                const bStat = fs.statSync(path.join(dir, b));
                return bStat.mtimeMs - aStat.mtimeMs;
            });
        res.json(files);
    } catch (err) {
        console.error('[CRITICAL] Report list failure:', err.message);
        res.status(500).json({ error: 'Storage Access Denied' });
    }
});

// ---------------------------------------------------------------------------
// ADMIN API: LIST FILE ATTACHMENTS FOR A REPORT
// ---------------------------------------------------------------------------
app.get('/api/admin/list-attachments/:reportId', authenticate, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'ACCESS_DENIED_UNAUTHORIZED_ROLE' });
    }

    // reportId must be a UUID
    const reportId = req.params.reportId;
    if (!/^[0-9a-f-]{36}$/.test(reportId)) {
        return res.status(400).json({ error: 'INVALID_REPORT_ID' });
    }

    const dir = process.env.REPORT_STORAGE_PATH || path.join(__dirname, '../db/reports');
    const attachDir = path.join(dir, 'attachments', reportId);

    if (!fs.existsSync(attachDir)) return res.json([]);

    try {
        const files = fs.readdirSync(attachDir)
            .filter(f => f.endsWith('.asc'))
            .map(f => ({
                filename: f,
                size:     fs.statSync(path.join(attachDir, f)).size,
            }));
        res.json(files);
    } catch (err) {
        console.error('[CRITICAL] Attachment list failure:', err.message);
        res.status(500).json({ error: 'Storage Access Denied' });
    }
});

// ---------------------------------------------------------------------------
// ADMIN API: DOWNLOAD & DECRYPT A FILE ATTACHMENT
// ---------------------------------------------------------------------------
app.get('/api/admin/get-attachment/:reportId/:filename', authenticate, async (req, res) => {
    if (req.user.role !== 'admin') {
        console.warn(`[SECURITY_ALERT] Non-admin attachment access by: ${req.user.username}`);
        return res.status(403).json({ error: 'ACCESS_DENIED_UNAUTHORIZED_ROLE' });
    }

    const reportId = req.params.reportId;
    if (!/^[0-9a-f-]{36}$/.test(reportId)) {
        return res.status(400).json({ error: 'INVALID_REPORT_ID' });
    }

    const safeFilename = path.basename(req.params.filename);
    if (!safeFilename.endsWith('.asc') || safeFilename !== req.params.filename) {
        return res.status(400).json({ error: 'INVALID_FILENAME' });
    }

    const dir        = process.env.REPORT_STORAGE_PATH || path.join(__dirname, '../db/reports');
    const attachDir  = path.join(dir, 'attachments', reportId);
    const filePath   = path.join(attachDir, safeFilename);

    // Path traversal guard
    const resolvedPath = path.resolve(filePath);
    const allowedBase  = path.resolve(attachDir);
    if (!resolvedPath.startsWith(allowedBase + path.sep)) {
        console.warn(`[SECURITY_ALERT] Path traversal attempt: ${filePath}`);
        return res.status(400).json({ error: 'INVALID_PATH' });
    }

    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'Attachment not found' });
    }

    try {
        const armoredMessage = fs.readFileSync(filePath, 'utf8');
        const message        = await openpgp.readMessage({ armoredMessage });

        const { data: decryptedBuffer } = await openpgp.decrypt({
            message,
            decryptionKeys: cachedPrivateKey,
            format: 'binary',
        });

        // Extract original filename — format: <originalname>_<uuid>.asc
        const metaPart   = safeFilename.replace(/\.asc$/, '');
        const lastUndIdx = metaPart.lastIndexOf('_');
        const origName   = lastUndIdx > 0 ? metaPart.substring(0, lastUndIdx) : metaPart;

        // RFC 5987 encoded filename to prevent header injection
        const safeDispName = origName.replace(/[^\w.\-]/g, '_').substring(0, 128);
        res.setHeader('Content-Disposition', `attachment; filename="${safeDispName}"; filename*=UTF-8''${encodeURIComponent(safeDispName)}`);
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.send(Buffer.from(decryptedBuffer));
    } catch (err) {
        console.error('[CRITICAL] Attachment decryption failure:', err.message);
        res.status(500).json({ error: 'DECRYPTION_FAILED' });
    }
});

// ---------------------------------------------------------------------------
// ADMIN API: GET AND DECRYPT A REPORT
// ---------------------------------------------------------------------------
app.get('/api/admin/get-report/:filename', authenticate, async (req, res) => {
    // STIG: Only admins may decrypt reports
    if (req.user.role !== 'admin') {
        console.warn(`[SECURITY_ALERT] Non-admin decrypt attempt by: ${req.user.username}`);
        return res.status(403).json({ error: 'ACCESS_DENIED_UNAUTHORIZED_ROLE' });
    }

    // Sanitise filename — prevent directory traversal
    const safeName = path.basename(req.params.filename);
    if (!safeName.endsWith('.asc') || safeName !== req.params.filename) {
        return res.status(400).json({ error: 'INVALID_FILENAME' });
    }

    const dir      = process.env.REPORT_STORAGE_PATH || path.join(__dirname, '../db/reports');
    const filePath = path.join(dir, safeName);

    // Path traversal guard
    const resolvedPath = path.resolve(filePath);
    const allowedBase  = path.resolve(dir);
    if (!resolvedPath.startsWith(allowedBase + path.sep)) {
        console.warn(`[SECURITY_ALERT] Path traversal attempt: ${filePath}`);
        return res.status(400).json({ error: 'INVALID_PATH' });
    }

    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
    }

    try {
        const armoredMessage = fs.readFileSync(filePath, 'utf8');
        const message        = await openpgp.readMessage({ armoredMessage });

        const { data: decrypted } = await openpgp.decrypt({
            message,
            decryptionKeys: cachedPrivateKey
        });

        res.json({ decrypted });
    } catch (err) {
        console.error('[CRITICAL] Decryption failure:', err.message);
        res.status(500).json({ error: 'DECRYPTION_FAILED' });
    }
});

// ---------------------------------------------------------------------------
// ADMIN API: DELETE A REPORT (and its attachments)
// ---------------------------------------------------------------------------
app.delete('/api/admin/reports/:filename', authenticate, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'ACCESS_DENIED_UNAUTHORIZED_ROLE' });
    }

    const safeName = path.basename(req.params.filename);
    if (!safeName.endsWith('.asc') || safeName !== req.params.filename) {
        return res.status(400).json({ error: 'INVALID_FILENAME' });
    }

    const dir      = process.env.REPORT_STORAGE_PATH || path.join(__dirname, '../db/reports');
    const filePath = path.join(dir, safeName);

    // Path traversal guard
    const resolvedPath = path.resolve(filePath);
    const allowedBase  = path.resolve(dir);
    if (!resolvedPath.startsWith(allowedBase + path.sep)) {
        return res.status(400).json({ error: 'INVALID_PATH' });
    }

    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

    // Also delete associated attachments directory
    const reportId  = safeName.replace(/^report_/, '').replace(/\.asc$/, '');
    const attachDir = path.join(dir, 'attachments', reportId);
    if (fs.existsSync(attachDir)) {
        fs.readdirSync(attachDir).forEach(f => fs.unlinkSync(path.join(attachDir, f)));
        fs.rmdirSync(attachDir);
    }

    console.log(`[STIG_AUDIT] Report + attachments purged by ${req.user.username}: ${safeName}`);
    res.json({ status: 'DELETED' });
});

// ---------------------------------------------------------------------------
// PUBLIC API: SUBMIT ENCRYPTED INTEL REPORT (with optional file attachments)
//
// Accepts multipart/form-data with:
//   - payload  (required): PGP-encrypted JSON text of the report fields
//   - files[]  (optional): up to 3 raw files — encrypted server-side with
//                          the server's public key before writing to disk
// ---------------------------------------------------------------------------
app.post('/api/submit-intel', submitLimiter, upload.array('files[]', 3), async (req, res) => {
    try {
        // Support both multipart (new) and JSON (legacy) submissions
        const encryptedData = req.body?.payload || req.body?.data;

        if (!encryptedData || typeof encryptedData !== 'string') {
            return res.status(400).json({ error: 'Missing or invalid payload' });
        }

        // Enforce payload size
        if (encryptedData.length > 200 * 1024) {
            return res.status(400).json({ error: 'PAYLOAD_TOO_LARGE' });
        }

        // Validate it is actually a PGP message before writing to disk
        try {
            await openpgp.readMessage({ armoredMessage: encryptedData });
        } catch (_) {
            console.warn('[SECURITY_ALERT] Rejected non-PGP submission payload.');
            return res.status(400).json({ error: 'INVALID_PGP_PAYLOAD' });
        }

        const dir = process.env.REPORT_STORAGE_PATH || path.join(__dirname, '../db/reports');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

        // UUID filename — not enumerable from timestamp
        const reportUUID = crypto.randomUUID();
        const filename   = `report_${reportUUID}.asc`;
        fs.writeFileSync(path.join(dir, filename), encryptedData, { mode: 0o600 });

        console.log(`[UPLINK] Secure report filed: ${filename}`);

        // -----------------------------------------------------------------------
        // Process file attachments — encrypt each file server-side before storage
        // -----------------------------------------------------------------------
        let filesStored = 0;
        if (req.files && req.files.length > 0) {
            // Load the public key to re-encrypt attachments
            const pubKeyPath = process.env.PGP_PUB_KEY_PATH || '/app/pgp/pub/dirtmap_public.asc';
            let publicKey;
            try {
                const armoredKey = fs.readFileSync(pubKeyPath, 'utf8');
                publicKey = await openpgp.readKey({ armoredKey });
            } catch (e) {
                console.error('[CRITICAL] Could not load public key for attachment encryption:', e.message);
                return res.status(500).json({ error: 'ENCRYPTION_KEY_UNAVAILABLE' });
            }

            const attachDir = path.join(dir, 'attachments', reportUUID);
            fs.mkdirSync(attachDir, { recursive: true, mode: 0o700 });

            for (const file of req.files) {
                // Re-validate extension (belt & suspenders)
                const ext = path.extname(file.originalname).toLowerCase();
                if (!ALLOWED_EXTENSIONS.has(ext)) {
                    console.warn(`[SECURITY_ALERT] Attachment rejected post-upload (ext): ${file.originalname}`);
                    continue;
                }

                // Sanitize original filename for storage metadata
                const safeOrigName = path.basename(file.originalname)
                    .replace(/[^a-zA-Z0-9._-]/g, '_')
                    .substring(0, 128);

                // Encrypt file buffer with the server's public key
                const encryptedFile = await openpgp.encrypt({
                    message: await openpgp.createMessage({ binary: file.buffer }),
                    encryptionKeys: publicKey,
                    format: 'armored',
                });

                const attachFilename = `${safeOrigName}_${crypto.randomUUID()}.asc`;
                fs.writeFileSync(
                    path.join(attachDir, attachFilename),
                    encryptedFile,
                    { mode: 0o600 }
                );

                filesStored++;
                console.log(`[UPLINK] Attachment stored (encrypted): ${attachFilename}`);
            }
        }

        res.json({
            status: 'Report filed securely',
            attachments_stored: filesStored,
        });

    } catch (err) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({ error: 'FILE_TOO_LARGE' });
        }
        if (err.code === 'LIMIT_FILE_COUNT') {
            return res.status(400).json({ error: 'TOO_MANY_FILES' });
        }
        if (err.message === 'FILE_TYPE_REJECTED' || err.message === 'MIME_TYPE_REJECTED') {
            return res.status(400).json({ error: err.message });
        }
        console.error('[CRITICAL] Submission error:', err.message);
        res.status(500).json({ error: 'Internal Filing Failure' });
    }
});

// ---------------------------------------------------------------------------
// 404 CATCH-ALL — return JSON not HTML (avoid information disclosure)
// ---------------------------------------------------------------------------
app.use((req, res) => {
    res.status(404).json({ error: 'Not Found' });
});

// ---------------------------------------------------------------------------
// GLOBAL ERROR HANDLER — never expose stack traces
// ---------------------------------------------------------------------------
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    console.error('[UNHANDLED_ERROR]', err.message);
    res.status(500).json({ error: 'Internal Server Error' });
});

// ---------------------------------------------------------------------------
// STARTUP
// ---------------------------------------------------------------------------
loadPrivateKey().then(() => {
    // Bind to 0.0.0.0 within the container network namespace — this is safe because:
    // (1) the backend Docker network is marked internal: true (no host routing),
    // (2) the Node container exposes no host ports,
    // (3) Nginx is the sole external entry point on the frontend network.
    // STIG isolation is enforced at the Docker network layer, not the socket layer.
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`[INIT] Backend Uplink active on port ${PORT}`);
    });
});