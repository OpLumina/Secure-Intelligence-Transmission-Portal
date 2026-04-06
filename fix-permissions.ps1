# =============================================================================
# fix-permissions.ps1  -  dirtmap.onion
# Run from the project root: .\fix-permissions.ps1
# Requirements: Docker Desktop must be running. Run as normal user (not admin).
# =============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$user = $env:USERNAME

# --- PATH GUARD ---
$ExpectedPath = "C:\Users\Palantir\Documents\cdev\dirtmap.onion"
if ($PWD.Path -ne $ExpectedPath) {
    Write-Error "CRITICAL: Script must be executed from $ExpectedPath. Current path is $($PWD.Path). Execution halted."
    exit 1
}
# ------------------

Write-Host ""
Write-Host "[1/6] Locking secrets\ to current user only..." -ForegroundColor Cyan
icacls "secrets"                    /inheritance:r /grant:r "${user}:(OI)(CI)F" | Out-Null
icacls "secrets\jwt_secret.txt"     /inheritance:r /grant:r "${user}:F"         | Out-Null
icacls "secrets\pgp_passphrase.txt" /inheritance:r /grant:r "${user}:F"         | Out-Null
Write-Host "  secrets\*  -> owner-only (F)" -ForegroundColor Green

Write-Host ""
Write-Host "[2/6] Locking pgp\priv\ (private key) to current user only..." -ForegroundColor Cyan
icacls "pgp\priv"                     /inheritance:r /grant:r "${user}:(OI)(CI)F" | Out-Null
icacls "pgp\priv\dirtmap_private.asc" /inheritance:r /grant:r "${user}:F"         | Out-Null
Write-Host "  pgp\priv\*  -> owner-only (F)" -ForegroundColor Green

Write-Host ""
Write-Host "[3/6] Locking db\users.db to current user only..." -ForegroundColor Cyan
if (Test-Path "db\users.db") {
    icacls "db\users.db" /inheritance:r /grant:r "${user}:F" | Out-Null
    Write-Host "  db\users.db  -> owner-only (F)" -ForegroundColor Green
} else {
    Write-Host "  db\users.db not found - skipping (run create-user.js first)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[4/6] Setting Node container Unix permissions (UID 1001)..." -ForegroundColor Cyan
# db/reports needs 777 — chown does not stick on NTFS-backed Docker Desktop
# volumes (Windows limitation). See setup.txt Section 8.
$nodeScript = 'chmod 777 /app/db/reports /app/db/reports/attachments; chown -R 1001:1001 /app/db /app/logs; chmod 640 /app/db/users.db; echo done'
docker run --rm `
    -u root `
    -v "${PWD}/db:/app/db" `
    -v "${PWD}/logs/node:/app/logs" `
    registry1.dso.mil/ironbank/opensource/nodejs/nodejs22:latest `
    sh -c $nodeScript
Write-Host "  db/reports, db/reports/attachments  -> 777 (NTFS Docker Desktop workaround)" -ForegroundColor Green
Write-Host "  db/users.db                         -> 640" -ForegroundColor Green
Write-Host "  db/, logs/node                      -> chowned UID 1001" -ForegroundColor Green

Write-Host ""
Write-Host "[5/6] Setting Nginx log directory permissions (UID 101)..." -ForegroundColor Cyan
# Iron Bank nginx runs as UID 101. The entrypoint runs as that user from the
# start (no root phase), so the bind-mounted log dir must already be owned by
# 101 before the container starts — it cannot chown it itself.
# chmod 755: nginx user needs rx on the dir to create log files inside it.
$nginxScript = 'chown -R 101:101 /var/log/nginx; chmod 755 /var/log/nginx; echo done'
docker run --rm `
    -u root `
    -v "${PWD}/logs/nginx:/var/log/nginx" `
    registry1.dso.mil/ironbank/opensource/nginx/nginx:1.29.4 `
    sh -c $nginxScript
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: nginx image not available. Pull it first:" -ForegroundColor Red
    Write-Host "  docker pull registry1.dso.mil/ironbank/opensource/nginx/nginx:1.29.4" -ForegroundColor Yellow
} else {
    Write-Host "  logs/nginx  -> chowned UID 101, chmod 755" -ForegroundColor Green
}

Write-Host ""
Write-Host "[6/6] Setting Tor hidden_service directory permissions (UID 100, 700)..." -ForegroundColor Cyan
# Tor runs as UID 100 inside the container. The bind mount ./db/tor_service
# is owned by Windows/root on the host. On Windows/Docker Desktop, chown does
# not stick on NTFS bind mounts, so we use chmod 700 + chown 100:101.
# The entrypoint drops to tor (uid=100) via su-exec before Tor reads this dir,
# so it must already be accessible by UID 100 before the container starts.
$torScript = 'chown -R 100:101 /var/lib/tor/hidden_service; chmod 700 /var/lib/tor/hidden_service; echo done'
docker run --rm `
    -u root `
    --entrypoint sh `
    -v "${PWD}/db/tor_service:/var/lib/tor/hidden_service" `
    local-tor:latest `
    -c $torScript
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: local-tor image not built yet. Run: docker compose build" -ForegroundColor Red
} else {
    Write-Host "  db/tor_service  -> chowned UID 100:101, chmod 700" -ForegroundColor Green
}
# Add this to the $nginxScript in your PS1 file:
$nginxScript = 'chown -R 101:101 /var/log/nginx /var/cache/nginx; chmod -R 755 /var/log/nginx /var/cache/nginx; echo done'
Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host " Permission fix complete." -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""
Write-Host "Re-run this script:"
Write-Host "  - Before first docker compose up"
Write-Host "  - After recreating any of the above directories"
Write-Host "  - If you see EACCES errors in: docker compose logs"
Write-Host ""