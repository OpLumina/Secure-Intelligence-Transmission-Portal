#!/bin/sh
# =============================================================================
# docker-entrypoint.sh
#
# Runs as root on container start. Fixes ownership on tmpfs-backed directories
# (Docker always creates tmpfs mounts as root:root regardless of mode= flags
# or the USER directive), then drops permanently to tor via su-exec.
#
# su-exec uses exec() semantics — it replaces this process entirely.
# After the exec, PID 1 is tor (uid=100) with zero capabilities.
# No root process remains.
#
# WHY NO chmod ON /var/lib/tor HERE:
#   The Dockerfile sets /var/lib/tor to root:tor 750. Root owns the directory
#   and can traverse it without DAC_OVERRIDE. Only CAP_CHOWN is needed to
#   fix ownership on the tmpfs mount points inside it.
# =============================================================================
set -e

# Fix ownership on tmpfs-backed paths (all mounted as root:root by Docker).
# /var/lib/tor/state — DataDirectory (tmpfs)
# /run               — runtime dir   (tmpfs)
# /var/log/tor       — bind mount from host
# Fix ownership on all critical paths, including the bind-mounted hidden_service keys
# Only chown the paths that are not bind-mounted from the Windows host
# Internal container paths (Safe to chown)


# Windows Bind Mount (Risky: ignore errors if Windows blocks ownership changes)
# This allows the container to keep running even if the host filesystem pushes back.
# Fix ownership; silence errors for Windows/WSL2 bind-mount restrictions
chown tor:tor /var/lib/tor/state /run /var/log/tor 2>/dev/null || true

# Fix modes; silence errors for filesystem boundaries
chmod 700 /var/lib/tor/state 2>/dev/null || true
chmod 700 /var/lib/tor/hidden_service 2>/dev/null || true
chmod 755 /run 2>/dev/null || true
chmod 755 /var/log/tor 2>/dev/null || true

# Drop privileges permanently and exec Tor.
# su-exec replaces PID 1 with the tor process under the tor user.
echo "[notice] Dropping privileges to tor user..."
exec su-exec tor:tor tor -f /etc/tor/torrc
