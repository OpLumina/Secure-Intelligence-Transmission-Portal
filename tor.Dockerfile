# =============================================================================
# Tor Hidden Service Gateway
# Base: Alpine 3.21
#
# OFFLINE BUILD — no network access required at build time.
#
# Pre-download packages to apk-cache/ on the host before building:
#
#   docker run --rm -u root \
#     -v "${PWD}/apk-cache:/var/cache/apk" \
#     alpine:3.21 \
#     sh -c "apk update && apk fetch --no-cache -o /var/cache/apk tor su-exec"
#
# This populates apk-cache/ with the .apk files. The build then COPYs
# them in and installs with --no-network, so no internet access occurs
# during docker compose build.
#
# PERMISSION DESIGN:
#   /var/lib/tor        owned root:tor, mode 750
#                       Root can traverse it without DAC_OVERRIDE.
#                       Tor (gid=101) can read/execute via group bit.
#   /var/lib/tor/state  owned root:tor, mode 770
#                       tmpfs mounted here by Docker (always root:root).
#                       Entrypoint chowns to tor:tor using only CAP_CHOWN.
#                       No DAC_OVERRIDE needed — root owns the parent.
#   /var/lib/tor/hidden_service
#                       owned tor:tor, mode 700
#                       bind mount from ./db/tor_service.
#   /var/log/tor        owned root:tor, mode 770
#                       bind mount from ./logs/tor, chowned at startup.
#   /run                owned root:root, mode 755
#                       tmpfs, chowned to tor:tor at startup.
#
# This layout means the entrypoint only needs CAP_CHOWN (to chown the
# tmpfs mounts) and CAP_SETUID/CAP_SETGID (for su-exec). DAC_OVERRIDE
# is NOT required because root owns /var/lib/tor and can traverse it.
#
# ENTRYPOINT:
#   docker-entrypoint.sh runs as root, chowns the three tmpfs-backed
#   paths, then exec's Tor as tor (uid=100) via su-exec. After the exec,
#   PID 1 is tor with zero capabilities. No root process remains.
#
# WINDOWS LINE ENDINGS:
#   docker-entrypoint.sh is stripped of CRLF during build via sed.
#
# On first run with an empty ./db/tor_service, Tor auto-generates:
#   hostname               <- your .onion address
#   hs_ed25519_public_key
#   hs_ed25519_secret_key
# Back up hs_ed25519_secret_key immediately. Loss is permanent.
# =============================================================================

FROM alpine:3.21

LABEL org.opencontainers.image.title="Onion-Gateway" \
      org.opencontainers.image.description="Hardened Tor Hidden Service Gateway" \
      org.opencontainers.image.base.name="alpine:3.21"

# Copy pre-downloaded .apk files from the host cache directory.
# Populate apk-cache/ first — see header for the fetch command.
COPY apk-cache/ /tmp/apk-cache/

# Install tor and su-exec from local cache — no network required.
# su-exec: minimal privilege-drop utility. Replaces the calling process
# via exec() — no shell remains after the privilege drop.
#
# Ownership/permission strategy (see header for full rationale):
#   /var/lib/tor        root:tor  750  — root owns, tor group can traverse
#   /var/lib/tor/state  root:tor  770  — tmpfs target; chowned at startup
#   /var/lib/tor/hidden_service
#                       tor:tor   700  — bind mount target; tor owns
#   /var/log/tor        root:tor  770  — bind mount; chowned at startup
#   /run                root:root 755  — tmpfs; chowned at startup
#   /tmp                root:root 1777
RUN apk add --no-network --no-cache /tmp/apk-cache/*.apk \
    && rm -rf /tmp/apk-cache \
    && mkdir -p /var/lib/tor/state \
                /var/lib/tor/hidden_service \
                /var/log/tor \
                /run \
                /tmp \
    && chown root:tor  /var/lib/tor \
    && chown root:tor  /var/lib/tor/state \
    && chown tor:tor   /var/lib/tor/hidden_service \
    && chown root:tor  /var/log/tor \
    && chmod 750  /var/lib/tor \
    && chmod 770  /var/lib/tor/state \
    && chmod 700  /var/lib/tor/hidden_service \
    && chmod 770  /var/log/tor \
    && chmod 755  /run \
    && chmod 1777 /tmp \
    && rm -rf /var/cache/apk/*

# Copy entrypoint and strip Windows CRLF in one layer.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN sed -i 's/\r//' /usr/local/bin/docker-entrypoint.sh \
    && chmod 755 /usr/local/bin/docker-entrypoint.sh

# Emit Tor version into build log for auditability.
RUN tor --version

# Start as root — entrypoint chowns tmpfs mounts then drops to tor via su-exec.
USER root

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
