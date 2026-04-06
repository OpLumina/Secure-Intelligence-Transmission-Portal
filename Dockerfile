# =============================================================================
# DIRMAP UPLINK — Node.js Backend
# Base: Iron Bank Node.js 22 (STIG-hardened, FIPS-validated)
#
# Pull before building:
#   docker pull registry1.dso.mil/ironbank/opensource/nodejs/nodejs22:latest
#
# Runtime volume/tmpfs layout (set in docker-compose.yaml):
#
#   volume ./db           -> /app/db           (report storage, users.db)
#   volume ./pgp/priv     -> /app/pgp/priv:ro  (private key — read-only)
#   volume ./pgp/pub      -> /app/pgp/pub:ro   (public key  — read-only)
#   volume ./logs/node    -> /app/logs:rw       (application logs)
#   tmpfs  /app/tmp       size=50M,noexec,nosuid
#   tmpfs  /tmp           size=10M,noexec,nosuid
#   tmpfs  /run           noexec,nosuid
#
# Docker secrets (mounted at /run/secrets/):
#   pgp_passphrase  -> read by getSecret('PGP_PASSPHRASE')
#   jwt_secret      -> read by getSecret('JWT_SECRET')
#
# PREREQUISITE: Run "npm install" in src/ via the container (Section 6
# of setup.txt) BEFORE running "docker compose build". This generates
# a valid src/package-lock.json which npm ci requires. The lock file
# committed to the repo is a placeholder stub and will cause the build
# to fail if npm install has not been run first.
# =============================================================================

FROM registry1.dso.mil/ironbank/opensource/nodejs/nodejs22:latest

LABEL org.opencontainers.image.title="Uplink-Backend" \
      org.opencontainers.image.description="STIG-Hardened Intel Uplink Node.js Service" \
      org.opencontainers.image.base.name="registry1.dso.mil/ironbank/opensource/nodejs/nodejs22:latest"

# STIG: Never run as root.
# Iron Bank Node.js image provides a non-root 'node' user (UID 1001).
USER node

WORKDIR /app

# Copy package manifests first for layer-cache efficiency
COPY --chown=node:node src/package.json src/package-lock.json* ./

# Install production dependencies only.
# --ignore-scripts: prevent post-install scripts from running arbitrary code.
# --omit=dev: exclude devDependencies.
#
# NOTE: We use "npm install" rather than "npm ci" because the lock file in
# the repository is a placeholder stub (packages: {}) generated before
# dependencies were installed. "npm ci" strictly requires the lock file to
# already match package.json and will fail on a fresh clone.
# After you run "npm install" in the container per Section 6 of setup.txt,
# the real lock file is written to src/package-lock.json on the host volume
# and is then copied in by this COPY instruction on subsequent builds.
# If src/package-lock.json is valid and fully populated, you can change this
# to "npm ci" for fully deterministic builds (STIG SRG-APP-000456).
RUN npm install --omit=dev --ignore-scripts

# Copy application source
COPY --chown=node:node src/ .
COPY --chown=node:node views/ ./views/
COPY --chown=node:node pgp/ ./pgp/
COPY --chown=node:node web/ ./web/


# STIG V-235955: No shell available to the app user at runtime.
# The Iron Bank image already sets shell to /sbin/nologin for the node user.

# Expose internal port only — Nginx is the sole external entry point.
EXPOSE 3000

CMD ["node", "server.js"]