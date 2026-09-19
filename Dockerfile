# OREOCHAIN gateway.
#
# Two stages so the image that runs in production does not contain a compiler,
# a package cache, or the dev dependencies (solc and the EVM harness) that only
# the test suite needs.
#
#   docker build -t oreochain-gateway .
#   docker run --rm -p 8787:8787 --env-file .env oreochain-gateway
#
# Node 22 is the current LTS. package.json supports 18 and CI proves it, but an
# image is a choice rather than a constraint, and there is no reason to ship
# something past end of life.

FROM node:22-alpine AS deps

WORKDIR /app

# Copied on their own so this layer is only rebuilt when the dependency set
# changes, not on every source edit.
COPY package.json package-lock.json ./

# `npm ci` installs exactly the lockfile; `npm install` would silently resolve
# something newer than what CI tested. --omit=dev drops solc and the EVM
# harness, which nothing at runtime imports.
RUN npm ci --omit=dev --no-audit --no-fund

# --------------------------------------------------------------------- runtime

FROM node:22-alpine

# dumb-init reaps zombies and, more importantly here, forwards SIGTERM to the
# gateway. A process running as PID 1 does not get default signal handling, so
# without this the graceful shutdown never runs and every deploy kills uploads
# mid-chunk.
RUN apk add --no-cache dumb-init

ENV NODE_ENV=production \
    # A container is its own network namespace: loopback would make the gateway
    # unreachable from outside it. This is the one default that has to change.
    HOST=0.0.0.0 \
    PORT=8787 \
    OREOCHAIN_DB_PATH=/data/oreochain-proofs.log \
    # Long enough for an orchestrator to see /ready go 503 before the listener
    # closes. See server/README.md.
    OREOCHAIN_SHUTDOWN_DELAY_MS=5000

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY server ./server
COPY js ./js
COPY scripts ./scripts

# The frontend, for OREOCHAIN_SERVE_STATIC=true. Harmless when it is off: the
# allowlist in server/gateway.mjs decides what is reachable, not what is on
# disk.
COPY css ./css
COPY assets ./assets
COPY *.html ./

# The proof store. An anchored batch's ordered document list is the only thing
# that can prove a document is in it, so this directory must outlive the
# container — mount a volume over it.
RUN mkdir -p /data && chown -R node:node /data

# Nothing here needs root, and a gateway that accepts uploads from the public
# is the last place to run as it.
USER node

VOLUME ["/data"]
EXPOSE 8787

# Liveness only. /ready is the orchestrator's business; a container healthcheck
# that fails while the process is deliberately draining would just restart it.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8787)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server/index.mjs"]
