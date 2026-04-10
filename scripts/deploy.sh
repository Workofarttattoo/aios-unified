#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# Ai:oS Unified — Production Deployment Script
# ──────────────────────────────────────────────────────────────────────
#
# Usage:
#   ./scripts/deploy.sh              # deploy with defaults
#   DEPLOY_ENV=staging ./scripts/deploy.sh
#
# Requirements:
#   - Docker & Docker Compose
#   - .env file with production secrets
# ──────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Configuration ───────────────────────────────────────────────────
DEPLOY_ENV="${DEPLOY_ENV:-production}"
IMAGE_NAME="${IMAGE_NAME:-aios-unified}"
IMAGE_TAG="${IMAGE_TAG:-$(git rev-parse --short HEAD 2>/dev/null || echo latest)}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-60}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[deploy]${NC} $*"; }
ok()   { echo -e "${GREEN}[  ok  ]${NC} $*"; }
warn() { echo -e "${YELLOW}[ warn ]${NC} $*"; }
err()  { echo -e "${RED}[error ]${NC} $*" >&2; }

# ── Pre-flight checks ──────────────────────────────────────────────
log "Environment: ${DEPLOY_ENV}"
log "Image:       ${IMAGE_NAME}:${IMAGE_TAG}"

if ! command -v docker &>/dev/null; then
    err "docker is not installed"
    exit 1
fi

if ! command -v docker compose &>/dev/null && ! command -v docker-compose &>/dev/null; then
    err "docker compose is not installed"
    exit 1
fi

if [ ! -f .env ]; then
    warn ".env file not found — copying from .env.example"
    if [ -f .env.example ]; then
        cp .env.example .env
    else
        err "No .env or .env.example found"
        exit 1
    fi
fi

# ── Build ───────────────────────────────────────────────────────────
log "Building image..."
docker compose -f "${COMPOSE_FILE}" build --no-cache
ok "Image built"

# ── Deploy ──────────────────────────────────────────────────────────
log "Starting services..."
docker compose -f "${COMPOSE_FILE}" up -d
ok "Services started"

# ── Health check ────────────────────────────────────────────────────
log "Waiting for health check (timeout: ${HEALTH_TIMEOUT}s)..."
elapsed=0
while [ $elapsed -lt "$HEALTH_TIMEOUT" ]; do
    status=$(docker inspect --format='{{.State.Health.Status}}' aios-unified 2>/dev/null || echo "starting")
    if [ "$status" = "healthy" ]; then
        ok "Service is healthy"
        break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done

if [ $elapsed -ge "$HEALTH_TIMEOUT" ]; then
    warn "Health check timed out after ${HEALTH_TIMEOUT}s"
    log "Container logs:"
    docker compose -f "${COMPOSE_FILE}" logs --tail=30 aios
fi

# ── Summary ─────────────────────────────────────────────────────────
echo ""
log "═══════════════════════════════════════"
ok "Deployment complete — ${DEPLOY_ENV}"
log "  Image:  ${IMAGE_NAME}:${IMAGE_TAG}"
log "  Status: $(docker inspect --format='{{.State.Status}}' aios-unified 2>/dev/null || echo unknown)"
log "═══════════════════════════════════════"
