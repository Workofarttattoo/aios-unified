# ──────────────────────────────────────────────────────────────────────
# Ai:oS Unified — Makefile
# ──────────────────────────────────────────────────────────────────────
# Common shortcuts for local development and CI.
#
#   make help        — list available targets
#   make up          — build & start services
#   make test        — run the test suite
# ──────────────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help
SHELL := /bin/bash

IMAGE   := aios-unified
COMPOSE := docker compose

# ── Docker ──────────────────────────────────────────────────────────

.PHONY: build
build: ## Build the Docker image
	$(COMPOSE) build

.PHONY: up
up: ## Start services in the background
	$(COMPOSE) up -d --build

.PHONY: down
down: ## Stop and remove containers
	$(COMPOSE) down

.PHONY: restart
restart: down up ## Restart all services

.PHONY: logs
logs: ## Tail container logs
	$(COMPOSE) logs -f aios

.PHONY: shell
shell: ## Open a shell inside the running container
	$(COMPOSE) exec aios bash

.PHONY: ps
ps: ## Show running containers
	$(COMPOSE) ps

# ── Testing & Quality ───────────────────────────────────────────────

.PHONY: test
test: ## Run the test suite (pytest)
	python -m pytest tests/ -v --tb=short

.PHONY: lint
lint: ## Run linter (ruff)
	python -m ruff check . --fix

.PHONY: typecheck
typecheck: ## Run type checker (mypy, optional)
	python -m mypy aios/ --ignore-missing-imports || true

.PHONY: check
check: lint test ## Lint then test

# ── Local Dev ───────────────────────────────────────────────────────

.PHONY: install
install: ## Install Python dependencies locally
	pip install -r requirements.txt

.PHONY: run
run: ## Run the API server locally (no Docker)
	python -m uvicorn runtime_unified:app --host 0.0.0.0 --port $${PORT:-8080} --reload

.PHONY: cli-boot
cli-boot: ## Boot Ai:oS via the CLI
	python cli.py -v boot

.PHONY: cli-status
cli-status: ## Show Ai:oS status via the CLI
	python cli.py -v status

# ── Housekeeping ────────────────────────────────────────────────────

.PHONY: clean
clean: ## Remove caches, bytecode, temp files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	find . -type f -name '*.pyo' -delete 2>/dev/null || true
	find . -type f -name '*.tmp' -delete 2>/dev/null || true
	rm -rf .pytest_cache .mypy_cache .ruff_cache dist build *.egg-info

.PHONY: prune
prune: ## Docker system prune (reclaim disk)
	docker system prune -f

# ── Help ────────────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
