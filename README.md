# AI:OS Unified

<div align="center">

**Agentic Intelligence Operating System**

An autonomous control-plane that coordinates meta-agents and sub-agents through a declarative manifest, with real host inspection, quantum computing integration, and production-grade observability.

<a href="https://www.producthunt.com/products/ai-os?embed=true&utm_source=badge-featured&utm_medium=badge&utm_source=badge-ai&#0045;os" target="_blank"><img src="https://api.producthunt.com/widgets/embed-image/v1/featured.svg?post_id=1029998&theme=light&t=1761320709018" alt="Ai|oS on Product Hunt" style="width: 250px; height: 54px;" width="250" height="54" /></a>

</div>

---

## Overview

AI:OS (Ai:oS) is a concept operating system that orchestrates subsystem meta-agents through a **declarative manifest**. The runtime performs real host inspections — process snapshots, load averages, disk free space, firewall status, Docker/Multipass inventory, BitLocker/FileVault state — on both macOS and Linux so orchestration signals are rooted in actual machine state.

### Key Capabilities

| Area | Description |
|------|-------------|
| **Meta-Agent Orchestration** | Kernel, Security, Networking, Application, Scalability, Orchestration, and AI agents coordinated through a manifest-driven boot/shutdown lifecycle |
| **Quantum Computing** | Quantum state engine, VQE forecaster, HHL linear solver, and QuantumChip100 integration via Qiskit |
| **ML Algorithms** | Adaptive particle filters, neural-guided MCTS, Bayesian forecasting |
| **Observability** | Structured tracing (LangSmith-style), token/cost tracking, retry with exponential backoff |
| **Security Toolkit** | AuroraScan, CipherSpear, and sovereign security tools |
| **Virtualization** | QEMU/libvirt integration with forensic safeguards |
| **Natural Language Shell** | Route plain-English commands to the correct agent actions |

---

## Quick Start

### Prerequisites

- Python 3.10+
- Docker & Docker Compose (for containerised deployment)

### Local Development

```bash
# 1. Clone the repository
git clone https://github.com/Workofarttattoo/aios-unified.git
cd aios-unified

# 2. Install dependencies
pip install -r requirements.txt

# 3. Copy and configure environment
cp .env.example .env
# Edit .env with your API keys / secrets

# 4. Boot Ai:oS
python cli.py -v boot

# 5. Check status
python cli.py -v status
```

### Docker Deployment

```bash
cp .env.example .env       # configure secrets
make up                     # build & start
make logs                   # tail logs
```

### One-Command Deploy

```bash
./scripts/deploy.sh
```

---

## Project Structure

```
aios-unified/
├── aios/                   # Python package (forwarding shims + stubs)
│   ├── __init__.py
│   ├── config.py           # → config module
│   ├── runtime.py          # → runtime module
│   ├── agents/             # → agents/ package
│   └── ...
├── agents/                 # Meta-agent implementations
│   ├── kernel_agent.py     # Process & kernel management
│   ├── security_agent.py   # Firewall & threat response
│   ├── networking_agent.py # Network configuration
│   ├── application_agent.py
│   ├── scalability_agent.py
│   ├── orchestration_agent.py
│   ├── quantum_agent.py    # Quantum computing integration
│   └── ...
├── cli.py                  # CLI entrypoint (boot, status, exec, prompt)
├── config.py               # Declarative manifest definitions
├── runtime.py              # Production runtime with retry & tracing
├── runtime_unified.py      # FastAPI server entrypoint
├── model_router.py         # LLM model routing & response cache
├── observability.py        # Tracing & metrics
├── evaluation.py           # Agent evaluation harness
├── settings.py             # Environment-driven configuration
├── diagnostics.py          # System health & diagnostics
├── quantum/                # Quantum computing modules
├── modules/                # Workflow platform modules
├── tools/                  # Security & OSINT toolkit
├── tests/                  # Test suite
├── scripts/                # Deployment & utility scripts
│   └── deploy.sh
├── QuLabInfinite/          # Quantum lab platform
├── docs/                   # Documentation
├── Dockerfile              # Multi-stage production build
├── docker-compose.yml      # Compose for dev/staging
├── Makefile                # Common task shortcuts
├── requirements.txt        # Python dependencies
└── .env.example            # Environment variable template
```

---

## CLI Usage

The `cli.py` entrypoint wraps the runtime orchestrator:

```bash
# Boot the full agent manifest
python cli.py -v boot

# Check system status
python cli.py -v status

# Execute a specific action
python cli.py -v exec kernel.process_management

# Run a sequence of actions
python cli.py -v sequence "security.firewall,networking.network_configuration"

# Natural language prompt
python cli.py -v prompt "enable firewall and check container load"

# Custom manifest
python cli.py --manifest path/to/manifest.json -v boot

# Virtualization readiness report
python cli.py -v virtualization

# Setup wizard
python cli.py wizard
```

### Cloud Provider Integration

```bash
# AWS
python cli.py --env AGENTA_PROVIDER=aws --env AGENTA_AWS_REGION=us-west-2 -v exec scalability.monitor_load

# Azure
python cli.py --env AGENTA_PROVIDER=azure --env AGENTA_AZURE_SUBSCRIPTION=<sub-id> -v exec scalability.monitor_load

# GCP
python cli.py --env AGENTA_PROVIDER=gcloud --env AGENTA_GCP_PROJECT=<project> --env AGENTA_GCP_ZONE=<zone> -v exec scalability.monitor_load
```

---

## API

When running the FastAPI server (`make run` or Docker), the following endpoints are available:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | API root / health check |
| `GET` | `/health` | Detailed health status |
| `GET` | `/status` | Runtime status and loaded agents |
| `POST` | `/boot` | Trigger manifest boot sequence |
| `POST` | `/exec` | Execute a specific agent action |
| `POST` | `/prompt` | Natural language prompt routing |

API docs are auto-generated at `/docs` (Swagger) and `/redoc`.

---

## Environment Variables

See [`.env.example`](.env.example) for the full list. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | Logging verbosity |
| `PORT` | `8080` | HTTP listen port |
| `ALLOW_NETWORK_CALLS` | `false` | Enable outbound HTTP from agents |
| `USPTO_API_KEY` | — | USPTO Patent API key |
| `STRIPE_SECRET_KEY` | — | Stripe integration |
| `SENTRY_DSN` | — | Error tracking |
| `OPENAI_API_KEY` | — | OpenAI LLM provider |
| `AGENTA_PROVIDER` | — | Cloud provider (docker/aws/gcp/azure/qemu) |

---

## Testing

```bash
# Run all tests
make test

# Run a specific test file
python -m pytest tests/test_diagnostics.py -v

# Lint
make lint

# Full check (lint + test)
make check
```

---

## Makefile Targets

```
  build           Build the Docker image
  up              Start services in the background
  down            Stop and remove containers
  restart         Restart all services
  logs            Tail container logs
  shell           Open a shell inside the running container
  test            Run the test suite (pytest)
  lint            Run linter (ruff)
  check           Lint then test
  install         Install Python dependencies locally
  run             Run the API server locally (no Docker)
  clean           Remove caches, bytecode, temp files
  help            Show this help message
```

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  CLI / API                       │
│         (cli.py / runtime_unified.py)            │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│              Runtime Engine                       │
│  (manifest loading, retry, tracing, evaluation)  │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│            Meta-Agent Layer                       │
│  ┌─────────┐ ┌──────────┐ ┌───────────────┐     │
│  │ Kernel  │ │ Security │ │ Networking    │     │
│  └─────────┘ └──────────┘ └───────────────┘     │
│  ┌─────────┐ ┌──────────┐ ┌───────────────┐     │
│  │ App     │ │ Quantum  │ │ Scalability   │     │
│  └─────────┘ └──────────┘ └───────────────┘     │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│         Host / Cloud / Quantum Layer             │
│  (Docker, AWS, GCP, Azure, QEMU, Qiskit)        │
└─────────────────────────────────────────────────┘
```

---

## License

Copyright © 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. Patent Pending.

See [LICENSE](LICENSE) for details.
