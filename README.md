# 🛡️ Guardian Pi — Defensive Security Platform v2

[![CI/CD](https://github.com/your-org/guardian-pi/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/guardian-pi/actions)
[![Go Agent](https://img.shields.io/badge/Agent-Go%201.22-00ADD8?logo=go)](edge-agent/)
[![Python API](https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi)](backend/)
[![Flutter](https://img.shields.io/badge/Mobile-Flutter-02569B?logo=flutter)](mobile/)

Production-grade, cross-platform **Endpoint Detection & Response (EDR)** platform for authorized defensive security monitoring, threat detection, and automated remediation.

> ⚠️ **Authorized Use Only** — Guardian Pi is designed exclusively for defensive security on systems you own or have explicit authorization to monitor. It never performs unauthorized access, credential theft, device damage, or offensive actions.

---

## 🏗️ System Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                    FRONTEND / MOBILE                              │
│  ┌─────────────────┐  ┌──────────────────┐  ┌────────────────┐  │
│  │  React Console   │  │  Flutter Mobile   │  │  Grafana       │  │
│  │  (Vite + TS)     │  │  (iOS/Android)    │  │  (Dashboards)  │  │
│  └────────┬─────────┘  └────────┬──────────┘  └────────┬───────┘  │
│           │ REST/WS             │ REST                  │ Prom     │
├───────────┼─────────────────────┼──────────────────────┼──────────┤
│           ▼                     ▼                      ▼          │
│  ┌──────────────────── NGINX TLS Proxy ──────────────────────┐   │
│  │  Rate Limiting • TLS 1.3 • WebSocket Upgrade • HSTS       │   │
│  └──────────────────────────┬────────────────────────────────┘   │
│                              ▼                                    │
│  ┌──────────────── FastAPI Backend (Async) ───────────────────┐  │
│  │                                                             │  │
│  │  ┌──────┐ ┌────────┐ ┌────────┐ ┌──────────┐ ┌──────────┐│  │
│  │  │ Auth │ │Devices │ │ Alerts │ │ Policies │ │Investig. ││  │
│  │  │ JWT  │ │Registry│ │ Center │ │ Engine   │ │ Workflow ││  │
│  │  └──────┘ └────────┘ └────────┘ └──────────┘ └──────────┘│  │
│  │  ┌──────┐ ┌────────┐ ┌────────┐ ┌──────────┐ ┌──────────┐│  │
│  │  │Telem.│ │Remedtn.│ │Complnc.│ │  Metrics │ │  Agent   ││  │
│  │  │AES-GCM│ │Rollback│ │ HMAC   │ │Prometheus│ │  Update  ││  │
│  │  └──────┘ └────────┘ └────────┘ └──────────┘ └──────────┘│  │
│  │                                                             │  │
│  │  ┌─────── Services ────────────────────────────────────┐   │  │
│  │  │ Detection Engine │ Alert Pipeline │ NATS Event Bus  │   │  │
│  │  │ Sigma + YARA     │ Anomaly Scoring│ JetStream       │   │  │
│  │  └─────────────────────────────────────────────────────┘   │  │
│  └─────┬──────────┬──────────┬──────────┬─────────────────────┘  │
│        ▼          ▼          ▼          ▼                         │
│  ┌──────────┐┌─────────┐┌───────────┐┌──────┐                   │
│  │PostgreSQL││  Redis   ││TimescaleDB││ NATS │                   │
│  │   Data   ││  Cache   ││ Telemetry ││Events│                   │
│  └──────────┘└─────────┘└───────────┘└──────┘                   │
├──────────────────────────────────────────────────────────────────┤
│                    mTLS + Encrypted Telemetry                     │
├──────────────────────────────────────────────────────────────────┤
│  ┌──────────────── Go Edge Agent (Lightweight) ──────────────┐   │
│  │ System Telemetry │ Process Monitor │ File Integrity        │   │
│  │ Network Monitor  │ Detection Engine │ Offline Queue        │   │
│  │ mTLS Transport   │ Heartbeat        │ Auto-Update          │   │
│  └────────────────────────────────────────────────────────────┘   │
│  Platforms: Windows │ Linux │ macOS │ Raspberry Pi │ ARM Edge     │
└───────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Go 1.22+ (agent development)
- Python 3.12+ (backend development)
- Node.js 18+ (console development)
- Flutter 3.19+ (mobile development)

### 1. Clone & Configure
```bash
git clone https://github.com/your-org/guardian-pi.git
cd guardian-pi
cp .env.example .env
# Edit .env with your secrets
```

### 2. Start Full Stack (Docker)
```bash
docker-compose up -d
```
Services: API (:8000) • PostgreSQL (:5432) • TimescaleDB (:5433) • Redis (:6379) • NATS (:4222) • Prometheus (:9090) • Grafana (:3001) • Loki (:3100)

### 3. Management Console
```bash
cd console && npm install && npm run dev
```
Open http://localhost:5173

### 4. Build & Run Go Agent
```bash
cd edge-agent
go build -o guardian-agent ./cmd/agent
./guardian-agent --server http://localhost:8000 --api-key gpi_dev_test_key_change_in_production
```

### 5. Mobile Companion App
```bash
cd mobile && flutter pub get && flutter run
```

---

## 📁 Project Structure

```
GuardianPI/
├── backend/                    # FastAPI async backend
│   ├── app/
│   │   ├── api/v1/             # 13 REST + WebSocket routers
│   │   ├── core/               # Config, security, database, Redis
│   │   ├── models/             # 6 SQLAlchemy ORM models
│   │   ├── schemas/            # Pydantic validation
│   │   ├── services/           # Detection, alert pipeline, compliance, NATS
│   │   ├── middleware/         # Security headers, request logging
│   │   └── integrations/aws/  # GuardDuty, Security Hub
│   ├── tests/                  # Pytest async test suite
│   └── alembic/                # Database migrations
│
├── edge-agent/                 # Go edge agent (lightweight)
│   ├── cmd/agent/              # Main entry point
│   └── internal/
│       ├── collector/          # System telemetry, process, file, network
│       ├── detector/           # Sigma-style detection rules (8 rules)
│       ├── transport/          # mTLS HTTP client
│       ├── queue/              # Disk-backed offline queue
│       └── config/             # Configuration + threat database
│
├── agent/                      # Python agent (cross-platform)
│   ├── detectors/              # Device fingerprinting
│   ├── monitors/               # Process, file, network, USB
│   ├── security/               # Anti-tamper, AES-256-GCM crypto
│   ├── remediation/            # Quarantine, firewall manager
│   └── telemetry/              # Encrypted telemetry sender
│
├── console/                    # React management dashboard
│   └── src/                    # Dashboard, Devices, Alerts, Compliance
│
├── mobile/                     # Flutter companion app
│   └── lib/
│       ├── screens/            # 5 screens (login, dashboard, alerts, devices, settings)
│       ├── services/           # Auth with biometrics, API client
│       └── theme/              # Dark theme matching web console
│
├── infrastructure/
│   ├── terraform/              # AWS: VPC, RDS, ECS, GuardDuty, WAF, Cognito
│   ├── kubernetes/             # K8s: Deployment, HPA, DaemonSet, NetworkPolicy
│   ├── nginx/                  # Reverse proxy with TLS, rate limiting, WS
│   ├── timescaledb/            # Hypertables, continuous aggregates, compression
│   ├── grafana/                # Dashboard JSON + provisioning
│   └── prometheus.yml          # Scrape configs
│
├── database/                   # SQL schema with seed data
├── docs/                       # API spec, WebSocket events, hardening guide
├── .github/workflows/          # CI/CD: SAST, tests, multi-arch builds, deploy
└── docker-compose.yml          # Full stack with 9 services
```

## 🔒 Detection Capabilities

### Sigma-Style Rules (MITRE ATT&CK Mapped)

| Rule ID | Detection | MITRE | Severity |
|---------|-----------|-------|----------|
| SIGMA-001 | Mimikatz / credential dumping | T1003 | Critical |
| SIGMA-002 | Reverse shell patterns | T1059 | Critical |
| SIGMA-003 | Brute force tools (hydra, john) | T1110 | High |
| SIGMA-004 | Suspicious persistence (cron, schtasks) | T1053 | High |
| SIGMA-005 | Encoded PowerShell execution | T1027 | High |
| SIGMA-006 | C2 port communication | T1571 | Medium |
| SIGMA-007 | Debugger / tamper tools | T1622 | Medium |
| SIGMA-008 | Lateral movement tools (psexec) | T1021 | High |

### YARA-Style Signatures
- Shellcode patterns • Metasploit markers • Cobalt Strike beacons • Mimikatz strings • PowerSploit indicators

### Heuristic Anomaly Scoring
- CPU spike detection (>90%) • RAM exhaustion (>95%) • Connection burst (>500) • Process count anomalies

## 🌍 Platform Support

| Platform | Agent | Status |
|----------|-------|--------|
| Windows 10/11 | Go + Python | ✅ Production |
| Ubuntu/Debian | Go + Python | ✅ Production |
| macOS | Go + Python | ✅ Production |
| Raspberry Pi | Go (ARM64) | ✅ Production |
| ARM Edge Devices | Go (ARM) | ✅ Production |
| Android | Flutter Mobile | ✅ Companion App |
| iOS | Flutter Mobile | ✅ Companion App |

## 📡 Real-Time System

- **WebSocket Gateway**: 3 channels (alerts, devices, telemetry) with auto-reconnect
- **NATS JetStream**: Event bus with 7-day retention, 512MB per stream
- **Alert Pipeline**: Telemetry → Sigma matching → Anomaly scoring → Alert creation → WS broadcast

## 📊 Observability

- **Prometheus**: Custom metrics (devices, alerts, WebSocket connections, uptime)
- **Grafana**: Pre-built security dashboard with alerting
- **Loki**: Centralized structured logging
- **Health Probes**: Kubernetes-compatible liveness + readiness endpoints

## 📜 Documentation

| Document | Description |
|----------|-------------|
| [API Specification](docs/API_SPEC.md) | Full REST + WebSocket API reference |
| [WebSocket Events](docs/WEBSOCKET_EVENTS.md) | Event types, formats, and lifecycle |
| [Security Hardening](docs/SECURITY_HARDENING.md) | 10-category production hardening checklist |
| [Database Schema](database/schema.sql) | Full SQL with triggers and seed data |

## 📜 License

MIT — See [LICENSE](LICENSE) for details.
