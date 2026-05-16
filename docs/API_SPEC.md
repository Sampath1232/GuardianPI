# Guardian Pi — API Specification (OpenAPI Summary)

Base URL: `https://api.guardianpi.io/api/v1`

## Authentication

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/auth/login` | `{email, password}` | Returns JWT access + refresh tokens |
| POST | `/auth/refresh` | `{refresh_token}` | Rotates access token |
| POST | `/auth/register` | `{email, password, full_name}` | Admin-only user registration |

**Auth Headers:**
- Bearer: `Authorization: Bearer <jwt>`
- Agent API Key: `X-API-Key: gpi_xxxxx`

---

## Devices

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/devices/register` | API Key | Agent self-registration with device fingerprint |
| GET | `/devices` | JWT | List all devices (paginated) |
| GET | `/devices/{id}` | JWT | Device details + risk score |
| POST | `/devices/{id}/heartbeat` | API Key | Agent heartbeat with metrics |
| PATCH | `/devices/{id}` | JWT (admin) | Update device tags/status |
| DELETE | `/devices/{id}` | JWT (admin) | Deregister device |

---

## Alerts

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/alerts` | JWT | List alerts (filter: severity, status, device) |
| GET | `/alerts/{id}` | JWT | Alert details |
| PATCH | `/alerts/{id}/acknowledge` | JWT (analyst+) | Acknowledge alert |
| PATCH | `/alerts/{id}/resolve` | JWT (analyst+) | Resolve alert |
| PATCH | `/alerts/{id}/false-positive` | JWT (admin) | Mark as false positive |

---

## Telemetry

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/telemetry/ingest` | API Key | Ingest encrypted telemetry batch |

**Body:**
```json
{
  "device_id": "uuid",
  "timestamp": "ISO-8601",
  "encrypted_data": "base64",
  "nonce": "base64",
  "tag": "base64"
}
```

---

## Policies

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/policies` | JWT | List all policies |
| POST | `/policies` | JWT (admin) | Create policy |
| GET | `/policies/{id}` | JWT | Policy details |
| PATCH | `/policies/{id}` | JWT (admin) | Update policy |
| DELETE | `/policies/{id}` | JWT (admin) | Delete policy |
| GET | `/policies/agent/{os_type}` | API Key | Get policies for agent OS |

---

## Investigations

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/investigations` | JWT | List investigations |
| POST | `/investigations` | JWT (analyst+) | Create investigation |
| GET | `/investigations/{id}` | JWT | Investigation details + timeline |
| POST | `/investigations/{id}/timeline` | JWT (analyst+) | Add timeline entry |
| PATCH | `/investigations/{id}/assign` | JWT (admin) | Assign to analyst |
| PATCH | `/investigations/{id}/close` | JWT (analyst+) | Close with findings |

---

## Compliance

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/compliance/audit-log` | JWT | Immutable audit log (paginated) |
| GET | `/compliance/gdpr-export/{user_id}` | JWT (admin) | GDPR data export |
| GET | `/compliance/report` | JWT | Compliance posture report |

---

## Remediation

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/remediation` | JWT (admin) | Execute remediation action |
| POST | `/remediation/{id}/rollback` | JWT (admin) | Rollback remediation |

---

## Agent Management

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/agent/update/check` | API Key | Check for agent updates |
| POST | `/agent/update/publish` | JWT (admin) | Publish new agent binary |
| GET | `/agent/versions` | Public | List available versions |

---

## Metrics & Health

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/health/live` | Public | Kubernetes liveness probe |
| GET | `/health/ready` | Public | Kubernetes readiness probe |
| GET | `/metrics` | Internal | Prometheus metrics (text format) |

---

## WebSocket Endpoints

| URL | Description |
|-----|-------------|
| `ws://host/ws/alerts` | Real-time alert feed |
| `ws://host/ws/devices` | Device status stream |
| `ws://host/ws/telemetry` | Telemetry stream |

---

## Error Format

All errors return:
```json
{
  "detail": "Human-readable error message"
}
```

## Rate Limits

| Endpoint Group | Limit |
|---|---|
| Auth | 5 requests/minute |
| API (general) | 30 requests/second |
| Telemetry ingest | 100 requests/second |
| WebSocket | No limit (connection-based) |
