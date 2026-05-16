# Guardian Pi — WebSocket Event Specification

## Connection URLs

| Channel | URL | Description |
|---------|-----|-------------|
| Alerts | `ws://host/ws/alerts` | Real-time security alert feed |
| Devices | `ws://host/ws/devices` | Device status changes |
| Telemetry | `ws://host/ws/telemetry` | Live telemetry stream |

## Event Types

### Server → Client (Push)

#### `new_alert`
Broadcast when a new security alert is created.
```json
{
  "type": "new_alert",
  "data": {
    "id": "uuid",
    "title": "Suspicious process: mimikatz.exe",
    "severity": "critical",
    "alert_type": "credential_access",
    "device_id": "uuid",
    "details": {
      "rule_id": "SIGMA-001",
      "mitre_tactic": "Credential Access",
      "mitre_technique": "T1003",
      "pid": 1234,
      "process_name": "mimikatz.exe"
    },
    "created_at": "2026-05-16T12:00:00Z"
  },
  "timestamp": "2026-05-16T12:00:00Z"
}
```

#### `device_update`
Broadcast when a device changes status.
```json
{
  "type": "device_update",
  "data": {
    "device_id": "uuid",
    "status": "online",
    "hostname": "WS-001",
    "cpu_percent": 45.2,
    "ram_percent": 72.1
  },
  "timestamp": "2026-05-16T12:00:00Z"
}
```

#### `alert_acknowledged`
Broadcast when an analyst acknowledges an alert.
```json
{
  "type": "alert_acknowledged",
  "data": {
    "alert_id": "uuid",
    "acknowledged_by": "analyst@guardian.io"
  },
  "timestamp": "2026-05-16T12:00:00Z"
}
```

### Client → Server

#### `ping` / `pong`
Keepalive mechanism.
```json
{"type": "ping"}
```
Server responds:
```json
{"type": "pong", "timestamp": "2026-05-16T12:00:00Z"}
```

## Connection Lifecycle

1. Client connects to WebSocket endpoint
2. Server accepts and adds to channel pool
3. Server broadcasts events to all connected clients
4. Client can send `ping` for keepalive
5. On disconnect, server removes client from pool
6. Clients should implement exponential backoff reconnection

## Authentication
Pass JWT token as query parameter: `ws://host/ws/alerts?token=<jwt>`
