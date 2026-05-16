# 🛡️ Guardian Pi — Security Hardening Guide

## Production Deployment Checklist

### 1. Secrets Management

- [ ] Generate cryptographic secrets for `SECRET_KEY` and `JWT_SECRET_KEY` (min 64 chars)
  ```bash
  python -c "import secrets; print(secrets.token_urlsafe(64))"
  ```
- [ ] Store all secrets in AWS Secrets Manager or HashiCorp Vault
- [ ] Never commit `.env` files to version control
- [ ] Rotate JWT secrets every 90 days
- [ ] Use distinct keys for each environment (dev/staging/prod)

### 2. Authentication & Authorization

- [ ] Enable MFA for all admin accounts (TOTP via Cognito)
- [ ] Set JWT access token expiry to ≤30 minutes
- [ ] Set refresh token expiry to ≤7 days
- [ ] Implement token blacklisting on logout
- [ ] Enforce minimum 12-character passwords with complexity
- [ ] Lock accounts after 5 failed login attempts
- [ ] Implement IP-based rate limiting on auth endpoints (5 req/min)

### 3. Network Security

- [ ] Terminate TLS at NGINX with TLS 1.2+ only
- [ ] Enable HSTS with `max-age=63072000; includeSubDomains; preload`
- [ ] Configure CSP headers to prevent XSS
- [ ] Use private subnets for PostgreSQL and Redis (no public exposure)
- [ ] Enable VPC peering or PrivateLink for AWS service access
- [ ] Apply Kubernetes NetworkPolicies (deny-all default)
- [ ] Enable mTLS between agents and backend

### 4. Database Security

- [ ] Use encrypted connections (`sslmode=require`)
- [ ] Enable encryption at rest (RDS: `storage_encrypted = true`)
- [ ] Create read-only replica users for analytics
- [ ] Enable audit logging on PostgreSQL
- [ ] Set `statement_timeout = 30000` to prevent long queries
- [ ] Backup every 4 hours with 30-day retention
- [ ] Test backup restoration quarterly

### 5. Container Security

- [ ] Run all containers as non-root (`USER 1000`)
- [ ] Use read-only root filesystems
- [ ] Drop all Linux capabilities (`drop: ["ALL"]`)
- [ ] Set `seccompProfile: RuntimeDefault`
- [ ] Scan images with Trivy on every CI build
- [ ] Pin base image digests (not just tags)
- [ ] Limit container resources (CPU/memory)

### 6. Agent Security

- [ ] Sign all agent binaries with GPG/Sigstore
- [ ] Verify SHA-256 hash before applying updates
- [ ] Use certificate pinning for server verification
- [ ] Encrypt offline queue data at rest
- [ ] Protect against binary tampering (self-hash verification)
- [ ] Detect debugger attachment
- [ ] Never quarantine protected OS processes
- [ ] Implement clean uninstall (no hidden persistence)

### 7. API Security

- [ ] Enable rate limiting: 30 req/s (API), 5 req/s (auth)
- [ ] Validate all input with Pydantic models
- [ ] Sanitize JSON output (no stack traces in production)
- [ ] Set `docs_url=None` in production
- [ ] Use CORS allowlists (not `*`)
- [ ] Log all API requests with IP and user-agent
- [ ] Implement request size limits (10MB max)

### 8. Audit & Compliance

- [ ] HMAC-sign all audit log entries
- [ ] Make audit_logs table immutable (trigger-enforced)
- [ ] Implement GDPR data export endpoint
- [ ] Enable data retention policies (90 days raw, 1 year aggregates)
- [ ] Export findings to SIEM (via Security Hub ASFF format)
- [ ] Generate compliance reports monthly

### 9. Monitoring & Alerting

- [ ] Expose Prometheus metrics at `/api/v1/metrics` (internal only)
- [ ] Configure Grafana alerts for: critical alerts >0, devices offline >30min
- [ ] Forward logs to Loki/ELK for centralized analysis
- [ ] Monitor NATS JetStream lag
- [ ] Set up PagerDuty/Opsgenie for critical severity alerts

### 10. Incident Response

- [ ] Define incident severity matrix (P0-P4)
- [ ] Create investigation workflow with timeline tracking
- [ ] Map all detections to MITRE ATT&CK framework
- [ ] Implement automated remediation playbooks (quarantine → investigate → resolve)
- [ ] Conduct tabletop exercises quarterly
- [ ] Maintain incident runbook in docs/

---

## Ethical Constraints (Hardcoded — NEVER Override)

These constraints are embedded in every agent and backend module:

| Constraint | Enforcement |
|---|---|
| No unauthorized access | All endpoints require JWT or API key |
| No credential theft | No plaintext password logging, bcrypt only |
| No device bricking | Protected process list prevents critical process termination |
| No hidden persistence | Clean uninstall removes ALL files, systemd service |
| No self-propagation | Agent only connects to configured server |
| No offensive capability | Detection-only; no exploitation code exists |
| No retaliation | Block/quarantine only, never attack back |
| Full audit trail | Every action logged with HMAC signature |
| Consent required | Agent requires explicit admin installation |
| Rollback support | Every remediation action has undo capability |
