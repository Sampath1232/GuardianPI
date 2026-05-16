"""
Guardian Pi — Local Development Server
Runs both backend API + frontend from a single command.
Uses SQLite (no PostgreSQL needed) and mock Redis.
Usage: python run_local.py
"""
import asyncio
import json
import logging
import os
import subprocess
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Patch environment BEFORE any app imports ────────────────────
os.environ["ENVIRONMENT"] = "development"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./guardian_local.db"
os.environ["REDIS_URL"] = "mock://localhost"
os.environ["LOG_LEVEL"] = "INFO"
os.environ["CORS_ORIGINS"] = '["http://localhost:5173","http://localhost:3000","http://localhost:8000"]'
os.environ["AGENT_API_KEYS"] = '["gpi_local_dev_key"]'

# ── Install missing deps if needed ──────────────────────────────
def ensure_deps():
    required = {
        "fastapi": "fastapi",
        "uvicorn": "uvicorn[standard]",
        "sqlalchemy": "sqlalchemy[asyncio]",
        "aiosqlite": "aiosqlite",
        "jose": "python-jose[cryptography]",
        "bcrypt": "bcrypt",
        "pydantic_settings": "pydantic-settings",
        "multipart": "python-multipart",
    }
    missing = []
    for mod, pkg in required.items():
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"Installing missing packages: {', '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing, "-q"])

ensure_deps()

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

# ── Logging ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("guardian.local")

# ── SQLite-compatible DB setup ──────────────────────────────────
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Boolean, Integer, DateTime, Text, JSON, ForeignKey, select, func
import sqlalchemy as sa

DB_PATH = Path("./guardian_local.db")
engine = create_async_engine("sqlite+aiosqlite:///./guardian_local.db", echo=False)
async_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

# ── Models (SQLite-compatible) ──────────────────────────────────
class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login: Mapped[Optional[str]] = mapped_column(String(50))
    created_at: Mapped[str] = mapped_column(String(50), default=lambda: datetime.now(timezone.utc).isoformat())

class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    os_type: Mapped[str] = mapped_column(String(50), nullable=False)
    os_version: Mapped[str] = mapped_column(String(100), default="")
    architecture: Mapped[str] = mapped_column(String(50), default="x86_64")
    cpu_model: Mapped[Optional[str]] = mapped_column(String(255))
    cpu_cores: Mapped[int] = mapped_column(Integer, default=4)
    ram_mb: Mapped[int] = mapped_column(Integer, default=8192)
    storage_gb: Mapped[Optional[int]] = mapped_column(Integer)
    agent_version: Mapped[str] = mapped_column(String(50), default="2.0.0")
    status: Mapped[str] = mapped_column(String(50), default="online")
    is_rooted: Mapped[bool] = mapped_column(Boolean, default=False)
    is_virtual: Mapped[bool] = mapped_column(Boolean, default=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    last_heartbeat: Mapped[Optional[str]] = mapped_column(String(50))
    registered_at: Mapped[str] = mapped_column(String(50), default=lambda: datetime.now(timezone.utc).isoformat())
    metadata_json: Mapped[Optional[str]] = mapped_column(Text)

class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[Optional[str]] = mapped_column(String(36))
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    category: Mapped[str] = mapped_column(String(100), default="system")
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(50), default="open")
    source: Mapped[Optional[str]] = mapped_column(String(100))
    evidence: Mapped[Optional[str]] = mapped_column(Text)
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(100))
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(100))
    created_at: Mapped[str] = mapped_column(String(50), default=lambda: datetime.now(timezone.utc).isoformat())

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(100), default="system")
    details: Mapped[Optional[str]] = mapped_column(Text)
    hmac_signature: Mapped[str] = mapped_column(String(128), default="local")
    created_at: Mapped[str] = mapped_column(String(50), default=lambda: datetime.now(timezone.utc).isoformat())

class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    rules: Mapped[str] = mapped_column(Text, default="{}")
    severity: Mapped[str] = mapped_column(String(50), default="medium")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    target_os: Mapped[str] = mapped_column(Text, default='["windows","linux","macos"]')
    created_at: Mapped[str] = mapped_column(String(50), default=lambda: datetime.now(timezone.utc).isoformat())

class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(50), default="open")
    priority: Mapped[str] = mapped_column(String(50), default="medium")
    timeline: Mapped[str] = mapped_column(Text, default="[]")
    findings: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String(50), default=lambda: datetime.now(timezone.utc).isoformat())

# ── Auth helpers ────────────────────────────────────────────────
import secrets, hashlib, hmac as hmac_mod
from jose import jwt as jose_jwt

SECRET_KEY = secrets.token_urlsafe(32)
JWT_ALG = "HS256"

def hash_pw(password: str) -> str:
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()

def verify_pw(plain: str, hashed: str) -> bool:
    import bcrypt
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def make_token(user_id: str, role: str) -> str:
    return jose_jwt.encode({"sub": user_id, "role": role, "type": "access",
        "exp": int(time.time()) + 3600}, SECRET_KEY, algorithm=JWT_ALG)

def make_refresh(user_id: str) -> str:
    return jose_jwt.encode({"sub": user_id, "type": "refresh",
        "exp": int(time.time()) + 604800}, SECRET_KEY, algorithm=JWT_ALG)

def decode_tok(token: str) -> dict:
    return jose_jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALG])

async def get_db():
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    try:
        payload = decode_tok(auth[7:])
    except Exception:
        raise HTTPException(401, "Invalid token")
    result = await db.execute(select(User).where(User.id == payload["sub"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(401, "User not found")
    return user

# ── Seed data ───────────────────────────────────────────────────
async def seed_data():
    async with async_session_factory() as db:
        existing = await db.execute(select(User).where(User.email == "admin@guardianpi.io"))
        if existing.scalar_one_or_none():
            return

        admin = User(email="admin@guardianpi.io", password_hash=hash_pw("admin123456"),
                     full_name="Admin", role="admin")
        db.add(admin)

        devices_data = [
            ("WS-001", "windows", "Windows 11 Pro", "x86_64", "Intel i7-13700K", 16, 32768, 512, "online"),
            ("SRV-002", "linux", "Ubuntu 24.04 LTS", "x86_64", "AMD EPYC 7543", 32, 65536, 2048, "online"),
            ("PI-003", "raspberrypi", "Raspberry Pi OS", "arm64", "BCM2711", 4, 8192, 64, "online"),
            ("MAC-004", "macos", "macOS Sonoma 14.5", "arm64", "Apple M3 Pro", 12, 18432, 512, "online"),
            ("LNX-005", "linux", "Debian 12", "x86_64", "Intel Xeon E-2388G", 8, 16384, 256, "offline"),
            ("DRD-006", "android", "Android 14", "arm64", "Snapdragon 8 Gen 3", 8, 12288, 256, "online"),
        ]
        for hn, os_t, os_v, arch, cpu, cores, ram, st, status in devices_data:
            db.add(Device(hostname=hn, os_type=os_t, os_version=os_v, architecture=arch,
                         cpu_model=cpu, cpu_cores=cores, ram_mb=ram, storage_gb=st, status=status,
                         last_heartbeat=datetime.now(timezone.utc).isoformat()))

        alerts_data = [
            ("critical", "malware", "Suspicious process: mimikatz.exe", "WS-001", "Credential dumping tool detected", "Credential Access", "T1003"),
            ("critical", "tamper", "Debugger attached to agent process", "SRV-002", "Anti-tamper violation detected", "Defense Evasion", "T1622"),
            ("high", "integrity", "File integrity change: /etc/shadow", "PI-003", "Critical system file modified", "Persistence", "T1098"),
            ("high", "intrusion", "Brute-force tool detected: hydra", "SRV-002", "Password attack tool running", "Credential Access", "T1110"),
            ("medium", "anomaly", "Connection spike: 250 active connections", "SRV-002", "Unusual network activity", "Command and Control", "T1571"),
            ("medium", "policy", "Unknown USB device connected", "WS-001", "Unauthorized peripheral", "Collection", "T1025"),
            ("low", "system", "Agent updated to v2.0.0", "MAC-004", "Routine agent update", None, None),
        ]
        device_map = {d[0]: None for d in devices_data}
        result = await db.execute(select(Device))
        for dev in result.scalars().all():
            device_map[dev.hostname] = dev.id

        for sev, cat, title, dev_hn, desc, tactic, tech in alerts_data:
            db.add(Alert(severity=sev, category=cat, title=title,
                        device_id=device_map.get(dev_hn), description=desc,
                        source="agent", mitre_tactic=tactic, mitre_technique=tech))

        policies_data = [
            ("Suspicious Process Detection", "endpoint", '{"patterns":["mimikatz","hydra","hashcat"]}', "critical"),
            ("File Integrity Monitoring", "compliance", '{"paths":["/etc/passwd","/etc/shadow"]}', "high"),
            ("Network Anomaly Detection", "network", '{"max_connections":200}', "medium"),
        ]
        for name, cat, rules, sev in policies_data:
            db.add(Policy(name=name, category=cat, rules=rules, severity=sev))

        db.add(AuditLog(action="system_startup", category="system", details='{"version":"2.0.0"}'))
        await db.commit()
        logger.info("Database seeded with demo data")

# ── App lifespan ────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Guardian Pi Local Server starting...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await seed_data()
    logger.info("Database ready (SQLite)")
    yield
    await engine.dispose()

# ── FastAPI App ─────────────────────────────────────────────────
app = FastAPI(title="Guardian Pi", version="2.0.0",
              description="Local development server", lifespan=lifespan,
              docs_url="/docs", redoc_url="/redoc")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

# ── API Routes ──────────────────────────────────────────────────

@app.get("/")
async def root():
    return {"name": "Guardian Pi", "version": "2.0.0", "status": "operational", "docs": "/docs"}

@app.get("/api/v1/health/live")
async def health_live():
    return {"status": "alive"}

@app.get("/api/v1/health/ready")
async def health_ready():
    return {"status": "ready", "database": "sqlite", "mode": "local"}

# Auth
@app.post("/api/v1/auth/login")
async def login(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    result = await db.execute(select(User).where(User.email == body.get("email")))
    user = result.scalar_one_or_none()
    if not user or not verify_pw(body.get("password", ""), user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    user.last_login = datetime.now(timezone.utc).isoformat()
    return {"access_token": make_token(user.id, user.role), "refresh_token": make_refresh(user.id),
            "token_type": "bearer", "expires_in": 3600}

@app.get("/api/v1/auth/me")
async def get_me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "full_name": user.full_name,
            "role": user.role, "is_active": user.is_active}

# Devices
@app.get("/api/v1/devices")
async def list_devices(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Device))
    devices = result.scalars().all()
    return {"devices": [{"id": d.id, "hostname": d.hostname, "os_type": d.os_type,
        "os_version": d.os_version, "architecture": d.architecture, "cpu_model": d.cpu_model,
        "cpu_cores": d.cpu_cores, "ram_mb": d.ram_mb, "storage_gb": d.storage_gb,
        "agent_version": d.agent_version, "status": d.status, "is_rooted": d.is_rooted,
        "is_virtual": d.is_virtual, "last_heartbeat": d.last_heartbeat,
        "registered_at": d.registered_at} for d in devices], "total": len(devices)}

@app.get("/api/v1/devices/{device_id}")
async def get_device(device_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Device).where(Device.id == device_id))
    d = result.scalar_one_or_none()
    if not d: raise HTTPException(404, "Device not found")
    return {"id": d.id, "hostname": d.hostname, "os_type": d.os_type, "status": d.status,
            "os_version": d.os_version, "cpu_model": d.cpu_model, "ram_mb": d.ram_mb}

# Alerts
@app.get("/api/v1/alerts")
async def list_alerts(db: AsyncSession = Depends(get_db), severity: str = None, status_filter: str = None):
    query = select(Alert).order_by(Alert.created_at.desc())
    if severity: query = query.where(Alert.severity == severity)
    if status_filter: query = query.where(Alert.status == status_filter)
    result = await db.execute(query)
    alerts = result.scalars().all()
    return {"alerts": [{"id": a.id, "device_id": a.device_id, "severity": a.severity,
        "category": a.category, "title": a.title, "description": a.description,
        "status": a.status, "source": a.source, "mitre_tactic": a.mitre_tactic,
        "mitre_technique": a.mitre_technique, "created_at": a.created_at} for a in alerts],
        "total": len(alerts)}

@app.patch("/api/v1/alerts/{alert_id}/acknowledge")
async def ack_alert(alert_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert: raise HTTPException(404)
    alert.status = "acknowledged"
    return {"status": "acknowledged"}

# Telemetry ingest
@app.post("/api/v1/telemetry/ingest")
async def ingest_telemetry(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    device_id = body.get("device_id")
    events = body.get("data", {}).get("events", [])
    created = 0
    for evt in events:
        sev = evt.get("severity", "info")
        if sev in ("critical", "high", "medium"):
            db.add(Alert(device_id=device_id, severity=sev, title=evt.get("title", "Agent event"),
                        category=evt.get("event_type", "agent"), source="agent"))
            created += 1
    return {"status": "ingested", "events": len(events), "alerts_created": created}

# Policies
@app.get("/api/v1/policies")
async def list_policies(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Policy))
    policies = result.scalars().all()
    return {"policies": [{"id": p.id, "name": p.name, "description": p.description,
        "category": p.category, "severity": p.severity, "is_enabled": p.is_enabled,
        "created_at": p.created_at} for p in policies], "total": len(policies)}

# Investigations
@app.get("/api/v1/investigations")
async def list_investigations(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Investigation))
    items = result.scalars().all()
    return {"investigations": [{"id": i.id, "title": i.title, "status": i.status,
        "priority": i.priority, "created_at": i.created_at} for i in items]}

@app.post("/api/v1/investigations")
async def create_investigation(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.json()
    inv = Investigation(title=body["title"], description=body.get("description"),
                        priority=body.get("priority", "medium"))
    db.add(inv)
    await db.flush()
    return {"id": inv.id, "title": inv.title, "status": inv.status}

# Compliance
@app.get("/api/v1/compliance/audit-log")
async def audit_log(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()))
    logs = result.scalars().all()
    return {"logs": [{"id": l.id, "action": l.action, "category": l.category,
        "details": l.details, "created_at": l.created_at} for l in logs]}

# Metrics (Prometheus format)
@app.get("/api/v1/metrics")
async def metrics(db: AsyncSession = Depends(get_db)):
    devices = (await db.execute(select(func.count()).select_from(Device))).scalar() or 0
    online = (await db.execute(select(func.count()).select_from(Device).where(Device.status == "online"))).scalar() or 0
    alerts = (await db.execute(select(func.count()).select_from(Alert))).scalar() or 0
    open_a = (await db.execute(select(func.count()).select_from(Alert).where(Alert.status == "open"))).scalar() or 0
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(
        f"guardian_devices_total {devices}\nguardian_devices_online {online}\n"
        f"guardian_alerts_total {alerts}\nguardian_alerts_open {open_a}\n",
        media_type="text/plain")

# WebSocket
from fastapi import WebSocket, WebSocketDisconnect
ws_clients = set()

@app.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    await ws.accept()
    ws_clients.add(ws)
    try:
        while True:
            data = await ws.receive_text()
            if '"ping"' in data:
                await ws.send_json({"type": "pong", "timestamp": datetime.now(timezone.utc).isoformat()})
    except WebSocketDisconnect:
        ws_clients.discard(ws)

# ── Main ────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("")
    print("=" * 60)
    print("   Guardian Pi -- Local Dev Server")
    print("=" * 60)
    print("")
    print("   Backend API:  http://localhost:8000")
    print("   API Docs:     http://localhost:8000/docs")
    print("   Frontend:     http://localhost:5173 (run separately)")
    print("")
    print("   Login: admin@guardianpi.io / admin123456")
    print("   DB:    SQLite (guardian_local.db)")
    print("")
    print("=" * 60)
    print("")
    uvicorn.run(
        "run_local:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=["backend", "routes", "modules"],
        reload_includes=["run_local.py", "*.py"],
        reload_excludes=["console/*", "node_modules/*", ".venv/*", "venv/*", "__pycache__/*", "*.db"],
    )
