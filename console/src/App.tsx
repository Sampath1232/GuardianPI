import { useState } from 'react'
import './App.css'

type Page = 'dashboard' | 'devices' | 'alerts' | 'compliance'

function App() {
  const [activePage, setActivePage] = useState<Page>('dashboard')
  const [alertCount] = useState(7)

  return (
    <>
      {/* Sidebar */}
      <nav className="sidebar">
        <div className="sidebar-header">
          <div className="sidebar-logo">
            <div className="logo-icon">🛡️</div>
            <div>
              <h1>Guardian Pi</h1>
              <span className="version">v1.0.0</span>
            </div>
          </div>
        </div>
        <div className="sidebar-nav">
          <div className="nav-section">
            <div className="nav-section-title">Overview</div>
            <button className={`nav-item ${activePage === 'dashboard' ? 'active' : ''}`} onClick={() => setActivePage('dashboard')}>
              <span className="icon">📊</span> Dashboard
            </button>
            <button className={`nav-item ${activePage === 'devices' ? 'active' : ''}`} onClick={() => setActivePage('devices')}>
              <span className="icon">💻</span> Devices
              <span className="badge">12</span>
            </button>
          </div>
          <div className="nav-section">
            <div className="nav-section-title">Security</div>
            <button className={`nav-item ${activePage === 'alerts' ? 'active' : ''}`} onClick={() => setActivePage('alerts')}>
              <span className="icon">🚨</span> Alerts
              {alertCount > 0 && <span className="badge">{alertCount}</span>}
            </button>
            <button className={`nav-item ${activePage === 'compliance' ? 'active' : ''}`} onClick={() => setActivePage('compliance')}>
              <span className="icon">📋</span> Compliance
            </button>
          </div>
          <div className="nav-section">
            <div className="nav-section-title">System</div>
            <button className="nav-item">
              <span className="icon">⚙️</span> Settings
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="main-content">
        <div className="top-bar">
          <h2>{activePage === 'dashboard' ? 'Security Dashboard' : activePage === 'devices' ? 'Device Inventory' : activePage === 'alerts' ? 'Alert Center' : 'Compliance & Audit'}</h2>
          <div className="top-bar-actions">
            <div className="status-indicator">
              <span className="status-dot"></span>
              All Systems Operational
            </div>
            <button className="btn btn-outline">🔄 Refresh</button>
          </div>
        </div>

        <div className="page-content">
          {activePage === 'dashboard' && <DashboardPage />}
          {activePage === 'devices' && <DevicesPage />}
          {activePage === 'alerts' && <AlertsPage />}
          {activePage === 'compliance' && <CompliancePage />}
        </div>
      </main>
    </>
  )
}

/* ── Dashboard Page ──────────────────────────────────────── */
function DashboardPage() {
  return (
    <>
      <div className="stats-grid">
        <div className="stat-card animate-in delay-1">
          <div className="stat-header">
            <span className="stat-label">Total Devices</span>
            <div className="stat-icon">💻</div>
          </div>
          <div className="stat-value">12</div>
          <div className="stat-change">+2 this week</div>
        </div>
        <div className="stat-card danger animate-in delay-2">
          <div className="stat-header">
            <span className="stat-label">Active Alerts</span>
            <div className="stat-icon" style={{ background: 'rgba(239,68,68,0.15)' }}>🚨</div>
          </div>
          <div className="stat-value">7</div>
          <div className="stat-change negative">+3 since yesterday</div>
        </div>
        <div className="stat-card success animate-in delay-3">
          <div className="stat-header">
            <span className="stat-label">Threats Blocked</span>
            <div className="stat-icon" style={{ background: 'rgba(16,185,129,0.15)' }}>🛡️</div>
          </div>
          <div className="stat-value">143</div>
          <div className="stat-change">All-time</div>
        </div>
        <div className="stat-card animate-in delay-4">
          <div className="stat-header">
            <span className="stat-label">Uptime</span>
            <div className="stat-icon">⏱️</div>
          </div>
          <div className="stat-value">99.9%</div>
          <div className="stat-change">Last 30 days</div>
        </div>
      </div>

      <div className="grid-2">
        <div className="panel animate-in delay-2">
          <div className="panel-header">
            <span className="panel-title">Security Posture</span>
          </div>
          <div className="posture-meter">
            <div className="posture-ring" style={{ background: `conic-gradient(var(--accent-green) 0deg, var(--accent-cyan) ${85 * 3.6}deg, var(--bg-card) ${85 * 3.6}deg)` }}>
              <div className="posture-ring-inner">
                <span className="posture-score">85</span>
                <span className="posture-label">Score</span>
              </div>
            </div>
            <p style={{ marginTop: 16, color: 'var(--accent-green)', fontWeight: 600 }}>✓ Healthy</p>
          </div>
        </div>

        <div className="panel animate-in delay-3">
          <div className="panel-header">
            <span className="panel-title">Recent Alerts</span>
            <button className="btn btn-outline" style={{ padding: '6px 12px', fontSize: 12 }}>View All</button>
          </div>
          <div className="panel-body">
            <div className="alert-list">
              <div className="alert-item critical">
                <span className="severity-badge critical">Critical</span>
                <div className="alert-info">
                  <div className="alert-title">Suspicious process: mimikatz.exe</div>
                  <div className="alert-meta">Device: WS-001 • 2 min ago</div>
                </div>
              </div>
              <div className="alert-item high">
                <span className="severity-badge high">High</span>
                <div className="alert-info">
                  <div className="alert-title">File integrity change: /etc/shadow</div>
                  <div className="alert-meta">Device: PI-003 • 15 min ago</div>
                </div>
              </div>
              <div className="alert-item medium">
                <span className="severity-badge medium">Medium</span>
                <div className="alert-info">
                  <div className="alert-title">Connection spike: 250 connections</div>
                  <div className="alert-meta">Device: SRV-002 • 1 hr ago</div>
                </div>
              </div>
              <div className="alert-item low">
                <span className="severity-badge low">Low</span>
                <div className="alert-info">
                  <div className="alert-title">USB device connected</div>
                  <div className="alert-meta">Device: WS-005 • 3 hr ago</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="panel animate-in delay-4">
        <div className="panel-header">
          <span className="panel-title">System Resources</span>
        </div>
        <div className="panel-body">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 24 }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, color: 'var(--text-secondary)' }}>
                <span>CPU Usage</span><span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>45%</span>
              </div>
              <div className="progress-bar"><div className="progress-fill" style={{ width: '45%' }}></div></div>
            </div>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, color: 'var(--text-secondary)' }}>
                <span>Memory</span><span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>72%</span>
              </div>
              <div className="progress-bar"><div className="progress-fill warning" style={{ width: '72%' }}></div></div>
            </div>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, color: 'var(--text-secondary)' }}>
                <span>Disk</span><span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>34%</span>
              </div>
              <div className="progress-bar"><div className="progress-fill" style={{ width: '34%' }}></div></div>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}

/* ── Devices Page ────────────────────────────────────────── */
function DevicesPage() {
  const devices = [
    { name: 'WS-001', os: 'Windows 11', arch: 'x86_64', status: 'online', cpu: 45, ram: 72, alerts: 2 },
    { name: 'PI-003', os: 'Raspberry Pi OS', arch: 'arm64', status: 'online', cpu: 23, ram: 58, alerts: 1 },
    { name: 'SRV-002', os: 'Ubuntu 24.04', arch: 'x86_64', status: 'online', cpu: 67, ram: 81, alerts: 3 },
    { name: 'MAC-001', os: 'macOS Ventura', arch: 'arm64', status: 'online', cpu: 12, ram: 45, alerts: 0 },
    { name: 'WS-005', os: 'Windows 10', arch: 'x86_64', status: 'offline', cpu: 0, ram: 0, alerts: 0 },
    { name: 'DRD-001', os: 'Android 14', arch: 'arm64', status: 'online', cpu: 8, ram: 52, alerts: 1 },
  ]

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 24 }}>
        <h3 style={{ fontSize: 16, color: 'var(--text-secondary)' }}>6 registered devices</h3>
        <button className="btn btn-primary">+ Register Device</button>
      </div>
      <div className="device-grid">
        {devices.map((d, i) => (
          <div key={i} className={`device-card animate-in delay-${i % 4 + 1}`}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <div>
                <div style={{ fontWeight: 700, fontSize: 16 }}>{d.name}</div>
                <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>{d.os} • {d.arch}</div>
              </div>
              <span className={`device-status ${d.status}`}>
                <span className="status-dot" style={d.status === 'offline' ? { background: 'var(--text-muted)', animation: 'none' } : d.status === 'compromised' ? { background: 'var(--accent-red)' } : {}}></span>
                {d.status}
              </span>
            </div>
            {d.status === 'online' && (
              <>
                <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 4 }}>CPU: {d.cpu}%</div>
                <div className="progress-bar"><div className={`progress-fill ${d.cpu > 80 ? 'danger' : d.cpu > 60 ? 'warning' : ''}`} style={{ width: `${d.cpu}%` }}></div></div>
                <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 8, marginBottom: 4 }}>RAM: {d.ram}%</div>
                <div className="progress-bar"><div className={`progress-fill ${d.ram > 80 ? 'danger' : d.ram > 60 ? 'warning' : ''}`} style={{ width: `${d.ram}%` }}></div></div>
              </>
            )}
            {d.alerts > 0 && (
              <div style={{ marginTop: 12, fontSize: 13, color: 'var(--accent-amber)' }}>⚠️ {d.alerts} active alert{d.alerts > 1 ? 's' : ''}</div>
            )}
          </div>
        ))}
      </div>
    </>
  )
}

/* ── Alerts Page ─────────────────────────────────────────── */
function AlertsPage() {
  const alerts = [
    { severity: 'critical', title: 'Suspicious process: mimikatz.exe', device: 'WS-001', time: '2 min ago', category: 'Malware' },
    { severity: 'critical', title: 'Debugger attached to agent process', device: 'SRV-002', time: '8 min ago', category: 'Tamper' },
    { severity: 'high', title: 'File integrity change: /etc/shadow', device: 'PI-003', time: '15 min ago', category: 'Integrity' },
    { severity: 'high', title: 'Brute-force tool detected: hydra', device: 'SRV-002', time: '32 min ago', category: 'Intrusion' },
    { severity: 'medium', title: 'Connection spike: 250 active connections', device: 'SRV-002', time: '1 hr ago', category: 'Anomaly' },
    { severity: 'medium', title: 'Unknown USB device connected', device: 'DRD-001', time: '2 hr ago', category: 'Policy' },
    { severity: 'low', title: 'Agent updated to v1.0.1', device: 'MAC-001', time: '6 hr ago', category: 'System' },
  ]

  return (
    <>
      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(5, 1fr)' }}>
        <div className="stat-card"><div className="stat-label">Total</div><div className="stat-value">7</div></div>
        <div className="stat-card danger"><div className="stat-label">Critical</div><div className="stat-value" style={{ color: 'var(--accent-red)' }}>2</div></div>
        <div className="stat-card"><div className="stat-label">High</div><div className="stat-value" style={{ color: 'var(--accent-amber)' }}>2</div></div>
        <div className="stat-card"><div className="stat-label">Medium</div><div className="stat-value" style={{ color: 'var(--accent-blue)' }}>2</div></div>
        <div className="stat-card success"><div className="stat-label">Low</div><div className="stat-value" style={{ color: 'var(--accent-green)' }}>1</div></div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Active Alerts</span>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-outline" style={{ padding: '6px 12px', fontSize: 12 }}>Export</button>
            <button className="btn btn-primary" style={{ padding: '6px 12px', fontSize: 12 }}>Acknowledge All</button>
          </div>
        </div>
        <div className="panel-body">
          <div className="alert-list">
            {alerts.map((a, i) => (
              <div key={i} className={`alert-item ${a.severity} animate-in delay-${i % 4 + 1}`}>
                <span className={`severity-badge ${a.severity}`}>{a.severity}</span>
                <div className="alert-info">
                  <div className="alert-title">{a.title}</div>
                  <div className="alert-meta">{a.device} • {a.category} • {a.time}</div>
                </div>
                <button className="btn btn-outline" style={{ padding: '4px 10px', fontSize: 11 }}>Investigate</button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  )
}

/* ── Compliance Page ─────────────────────────────────────── */
function CompliancePage() {
  const logs = [
    { action: 'login', user: 'admin@guardian.io', ip: '192.168.1.10', time: '10:32:15' },
    { action: 'device_register', user: 'system', ip: '10.0.1.5', time: '10:28:00' },
    { action: 'alert_ack', user: 'analyst@guardian.io', ip: '192.168.1.12', time: '10:15:42' },
    { action: 'remediation_exec', user: 'admin@guardian.io', ip: '192.168.1.10', time: '09:58:30' },
    { action: 'config_change', user: 'admin@guardian.io', ip: '192.168.1.10', time: '09:45:11' },
  ]

  return (
    <>
      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)' }}>
        <div className="stat-card animate-in delay-1">
          <div className="stat-label">Audit Entries</div>
          <div className="stat-value">1,247</div>
          <div className="stat-change">HMAC Verified ✓</div>
        </div>
        <div className="stat-card animate-in delay-2">
          <div className="stat-label">GDPR Status</div>
          <div className="stat-value" style={{ fontSize: 24, color: 'var(--accent-green)' }}>Compliant</div>
        </div>
        <div className="stat-card animate-in delay-3">
          <div className="stat-label">Last Audit</div>
          <div className="stat-value" style={{ fontSize: 20 }}>2h ago</div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Audit Log (Immutable)</span>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-outline" style={{ padding: '6px 12px', fontSize: 12 }}>GDPR Export</button>
            <button className="btn btn-outline" style={{ padding: '6px 12px', fontSize: 12 }}>SIEM Export</button>
          </div>
        </div>
        <div className="panel-body">
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 14 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left' }}>
                <th style={{ padding: '10px 12px', color: 'var(--text-muted)', fontWeight: 600 }}>Time</th>
                <th style={{ padding: '10px 12px', color: 'var(--text-muted)', fontWeight: 600 }}>Action</th>
                <th style={{ padding: '10px 12px', color: 'var(--text-muted)', fontWeight: 600 }}>User</th>
                <th style={{ padding: '10px 12px', color: 'var(--text-muted)', fontWeight: 600 }}>IP</th>
                <th style={{ padding: '10px 12px', color: 'var(--text-muted)', fontWeight: 600 }}>HMAC</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((l, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '10px 12px', fontFamily: 'monospace', fontSize: 13 }}>{l.time}</td>
                  <td style={{ padding: '10px 12px' }}><span className="severity-badge medium">{l.action}</span></td>
                  <td style={{ padding: '10px 12px', color: 'var(--text-secondary)' }}>{l.user}</td>
                  <td style={{ padding: '10px 12px', fontFamily: 'monospace', fontSize: 13 }}>{l.ip}</td>
                  <td style={{ padding: '10px 12px', color: 'var(--accent-green)', fontSize: 12 }}>✓ Valid</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}

export default App
