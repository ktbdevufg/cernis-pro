import React from 'react'
import { Radar, Activity, Database, Shield, Settings, FileText, TrendingUp, Bell, Sun, Moon, Server } from 'lucide-react'

const css = `
.sidebar {
  width: 52px;
  flex-shrink: 0;
  background: var(--bg-1);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 8px 0;
  gap: 2px;
  z-index: 50;
}
.sidebar-logo {
  font-size: 18px;
  font-weight: 900;
  color: var(--accent);
  letter-spacing: -1px;
  padding: 8px 0 12px;
  border-bottom: 1px solid var(--border);
  width: 100%;
  text-align: center;
  margin-bottom: 6px;
  font-family: var(--font-ui);
}
.sidebar-logo span { font-size: 8px; display: block; color: var(--text-muted); letter-spacing: 0.12em; font-weight: 400; margin-top: -2px; }
.nav-item {
  position: relative;
  width: 40px; height: 40px;
  display: flex; align-items: center; justify-content: center;
  border-radius: 6px;
  cursor: pointer;
  color: var(--text-muted);
  transition: all 0.15s;
  border: 1px solid transparent;
}
.nav-item:hover { color: var(--text-primary); background: var(--bg-3); }
.nav-item.active {
  color: var(--accent);
  background: rgba(0,212,255,0.1);
  border-color: rgba(0,212,255,0.2);
}
.nav-item .nav-badge {
  position: absolute;
  top: 5px; right: 5px;
  width: 7px; height: 7px;
  border-radius: 50%;
  background: var(--red);
  border: 1px solid var(--bg-1);
}
.nav-item .nav-badge.warning { background: var(--orange); }
.nav-item .nav-badge.ok { background: var(--green); }

/* Tooltip */
.nav-item:hover::after {
  content: attr(data-label);
  position: absolute;
  left: calc(100% + 8px);
  top: 50%; transform: translateY(-50%);
  background: var(--bg-4);
  border: 1px solid var(--border-bright);
  color: var(--text-primary);
  font-size: 11px;
  font-weight: 600;
  padding: 4px 9px;
  border-radius: 4px;
  white-space: nowrap;
  z-index: 1000;
  pointer-events: none;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  font-family: var(--font-ui);
}

.sidebar-bottom {
  margin-top: auto;
  padding-top: 8px;
  border-top: 1px solid var(--border);
  width: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  padding-bottom: 4px;
}

/* Live status dots at bottom */
.status-dots {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 3px;
  padding: 6px 0;
  width: 100%;
  border-bottom: 1px solid var(--border);
  margin-bottom: 4px;
}
.status-dot-row {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 8px;
  color: var(--text-muted);
  font-family: var(--font-mono);
  letter-spacing: 0.04em;
}
.status-dot {
  width: 6px; height: 6px;
  border-radius: 50%;
  flex-shrink: 0;
}
.status-dot.up   { background: var(--green); box-shadow: 0 0 4px var(--green); }
.status-dot.down { background: var(--red);   box-shadow: 0 0 4px var(--red); animation: pulse-dot 1s infinite; }
.status-dot.unknown { background: var(--text-muted); }
`

const NAV_ITEMS = [
  { id: 'scan',     icon: Radar,    label: 'SCAN' },
  { id: 'monitor',  icon: Activity, label: 'MONITOR' },
  { id: 'devices',  icon: Database, label: 'DEVICES' },
  { id: 'security', icon: Shield,   label: 'SECURITY' },
  { id: 'report',   icon: FileText,  label: 'REPORT' },
  { id: 'sla',      icon: TrendingUp, label: 'SLA' },
  { id: 'alerts',   icon: Bell,      label: 'ALERTS' },
  { id: 'infra',    icon: Server,    label: 'INFRA' },
]

export default function Sidebar({ activeView, onViewChange, monitorStatus, arpAlertCount, isDark, onToggleTheme }) {
  const getMonitorBadge = () => {
    if (!monitorStatus) return null
    const hasDown = Object.values(monitorStatus).some(s => s.alive === false)
    if (hasDown) return 'alert'
    const allUp = Object.values(monitorStatus).every(s => s.alive === true)
    if (allUp) return 'ok'
    return null
  }

  const badge = getMonitorBadge()

  // Build 3-line status summary for sidebar
  const statusLines = [
    { label: 'WLAN', id: 'wlan' },
    { label: 'LAN',  id: 'lan' },
    { label: 'WAN',  id: 'wan' },
  ].map(({ label, id }) => {
    const match = monitorStatus
      ? Object.entries(monitorStatus).find(([tid]) => tid.includes(id) || tid.includes('gw') || (id === 'wan' && tid.includes('internet')))
      : null
    const alive = match ? match[1].alive : null
    return { label, alive }
  })

  return (
    <>
      <style>{css}</style>
      <div className="sidebar">

        {/* Logo */}
        <div className="sidebar-logo" onClick={() => onViewChange('scan')} title="CERNIS PRO">
          <img src="/cernis-logo.png" alt="CERNIS PRO"
            style={{ width:36, height:36, objectFit:'contain', borderRadius:4, flexShrink:0 }} />
        </div>

        {/* Nav items */}
        {NAV_ITEMS.map(({ id, icon: Icon, label }) => (
          <div
            key={id}
            className={`nav-item${activeView === id ? ' active' : ''}`}
            data-label={label}
            onClick={() => onViewChange(id)}
          >
            <Icon size={16} />
            {id === 'monitor' && badge && (
              <span className={`nav-badge ${badge === 'alert' ? 'warning' : 'ok'}`} />
            )}
            {id === 'security' && arpAlertCount > 0 && (
              <span className="nav-badge warning">{arpAlertCount}</span>
            )}
          </div>
        ))}

        {/* Bottom: status dots + settings + theme toggle */}
        <div className="sidebar-bottom">
          <div className="status-dots">
            {statusLines.map(({ label, alive }) => (
              <div key={label} className="status-dot-row">
                <div className={`status-dot ${alive === true ? 'up' : alive === false ? 'down' : 'unknown'}`} />
                {label}
              </div>
            ))}
          </div>

          <div
            className={`nav-item${activeView === 'settings' ? ' active' : ''}`}
            data-label="SETTINGS"
            onClick={() => onViewChange('settings')}
          >
            <Settings size={16} />
          </div>
          <div className="nav-item" data-label="LIGHT / DARK"
            onClick={onToggleTheme}
            style={{ marginTop: 2 }}>
            {isDark ? <Sun size={15} /> : <Moon size={15} />}
          </div>
        </div>

      </div>
    </>
  )
}
