import React, { useState, useEffect, useRef } from 'react'
import Sidebar from './components/Sidebar.jsx'
import Toolbar from './components/Toolbar.jsx'
import ProgressBar from './components/ProgressBar.jsx'
import HostTable from './components/HostTable.jsx'
import HostDetail from './components/HostDetail.jsx'
import ScanSettings from './components/ScanSettings.jsx'
import ColumnManager from './components/ColumnManager.jsx'
import TopologyView from './components/TopologyView.jsx'
import PortDiff from './components/PortDiff.jsx'
import MonitorView from './views/MonitorView.jsx'
import DevicesView from './views/DevicesView.jsx'
import SecurityView from './views/SecurityView.jsx'
import { DEFAULT_VISIBLE, DEFAULT_ORDER } from './components/ColumnManager.jsx'
import { useInterfaces } from './hooks/useInterfaces.js'
import { useScan, SCAN_STATE } from './hooks/useScan.js'
import { useSettings } from './hooks/useSettings.js'
import { DEFAULT_CONFIG } from './components/ScanSettings.jsx'
import { Network, GitCompare } from 'lucide-react'
import FritzBoxView from './views/FritzBoxView.jsx'
import ReportView from './views/ReportView.jsx'
import ToolsView from './views/ToolsView.jsx'
import SettingsView from './views/SettingsView.jsx'
import SLAView from './views/SLAView.jsx'
import AlertsView from './views/AlertsView.jsx'
import InfraView from './views/InfraView.jsx'
import useKeyboardShortcuts, { getShortcutsList } from './hooks/useKeyboardShortcuts.js'

const css = `
.app { height: 100vh; display: flex; overflow: hidden; background: var(--bg-0); }
.app-content { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
.app-topbar {
  display: flex; align-items: center;
  height: var(--toolbar-h); flex-shrink: 0;
  border-bottom: 1px solid var(--border);
  background: var(--bg-1);
}
.app-topbar-actions {
  display: flex; align-items: center; gap: 6px;
  padding-right: 12px; flex-shrink: 0;
}
.app-body { flex: 1; display: flex; overflow: hidden; min-height: 0; }
.app-main  { flex: 1; display: flex; flex-direction: column; overflow: hidden; min-height: 0; }
.app-view  { flex: 1; display: flex; flex-direction: column; overflow: hidden; min-height: 0; }
.app-view-scroll { flex: 1; overflow-y: auto; }
.error-bar {
  background: rgba(255,61,61,0.1); border-bottom: 1px solid rgba(255,61,61,0.3);
  color: var(--red); padding: 6px 16px; font-size: 12px; font-family: var(--font-mono);
  flex-shrink: 0;
}
.scan-overlay { position: fixed; inset: 0; pointer-events: none; z-index: 50; overflow: hidden; }
.scan-line {
  position: absolute; left: 0; right: 0; height: 1px;
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
  opacity: 0.3; animation: scan-line 3s ease-in-out infinite;
}
.rescan-countdown {
  font-family: var(--font-mono); font-size: 10px; color: var(--accent);
  padding: 3px 8px; border-radius: 3px;
  background: rgba(0,212,255,0.08); border: 1px solid rgba(0,212,255,0.2);
  white-space: nowrap;
}
.view-btn {
  display: flex; align-items: center; gap: 5px;
  background: var(--bg-3); border: 1px solid var(--border);
  color: var(--text-secondary); padding: 6px 11px; border-radius: 4px;
  font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em;
  cursor: pointer; transition: all 0.12s; white-space: nowrap; border: none;
}
.view-btn:hover { color: var(--text-primary); }
.view-btn:disabled { opacity: 0.35; cursor: not-allowed; }
`

export default function App() {
  const { interfaces } = useInterfaces()
  const [activeView, setActiveView]       = useState('scan')
  const [selectedIface, setSelectedIface] = useState(null)
  const [cidr, setCidr]                   = useState('192.168.1.0/24')

  const [scanConfig, setScanConfig]       = useSettings('scan_config', DEFAULT_CONFIG)
  const [columnOrder, setColumnOrder]     = useSettings('column_order', DEFAULT_ORDER)
  const [columnVisible, setColumnVisible] = useSettings('column_visible', DEFAULT_VISIBLE)
  const [autoRescan, setAutoRescan]       = useSettings('auto_rescan_secs', 0)

  const [selectedHost, setSelectedHost]   = useState(null)
  const [showDetail, setShowDetail]       = useState(false)
  const [showTopo, setShowTopo]           = useState(false)
  const [showDiff, setShowDiff]           = useState(false)
  const [lastScanId, setLastScanId]       = useState(null)
  const [countdown, setCountdown]         = useState(0)
  const [monitorStatus, setMonitorStatus] = useState({})
  const [showShortcuts, setShowShortcuts]   = useState(false)
  const [fritzConnected, setFritzConnected]   = useState(false)
  const [fritzStatus, setFritzStatus]         = useState(null)
  const [scanProfile, setScanProfile]         = useState('standard')
  const [isDark, setIsDark]               = useState(() => localStorage.getItem('cernis_theme') !== 'light')

  const { scanState, hosts, progress, error, startScan, stopScan } = useScan()
  const scanning = scanState === SCAN_STATE.RUNNING
  const done     = scanState === SCAN_STATE.DONE

  // Monitor WebSocket — always active with reconnect
  useEffect(() => {
    let ws = null
    let reconnectTimer = null

    const connect = () => {
      const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
      const wsBase = window.CERNIS_WS_BASE || `${protocol}://${window.location.host}`
      ws = new WebSocket(`${wsBase}/ws/monitor`)
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data)
          if (msg.type === 'monitor_status') setMonitorStatus(msg.status)
          if (msg.type === 'monitor_update') {
            setMonitorStatus(prev => ({
              ...prev,
              [msg.target_id]: { alive: msg.alive, label: msg.label }
            }))
          }
        } catch {}
      }
      ws.onclose = () => {
        reconnectTimer = setTimeout(connect, 3000)
      }
      ws.onerror = () => {
        // Monitor WS errors are silent - reconnect handles it
        try { ws.close() } catch {}
      }
    }

    connect()
    return () => {
      if (reconnectTimer) clearTimeout(reconnectTimer)
      if (ws) ws.close()
    }
  }, [])

  // Auto-select first interface
  useEffect(() => {
    if (interfaces.length > 0 && !selectedIface) {
      const active = interfaces.find(i => i.ipv4 && i.gateway) || interfaces[0]
      setSelectedIface(active)
      if (active.network_cidr) setCidr(active.network_cidr)
    }
  }, [interfaces])

  // Load last scan id on startup + after each scan
  useEffect(() => {
    fetch('/api/history?limit=1').then(r=>r.json()).then(data => {
      if (data.length > 0) setLastScanId(data[0].id)
    }).catch(() => {})
  }, [done])

  // Auto-rescan countdown
  const rescanTimer = useRef(null), countdownTimer = useRef(null)
  useEffect(() => {
    if (rescanTimer.current)    clearTimeout(rescanTimer.current)
    if (countdownTimer.current) clearInterval(countdownTimer.current)
    setCountdown(0)
    if ((autoRescan || 0) > 0 && !scanning) {
      let rem = autoRescan
      setCountdown(rem)
      countdownTimer.current = setInterval(() => {
        rem -= 1; setCountdown(rem)
        if (rem <= 0) clearInterval(countdownTimer.current)
      }, 1000)
      rescanTimer.current = setTimeout(() => handleScan(), autoRescan * 1000)
    }
    return () => {
      if (rescanTimer.current)    clearTimeout(rescanTimer.current)
      if (countdownTimer.current) clearInterval(countdownTimer.current)
    }
  }, [autoRescan, done])

  const toggleTheme = () => {
    const next = !isDark
    setIsDark(next)
    document.body.classList.toggle('light', !next)
    localStorage.setItem('cernis_theme', next ? 'dark' : 'light')
  }

  // Apply theme on mount
  React.useEffect(() => {
    document.body.classList.toggle('light', !isDark)
  }, [])

  // Keyboard shortcuts
  useKeyboardShortcuts({
    onScanToggle: () => scanning ? handleStop() : handleScan(),
    onViewChange: setActiveView,
    onClose: () => { setSelectedHost(null); setShowShortcuts(false) },
    scanning,
  })

  React.useEffect(() => {
    const handler = () => setShowShortcuts(true)
    window.addEventListener('cernis:show-shortcuts', handler)
    return () => window.removeEventListener('cernis:show-shortcuts', handler)
  }, [])

  const handleStop = () => {
    stopScan()
    if (rescanTimer.current)    clearTimeout(rescanTimer.current)
    if (countdownTimer.current) clearInterval(countdownTimer.current)
    setCountdown(0)
  }

  const handleScan = () => {
    // Merge profile config with user settings
    const PROFILES = {
      quick:    { port_scan:false, mdns_scan:false, ssdp_scan:false, resolve_hostnames:false, ping_timeout:0.5, max_concurrent_ping:128 },
      standard: {},
      deep:     { port_scan:true, port_mode:'nmap', smb_scan:true, ping_timeout:1.5, max_concurrent_ping:32 },
      iot:      { mdns_duration:10.0, custom_ports:[80,443,554,1883,5353,5900,5960,7788,8080,8443] },
      security: { smb_scan:true, custom_ports:[21,22,23,25,53,80,110,135,139,143,389,443,445,3389,5900,6379,27017,9200] },
    }
    const profileOverride = PROFILES[scanProfile] || {}
    startScan({ ...(scanConfig || DEFAULT_CONFIG), ...profileOverride, cidr })
    setSelectedHost(null); setCountdown(0)
    if (rescanTimer.current)    clearTimeout(rescanTimer.current)
    if (countdownTimer.current) clearInterval(countdownTimer.current)
  }

  const fullHost = selectedHost ? hosts.find(h => h.ip === selectedHost.ip) || selectedHost : null
  const arpAlertCount = 0  // loaded lazily in SecurityView

  return (
    <>
      <style>{css}</style>
      <div className="app">
        {scanning && <div className="scan-overlay"><div className="scan-line" /></div>}

        {/* ── Sidebar ───────────────────────────────────────── */}
        <Sidebar
          activeView={activeView}
          onViewChange={setActiveView}
          monitorStatus={monitorStatus}
          arpAlertCount={arpAlertCount}
          isDark={isDark}
          onToggleTheme={toggleTheme}
        />

        {/* ── Main content area ─────────────────────────────── */}
        <div className="app-content">

          {/* ── SCAN view ─────────────────────────────────── */}
          {activeView === 'scan' && (
            <>
              <div className="app-topbar">
                <Toolbar
                  interfaces={interfaces}
                  selectedIface={selectedIface}
                  onSelectIface={setSelectedIface}
                  cidr={cidr}
                  onCidrChange={setCidr}
                  onScan={handleScan}
                  onStop={stopScan}
                  scanning={scanning}
                  hostCount={hosts.length}
                  lastScanId={lastScanId}
                  autoRescan={autoRescan || 0}
                  onAutoRescanChange={setAutoRescan}
                  profile={scanProfile}
                  onProfileChange={setScanProfile}
                />
                <div className="app-topbar-actions">
                  {countdown > 0 && !scanning && (
                    <span className="rescan-countdown">⟳ {countdown}s</span>
                  )}
                  <button className="view-btn" onClick={() => setShowTopo(true)}
                    disabled={hosts.length === 0} title="Network Topology">
                    <Network size={13} /> Topology
                  </button>
                  <button className="view-btn" onClick={() => setShowDiff(true)} title="Compare Scans">
                    <GitCompare size={13} /> Diff
                  </button>
                  <ColumnManager
                    order={columnOrder || DEFAULT_ORDER}
                    visible={columnVisible || DEFAULT_VISIBLE}
                    onChange={(o,v) => { setColumnOrder(o); setColumnVisible(v) }}
                  />
                  <ScanSettings config={scanConfig || DEFAULT_CONFIG} onChange={setScanConfig} />
                </div>
              </div>
              <ProgressBar progress={progress} scanning={scanning} done={done} />
              {error && <div className="error-bar">⚠ {error}</div>}
              <div className="app-body">
                <div className="app-main">
                  <HostTable
                    hosts={hosts}
                    selectedIp={fullHost?.ip}
                    onSelect={h => { setSelectedHost(h); setShowDetail(true) }}
                    columnOrder={columnOrder || DEFAULT_ORDER}
                    columnVisible={columnVisible || DEFAULT_VISIBLE}
                  />
                </div>
                {showDetail && (
                  <HostDetail host={fullHost} onClose={() => setShowDetail(false)} />
                )}
              </div>
            </>
          )}

          {/* ── All other views ─────────────────────────── */}
          {activeView !== 'scan' && (
            <div style={{ flex:1, position:'relative', overflow:'hidden', display:'flex', flexDirection:'column' }}>
              {activeView === 'monitor'  && <MonitorView monitorStatus={monitorStatus} />}
              {activeView === 'devices'  && <DevicesView />}
              {activeView === 'security' && <SecurityView />}
              {activeView === 'fritzbox' && <FritzBoxView connected={fritzConnected} onConnect={(s) => { setFritzConnected(true); setFritzStatus(s) }} status={fritzStatus} />}
              {activeView === 'report'   && <ReportView hosts={hosts} />}
              {activeView === 'tools'    && <ToolsView selectedIface={selectedIface} />}
              {activeView === 'sla'      && <SLAView />}
              {activeView === 'alerts'   && <AlertsView />}
              {activeView === 'infra'    && <InfraView selectedIface={selectedIface} />}
              {activeView === 'settings' && <SettingsView interfaces={interfaces} cidr={cidr} />}
            </div>
          )}

        </div>{/* end app-content */}

        {/* ── Modals ────────────────────────────────────────── */}
        {showTopo && (
          <TopologyView hosts={hosts} gateway={selectedIface?.gateway} onClose={() => setShowTopo(false)} />
        )}
        {showDiff && <PortDiff onClose={() => setShowDiff(false)} />}
      </div>{/* end app */}
    </>
  )
}
