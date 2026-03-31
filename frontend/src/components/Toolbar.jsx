import React, { useState, useEffect } from 'react'
import { Wifi, ChevronDown, Play, Square, RefreshCw, Download, Clock } from 'lucide-react'

const css = `
.toolbar {
  flex: 1; display: flex; align-items: center; gap: 6px;
  padding: 0 10px; height: var(--toolbar-h);
  min-width: 0;
}
.toolbar-logo {
  font-family: var(--font-ui); font-size: 20px; font-weight: 700;
  letter-spacing: 0.2em; color: var(--accent); text-transform: uppercase;
  margin-right: 4px; white-space: nowrap; flex-shrink: 0;
}
.toolbar-logo span { color: var(--text-muted); font-size: 10px; font-weight: 400; letter-spacing: 0.08em; vertical-align: middle; margin-left: 4px; }
.iface-selector { position: relative; }
.iface-btn {
  display: flex; align-items: center; gap: 6px;
  background: var(--bg-3); border: 1px solid var(--border);
  color: var(--text-primary); padding: 6px 12px; border-radius: 4px;
  font-size: 12px; font-family: var(--font-mono); cursor: pointer;
  transition: border-color 0.15s, background 0.15s; white-space: nowrap;
}
.iface-btn:hover { border-color: var(--border-bright); background: var(--bg-4); }
.iface-name { color: var(--accent); font-weight: 500; }
.iface-ip { color: var(--text-secondary); font-size: 11px; }
.iface-dropdown {
  position: absolute; top: calc(100% + 4px); left: 0; min-width: 380px;
  background: var(--bg-2); border: 1px solid var(--border-bright);
  border-radius: 6px; box-shadow: 0 8px 32px rgba(0,0,0,0.6); z-index: 300; overflow: hidden;
}
.iface-dropdown-hdr { padding: 7px 14px; font-size: 9px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--text-muted); border-bottom: 1px solid var(--border); }
.iface-option { display: flex; flex-direction: column; gap: 3px; padding: 10px 14px; cursor: pointer; border-bottom: 1px solid var(--border); transition: background 0.1s; }
.iface-option:last-child { border-bottom: none; }
.iface-option:hover { background: var(--bg-3); }
.iface-option.active { background: rgba(0,212,255,0.05); }
.iface-top { display: flex; align-items: center; gap: 8px; }
.iface-opt-name { font-family: var(--font-mono); font-size: 13px; color: var(--accent); font-weight: 600; }
.iface-opt-mac { font-family: var(--font-mono); font-size: 10px; color: var(--text-muted); margin-left: auto; }
.iface-details { display: flex; gap: 12px; flex-wrap: wrap; }
.kv { display: flex; gap: 4px; font-size: 11px; }
.kv-k { color: var(--text-muted); }
.kv-v { font-family: var(--font-mono); color: var(--text-secondary); }
.cidr-input {
  background: var(--bg-3); border: 1px solid var(--border);
  color: var(--text-primary); padding: 6px 8px; border-radius: 4px;
  font-size: 12px; font-family: var(--font-mono); width: 140px;
  transition: border-color 0.15s;
}
.cidr-input:focus { border-color: var(--accent-dim); }
.cidr-input.invalid { border-color: var(--red); }
.divider { width: 1px; height: 28px; background: var(--border); margin: 0 2px; flex-shrink: 0; }
.scan-btn {
  display: flex; align-items: center; gap: 6px;
  padding: 7px 18px; border-radius: 4px; font-size: 12px;
  font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; transition: all 0.15s;
  white-space: nowrap; flex-shrink: 0;
}
.scan-btn.start { background: var(--accent); color: var(--bg-0); }
.scan-btn.start:hover { background: #33ddff; box-shadow: 0 0 20px rgba(0,212,255,0.25); }
.scan-btn.stop { background: rgba(255,61,61,0.12); color: var(--red); border: 1px solid rgba(255,61,61,0.3); }
.scan-btn.stop:hover { background: rgba(255,61,61,0.22); }
.toolbar-right { margin-left: auto; display: flex; align-items: center; gap: 6px; flex-shrink: 0; }
.host-count { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); white-space: nowrap; margin-right: 4px; }
.host-count span { color: var(--green); font-size: 14px; font-weight: 600; }
.icon-btn {
  display: flex; align-items: center; gap: 5px;
  background: var(--bg-3); border: 1px solid var(--border);
  color: var(--text-secondary); padding: 6px 10px; border-radius: 4px;
  font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em;
  cursor: pointer; transition: all 0.12s; white-space: nowrap;
}
.icon-btn:hover { border-color: var(--border-bright); color: var(--text-primary); }
.icon-btn.active { border-color: var(--accent-dim); color: var(--accent); background: rgba(0,212,255,0.08); }
.rescan-select {
  background: var(--bg-3); border: 1px solid var(--border);
  color: var(--text-secondary); padding: 5px 6px; border-radius: 4px;
  font-size: 11px; font-family: var(--font-mono); cursor: pointer;
}
`

function ifaceIcon(iface) {
  const t = (iface?.iface_type || '').toLowerCase()
  if (t === 'wifi')       return '📶'
  if (t === 'ethernet')   return '🔌'
  if (t === 'thunderbolt')return '⚡'
  if (t === 'vpn')        return '🔒'
  if (t === 'bluetooth')  return '🔵'
  if (t === 'bridge')     return '🔗'
  // Fallback by name
  const n = iface?.name || ''
  if (n.startsWith('en0') || n.startsWith('wl')) return '📶'
  if (n.startsWith('eth') || n.startsWith('en1')) return '🔌'
  return '🖧'
}

function validateSingleCIDR(cidr) {
  const p = cidr.trim().split('/')
  if (p.length !== 2) return false
  const prefix = parseInt(p[1])
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false
  const o = p[0].split('.')
  if (o.length !== 4) return false
  return o.every(x => { const n = parseInt(x); return !isNaN(n) && n >= 0 && n <= 255 })
}

function validateCIDR(cidr) {
  // Support comma-separated multi-CIDR: "192.168.1.0/24, 10.0.0.0/24"
  return cidr.split(',').every(c => validateSingleCIDR(c.trim()))
}

export default function Toolbar({
  interfaces, selectedIface, onSelectIface,
  cidr, onCidrChange,
  onScan, onStop, scanning,
  hostCount, lastScanId,
  autoRescan, onAutoRescanChange,
  profile = 'standard', onProfileChange,
}) {
  const [open, setOpen] = useState(false)
  const [localCidr, setLocalCidr] = useState(cidr)
  const valid = validateCIDR(localCidr)

  useEffect(() => setLocalCidr(cidr), [cidr])

  const handleIfaceSelect = (iface) => {
    onSelectIface(iface)
    // Use network_cidr from backend if available (most reliable)
    if (iface.network_cidr && validateCIDR(iface.network_cidr)) {
      setLocalCidr(iface.network_cidr)
      onCidrChange(iface.network_cidr)
    } else if (iface.ipv4 && iface.ipv4_prefix) {
      // Calculate network address manually
      const parts = iface.ipv4.split('.').map(Number)
      const prefix = parseInt(iface.ipv4_prefix)
      const shift = 32 - prefix
      const ipInt = (parts[0]<<24|parts[1]<<16|parts[2]<<8|parts[3]) >>> 0
      const mask  = shift >= 32 ? 0 : (~0 << shift) >>> 0
      const netInt = (ipInt & mask) >>> 0
      const a = (netInt>>>24)&0xff
      const b = (netInt>>>16)&0xff
      const d = (netInt>>>8)&0xff
      const e = netInt&0xff
      const newCidr = `${a}.${b}.${d}.${e}/${prefix}`
      setLocalCidr(newCidr)
      onCidrChange(newCidr)
    }
    setOpen(false)
  }

  const handleCidrInput = (v) => {
    setLocalCidr(v)
    if (validateCIDR(v)) onCidrChange(v)
  }

  const handleExport = async (fmt) => {
    if (!lastScanId) return alert('Run a scan first')
    window.open(`/api/export/${fmt}?scan_id=${lastScanId}`, '_blank')
  }

  return (
    <>
      <style>{css}</style>
      <div className="toolbar">
        {/* Logo */}
        <div className="toolbar-logo" style={{ display:'flex', alignItems:'center', gap:6 }}>
          <img src="/cernis-logo.png" alt="CERNIS" style={{ height:24, width:24, objectFit:'contain', borderRadius:3, flexShrink:0 }} />
          <span style={{ fontWeight:700, fontSize:12, letterSpacing:'0.08em', whiteSpace:'nowrap' }}>CERNIS PRO</span>
        </div>

        {/* Interface selector */}
        <div className="iface-selector">
          <button className="iface-btn" onClick={() => setOpen(o => !o)}>
            <Wifi size={13} color="var(--accent)" />
            <span className="iface-name">{selectedIface?.name || '—'}</span>
            <span className="iface-ip">{selectedIface?.ipv4 || ''}</span>
            <ChevronDown size={11} />
          </button>
          {open && (
            <div className="iface-dropdown">
              <div className="iface-dropdown-hdr">Network Interfaces</div>
              {interfaces.map(iface => (
                <div key={iface.name}
                  className={`iface-option${selectedIface?.name===iface.name?' active':''}`}
                  onClick={() => handleIfaceSelect(iface)}>
                  <div className="iface-top">
                    <span className="iface-opt-name">{iface.name}</span>
                    <span className="iface-opt-mac">{iface.mac}</span>
                  </div>
                  <div className="iface-details">
                    {iface.ipv4 && <span className="kv"><span className="kv-k">IPv4</span><span className="kv-v">{iface.ipv4}/{iface.ipv4_prefix}</span></span>}
                    {iface.gateway && <span className="kv"><span className="kv-k">GW</span><span className="kv-v">{iface.gateway}</span></span>}
                    {iface.ipv6_link_local && <span className="kv"><span className="kv-k">LL</span><span className="kv-v">{iface.ipv6_link_local.substring(0,18)}…</span></span>}
                    {iface.mtu && <span className="kv"><span className="kv-k">MTU</span><span className="kv-v">{iface.mtu}</span></span>}
                    {iface.host_count > 0 && <span className="kv"><span className="kv-k">Hosts</span><span className="kv-v">{iface.host_count}</span></span>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="divider" />

        {/* CIDR */}
        <input className={`cidr-input${!valid && localCidr ? ' invalid' : ''}`}
          value={localCidr} onChange={e => handleCidrInput(e.target.value)}
          placeholder="192.168.1.0/24" spellCheck={false} />

        <div className="divider" />

        {/* Profile selector */}
        <select
          style={{ background:'var(--bg-3)', border:'1px solid var(--border)', color:'var(--text-secondary)', padding:'6px 8px', borderRadius:4, fontSize:11, fontFamily:'var(--font-mono)', cursor:'pointer' }}
          value={profile} onChange={e => onProfileChange && onProfileChange(e.target.value)}
          title="Scan Profile"
        >
          <option value="quick">⚡ Quick</option>
          <option value="standard">🔍 Standard</option>
          <option value="deep">🔬 Deep</option>
          <option value="iot">📡 IoT</option>
          <option value="security">🛡 Security</option>
        </select>

        <div className="divider" />

        {/* Scan button */}
        {!scanning ? (
          <button className="scan-btn start" onClick={() => valid && onScan()} disabled={!valid} style={{ opacity: valid ? 1 : 0.5 }}>
            <Play size={12} /> Scan
          </button>
        ) : (
          <button className="scan-btn stop" onClick={onStop}>
            <Square size={12} /> Stop
          </button>
        )}

        <div className="toolbar-right">
          <span className="host-count"><span>{hostCount}</span> hosts</span>

          {/* Auto-rescan */}
          <div style={{ display:'flex', alignItems:'center', gap:4 }}>
            <Clock size={13} color={autoRescan > 0 ? 'var(--accent)' : 'var(--text-muted)'} />
            <select className="rescan-select" value={autoRescan}
              onChange={e => onAutoRescanChange(parseInt(e.target.value))}>
              <option value={0}>Manual</option>
              <option value={30}>30s</option>
              <option value={60}>1 min</option>
              <option value={300}>5 min</option>
              <option value={600}>10 min</option>
            </select>
          </div>

          {/* Export */}
          <button className="icon-btn" onClick={() => handleExport('csv')} title="Export CSV">
            <Download size={12} /> CSV
          </button>
          <button className="icon-btn" onClick={() => handleExport('json')} title="Export JSON">
            <Download size={12} /> JSON
          </button>
        </div>
      </div>
      {open && <div style={{ position:'fixed', inset:0, zIndex:299 }} onClick={() => setOpen(false)} />}
    </>
  )
}
