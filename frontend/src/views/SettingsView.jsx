import React, { useState, useEffect } from 'react'
import { Settings, Save, RotateCcw, Plus, Trash2, Play, Clock, Wifi, Database, Radar } from 'lucide-react'

const css = `
.settings-view { position: absolute; inset: 0; display: flex; flex-direction: column; }
.sv-header {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 20px; border-bottom: 1px solid var(--border);
  background: var(--bg-1); flex-shrink: 0;
}
.sv-title { font-size: 13px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); }
.sv-body { flex: 1; overflow-y: auto; padding: 20px 24px 0; display: flex; flex-direction: column; gap: 20px; }

.sv-card { background: var(--bg-2); border: 1px solid var(--border); border-radius: 6px; }
.sv-card-title {
  display: flex; align-items: center; gap: 8px;
  padding: 14px 20px; border-bottom: 1px solid var(--border);
  font-size: 10px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--text-muted);
}
.sv-card-body { padding: 20px 22px; display: flex; flex-direction: column; gap: 16px; }

.sv-row { display: flex; align-items: center; gap: 12px; min-height: 36px; padding: 4px 0; }
.sv-label { flex: 1; font-size: 13px; color: var(--text-secondary); }
.sv-label small { display: block; font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); margin-top: 3px; line-height: 1.5; }

.sv-input {
  background: var(--bg-3); border: 1px solid var(--border);
  color: var(--text-primary); padding: 6px 10px; border-radius: 4px;
  font-size: 12px; font-family: var(--font-mono);
}
.sv-input:focus { border-color: var(--accent-dim); outline: none; }
.sv-input.wide { width: 220px; }
.sv-input.narrow { width: 90px; text-align: right; }

.toggle { position: relative; width: 36px; height: 20px; flex-shrink: 0; }
.toggle input { opacity: 0; width: 0; height: 0; }
.toggle-slider {
  position: absolute; inset: 0; background: var(--bg-4); border-radius: 20px;
  cursor: pointer; transition: background 0.2s; border: 1px solid var(--border);
}
.toggle-slider::before {
  content: ''; position: absolute; width: 14px; height: 14px;
  left: 2px; top: 2px; background: var(--text-muted);
  border-radius: 50%; transition: transform 0.2s, background 0.2s;
}
.toggle input:checked + .toggle-slider { background: rgba(0,212,255,0.2); border-color: var(--accent-dim); }
.toggle input:checked + .toggle-slider::before { transform: translateX(16px); background: var(--accent); }

/* Profiles */
.profile-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 10px; }
.profile-card {
  background: var(--bg-3); border: 1px solid var(--border); border-radius: 5px;
  padding: 16px 14px; cursor: pointer; transition: all 0.12s;
  display: flex; flex-direction: column; gap: 6px;
}
.profile-card:hover { border-color: var(--border-bright); }
.profile-card.builtin { border-left: 2px solid var(--accent-dim); }
.profile-card.custom  { border-left: 2px solid var(--purple); }
.profile-name { font-size: 12px; font-weight: 700; color: var(--text-primary); }
.profile-desc { font-size: 10px; color: var(--text-muted); line-height: 1.4; }
.profile-icon { font-size: 18px; margin-bottom: 4px; }

/* Schedules */
.schedule-list { display: flex; flex-direction: column; gap: 6px; }
.schedule-item {
  display: flex; align-items: center; gap: 10px;
  padding: 8px 12px; border-radius: 4px; background: var(--bg-3);
  border: 1px solid var(--border);
}
.schedule-item.disabled { opacity: 0.5; }
.schedule-name { font-size: 12px; font-weight: 600; color: var(--text-primary); flex: 1; }
.schedule-meta { font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); }
.schedule-next { font-size: 10px; color: var(--accent); font-family: var(--font-mono); }

.add-row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-top: 8px; }
.sv-select {
  background: var(--bg-3); border: 1px solid var(--border);
  color: var(--text-primary); padding: 6px 8px; border-radius: 4px;
  font-size: 12px; font-family: var(--font-mono);
}
.sv-btn {
  display: flex; align-items: center; gap: 5px;
  padding: 6px 14px; border-radius: 4px; font-size: 11px; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.06em; cursor: pointer; border: none;
  transition: all 0.12s;
}
.sv-btn.primary { background: var(--accent); color: var(--bg-0); }
.sv-btn.primary:hover { background: #33ddff; }
.sv-btn.danger { background: rgba(255,61,61,0.1); color: var(--red); border: 1px solid rgba(255,61,61,0.3); }
.sv-btn.danger:hover { background: rgba(255,61,61,0.2); }
.sv-btn.secondary { background: var(--bg-3); border: 1px solid var(--border); color: var(--text-secondary); }
.sv-btn.secondary:hover { color: var(--text-primary); border-color: var(--border-bright); }

.version-badge {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 4px 10px; border-radius: 4px;
  background: rgba(0,212,255,0.1); color: var(--accent);
  border: 1px solid rgba(0,212,255,0.2);
  font-family: var(--font-mono); font-size: 12px; font-weight: 700;
}
`

const SCHEDULE_OPTIONS = [
  { value: "interval:30m",   label: "Every 30 min" },
  { value: "interval:1h",    label: "Every 1 hour" },
  { value: "interval:6h",    label: "Every 6 hours" },
  { value: "interval:12h",   label: "Every 12 hours" },
  { value: "interval:24h",   label: "Every 24 hours" },
  { value: "cron:0 2 * * *", label: "Daily at 02:00" },
  { value: "cron:0 8 * * 1", label: "Weekly Mon 08:00" },
]


function ShodanKeyRow() {
  const [key, setKey]       = React.useState('')
  const [saved, setSaved]   = React.useState(false)
  const [loading, setLoading] = React.useState(true)

  React.useEffect(() => {
    fetch('/api/settings').then(r=>r.json()).then(d => {
      if (d.shodan_api_key) setKey('••••••••')
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  const save = async () => {
    if (key === '••••••••') return
    await fetch('/api/settings/shodan-key', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: key })
    })
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div className="sv-row" style={{ flexWrap:'wrap', gap:8 }}>
      <div className="sv-label">
        Shodan API Key
        <small>Optional — enables full Shodan lookup. Free key at shodan.io</small>
      </div>
      <div style={{ display:'flex', gap:6 }}>
        <input className="sv-input" type="password"
          value={key} onChange={e => setKey(e.target.value)}
          placeholder="Enter Shodan API key…"
          style={{ width:200 }} />
        <button className="sv-btn primary" onClick={save}>
          {saved ? '✓ Saved' : 'Save'}
        </button>
      </div>
    </div>
  )
}

function ScanConfigCard({ config, onChange }) {
  const set = (k, v) => onChange({ ...config, [k]: v })
  const Toggle = ({ k }) => (
    <label className="toggle">
      <input type="checkbox" checked={!!config[k]} onChange={e => set(k, e.target.checked)} />
      <span className="toggle-slider" />
    </label>
  )
  return (
    <div className="sv-card">
      <div className="sv-card-title"><Radar size={11} /> Scan Configuration</div>
      <div className="sv-card-body">
        {/* Discovery */}
        <div style={{ fontSize:9, fontWeight:700, letterSpacing:'0.1em', textTransform:'uppercase', color:'var(--text-muted)', marginBottom:4 }}>Host Discovery</div>
        <div className="sv-row">
          <div className="sv-label">Ping Timeout (s)<small>Lower = faster, less reliable</small></div>
          <input className="sv-input narrow" type="number" min={0.2} max={5} step={0.1}
            value={config.ping_timeout || 1} onChange={e => set('ping_timeout', parseFloat(e.target.value))} />
        </div>
        <div className="sv-row">
          <div className="sv-label">Concurrent Pings<small>Max parallel pings</small></div>
          <input className="sv-input narrow" type="number" min={8} max={254} step={8}
            value={config.max_concurrent_ping || 64} onChange={e => set('max_concurrent_ping', parseInt(e.target.value))} />
        </div>
        <div className="sv-row">
          <div className="sv-label">Hostname Resolution<small>Reverse DNS per host</small></div>
          <Toggle k="resolve_hostnames" />
        </div>
        <div className="sv-row">
          <div className="sv-label">NetBIOS / SMB Names<small>Requires nmblookup — slower</small></div>
          <Toggle k="smb_scan" />
        </div>

        {/* Port Scan */}
        <div style={{ fontSize:9, fontWeight:700, letterSpacing:'0.1em', textTransform:'uppercase', color:'var(--text-muted)', marginTop:16, marginBottom:4 }}>Port Scanning</div>
        <div className="sv-row">
          <div className="sv-label">Port Scan Enabled</div>
          <Toggle k="port_scan" />
        </div>
        <div className="sv-row">
          <div className="sv-label">Scan Mode<small>socket = fast async · nmap = deep + OS</small></div>
          <div style={{ display:'flex', gap:6 }}>
            {['socket','nmap'].map(m => (
              <button key={m} onClick={() => set('port_mode', m)}
                style={{
                  padding:'4px 10px', borderRadius:4, fontSize:11, cursor:'pointer', fontFamily:'var(--font-mono)',
                  border: `1px solid ${config.port_mode === m ? 'var(--accent-dim)' : 'var(--border)'}`,
                  background: config.port_mode === m ? 'rgba(0,212,255,0.08)' : 'var(--bg-3)',
                  color: config.port_mode === m ? 'var(--accent)' : 'var(--text-secondary)',
                }}>{m}</button>
            ))}
          </div>
        </div>
        <div className="sv-row">
          <div className="sv-label">Concurrent Port Checks</div>
          <input className="sv-input narrow" type="number" min={20} max={500} step={20}
            value={config.max_concurrent_ports || 100} onChange={e => set('max_concurrent_ports', parseInt(e.target.value))} />
        </div>

        {/* Service Discovery */}
        <div style={{ fontSize:9, fontWeight:700, letterSpacing:'0.1em', textTransform:'uppercase', color:'var(--text-muted)', marginTop:16, marginBottom:4 }}>Service Discovery</div>
        <div className="sv-row">
          <div className="sv-label">mDNS / Bonjour / NDI<small>Discovers AirPlay, NDI, printers…</small></div>
          <Toggle k="mdns_scan" />
        </div>
        <div className="sv-row">
          <div className="sv-label">mDNS Duration (s)<small>Listen time for responses</small></div>
          <input className="sv-input narrow" type="number" min={2} max={30} step={1}
            value={config.mdns_duration || 5} onChange={e => set('mdns_duration', parseFloat(e.target.value))} />
        </div>
        <div className="sv-row">
          <div className="sv-label">UPnP / SSDP<small>Smart TVs, routers, NAS devices</small></div>
          <Toggle k="ssdp_scan" />
        </div>
      </div>
    </div>
  )
}

export default function SettingsView({ interfaces, cidr, scanConfig, onScanConfigChange }) {
  const [profiles, setProfiles] = useState({ defaults: [], custom: [] })
  const [schedules, setSchedules] = useState([])
  // New schedule form
  const [newSched, setNewSched] = useState({ name: '', cidr: cidr || '192.168.1.0/24', profile_id: 'standard', schedule: 'interval:1h' })

  const [sysInfo, setSysInfo] = useState({})
  const [installing, setInstalling] = useState({})

  const installPkg = async (pkg) => {
    setInstalling(p => ({ ...p, [pkg]: true }))
    try {
      const res = await fetch('/api/system/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ package: pkg })
      })
      const data = await res.json()
      if (data.ok) {
        setSysInfo(p => ({ ...p, [pkg]: true }))
      }
    } catch (e) {}
    setInstalling(p => ({ ...p, [pkg]: false }))
  }

  const loadAll = async () => {
    fetch('/api/system/info').then(r=>r.json()).then(d => { setSysInfo(d); }).catch(()=>{})
    const [p, s] = await Promise.all([
      fetch('/api/profiles').then(r => r.json()).catch(() => ({ defaults: [], custom: [] })),
      fetch('/api/schedules').then(r => r.json()).catch(() => []),
    ])
    setProfiles(p)
    setSchedules(s)
  }

  useEffect(() => { loadAll() }, [])

  const addSchedule = async () => {
    if (!newSched.name || !newSched.cidr) return
    await fetch('/api/schedules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newSched),
    })
    loadAll()
    setNewSched({ name: '', cidr: cidr || '192.168.1.0/24', profile_id: 'standard', schedule: 'interval:1h' })
  }

  const toggleSchedule = async (id, enabled) => {
    await fetch(`/api/schedules/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !enabled }),
    })
    loadAll()
  }

  const deleteSchedule = async (id) => {
    await fetch(`/api/schedules/${id}`, { method: 'DELETE' })
    loadAll()
  }

  const allProfiles = [...profiles.defaults, ...profiles.custom]

  return (
    <>
      <style>{css}</style>
      <div className="settings-view">
        <div className="sv-header">
          <Settings size={14} color="var(--accent)" />
          <span className="sv-title">Settings</span>
          <div className="version-badge" style={{ marginLeft: 'auto' }}>
            CERNIS PRO v{sysInfo.version || '1.0.0'}
          </div>
        </div>

        <div className="sv-body">

          {/* About */}
          <div className="sv-card">
            <div className="sv-card-title"><Settings size={11} /> About CERNIS PRO</div>
            <div className="sv-card-body">
              <div className="sv-row">
                <div className="sv-label">Version<small>CERNIS PRO</small></div>
                <span style={{ fontFamily:'var(--font-mono)', fontSize:13, color:'var(--accent)' }}>v{sysInfo.version || '…'}</span>
              </div>
              <div className="sv-row">
                <div className="sv-label">Backend API<small>FastAPI on port 8765</small></div>
                <a href="http://localhost:8765/docs" target="_blank" rel="noreferrer"
                  style={{ color:'var(--accent)', fontSize:11, fontFamily:'var(--font-mono)' }}>
                  localhost:8765/docs
                </a>
              </div>
              <div className="sv-row">
                <div className="sv-label">OUI Vendor DB<small>IEEE MAC vendor database</small></div>
                <button className="sv-btn secondary" onClick={() => fetch('/api/settings')}>
                  <RotateCcw size={11} /> Reload
                </button>
              </div>
            </div>
          </div>

          {/* Scan Configuration */}
          {scanConfig && onScanConfigChange && (
            <ScanConfigCard config={scanConfig} onChange={onScanConfigChange} />
          )}

          {/* Scan Profiles */}
          <div className="sv-card">
            <div className="sv-card-title"><Wifi size={11} /> Scan Profiles</div>
            <div className="sv-card-body">
              <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:4 }}>
                Built-in profiles — select in toolbar before scanning
              </div>
              <div className="profile-grid">
                {profiles.defaults.map(p => (
                  <div key={p.id} className="profile-card builtin">
                    <div className="profile-icon">{p.icon}</div>
                    <div className="profile-name">{p.name}</div>
                    <div className="profile-desc">{p.description}</div>
                  </div>
                ))}
                {profiles.custom.map(p => (
                  <div key={p.id} className="profile-card custom" style={{ position:'relative' }}>
                    <button onClick={() => fetch(`/api/profiles/${p.id}`, { method:'DELETE' }).then(loadAll)}
                      style={{ position:'absolute', top:4, right:4, background:'none', border:'none', color:'var(--text-muted)', cursor:'pointer' }}>
                      <Trash2 size={11} />
                    </button>
                    <div className="profile-icon">{p.icon || '⚙'}</div>
                    <div className="profile-name">{p.name}</div>
                    <div className="profile-desc">{p.description}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Scheduled Scans */}
          <div className="sv-card">
            <div className="sv-card-title"><Clock size={11} /> Scheduled Scans</div>
            <div className="sv-card-body">
              {schedules.length === 0 && (
                <div style={{ color:'var(--text-muted)', fontSize:12, padding:'8px 0' }}>
                  No schedules configured yet.
                </div>
              )}
              <div className="schedule-list">
                {schedules.map(s => (
                  <div key={s.id} className={`schedule-item${!s.enabled ? ' disabled' : ''}`}>
                    <label className="toggle" style={{ flexShrink:0 }}>
                      <input type="checkbox" checked={!!s.enabled} onChange={() => toggleSchedule(s.id, s.enabled)} />
                      <span className="toggle-slider" />
                    </label>
                    <div style={{ flex:1, minWidth:0 }}>
                      <div className="schedule-name">{s.name}</div>
                      <div className="schedule-meta">{s.cidr} · {s.profile_id} · {s.schedule}</div>
                      {s.next_run && <div className="schedule-next">Next: {new Date(s.next_run).toLocaleString('de-DE')}</div>}
                    </div>
                    <button className="sv-btn danger" onClick={() => deleteSchedule(s.id)}>
                      <Trash2 size={11} />
                    </button>
                  </div>
                ))}
              </div>

              {/* Add new schedule */}
              <div style={{ borderTop:'1px solid var(--border)', paddingTop:12, marginTop:4 }}>
                <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:8, textTransform:'uppercase', letterSpacing:'0.08em', fontWeight:700 }}>
                  Add Schedule
                </div>
                <div className="add-row">
                  <input className="sv-input" value={newSched.name}
                    onChange={e => setNewSched(p => ({ ...p, name: e.target.value }))}
                    placeholder="Schedule name" style={{ flex:1, minWidth:120 }} />
                  <input className="sv-input" value={newSched.cidr}
                    onChange={e => setNewSched(p => ({ ...p, cidr: e.target.value }))}
                    placeholder="CIDR" style={{ width:150 }} />
                </div>
                <div className="add-row" style={{ marginTop:6 }}>
                  <select className="sv-select" value={newSched.profile_id}
                    onChange={e => setNewSched(p => ({ ...p, profile_id: e.target.value }))}>
                    {allProfiles.map(p => <option key={p.id} value={p.id}>{p.icon} {p.name}</option>)}
                  </select>
                  <select className="sv-select" value={newSched.schedule}
                    onChange={e => setNewSched(p => ({ ...p, schedule: e.target.value }))}>
                    {SCHEDULE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                  <button className="sv-btn primary" onClick={addSchedule}>
                    <Plus size={12} /> Add
                  </button>
                </div>
              </div>
            </div>
          </div>


          {/* System / Dependencies */}
          <div className="sv-card">
            <div className="sv-card-title"><Settings size={11} /> Dependencies</div>
            <div className="sv-card-body">
              {[
                ['fritzconnection', 'FritzBox TR-064 Integration',      'pip install fritzconnection', false],
                ['scapy',          'Packet Capture, LLDP, Rogue DHCP', 'pip install scapy',           true],
                ['pysnmp',         'SNMP Discovery',                    'pip install pysnmp',          false],
                ['dnspython',      'Advanced DNS Lookup',               'pip install dnspython',       false],
                ['reportlab',      'PDF Report Export',                 'pip install reportlab',       false],
                ['cryptography',   'Credential Encryption (AES-128)',   'pip install cryptography',    false],
                ['apscheduler',    'Scheduled Scans',                   'pip install apscheduler',     false],
                ['websockets',     'Remote Agent WebSocket',            'pip install websockets',      false],
                ['nmap',           'Deep Port Scan (optional)',          navigator.platform?.includes('Win') ? 'winget install Insecure.Nmap' : 'brew install nmap', true],
              ].map(([pkg, desc, cmd, isOptional]) => (
                <div key={pkg} className="sv-row" style={{ flexWrap:'wrap', gap:6 }}>
                  <div className="sv-label" style={{ minWidth:160 }}>
                    {desc}
                    <small>{pkg}{isOptional ? ' (optional)' : ''}</small>
                  </div>
                  {sysInfo[pkg] === true
                    ? <span style={{ color:'var(--green)', fontSize:11, fontFamily:'var(--font-mono)', fontWeight:700 }}>✓ installed</span>
                    : sysInfo[pkg] === false
                    ? <div style={{ display:'flex', gap:6, alignItems:'center', flexWrap:'wrap' }}>
                        <span style={{ color:'var(--red)', fontSize:11, fontFamily:'var(--font-mono)' }}>✗ missing</span>
                        {!pkg.includes('nmap') && (
                          <button
                            onClick={() => installPkg(pkg)}
                            disabled={installing[pkg]}
                            style={{ padding:'2px 9px', borderRadius:3, fontSize:10, fontWeight:700, cursor:'pointer', border:'1px solid rgba(0,212,255,0.3)', background:'rgba(0,212,255,0.1)', color:'var(--accent)', textTransform:'uppercase', letterSpacing:'0.06em' }}>
                            {installing[pkg] ? 'Installing…' : '⬇ Install'}
                          </button>
                        )}
                        <code style={{ fontSize:10, fontFamily:'var(--font-mono)', background:'var(--bg-4)', padding:'2px 7px', borderRadius:3, color:'var(--text-secondary)' }}>{cmd}</code>
                      </div>
                    : <span style={{ color:'var(--text-muted)', fontSize:11 }}>…</span>
                  }
                </div>
              ))}
              <div style={{ marginTop:8, padding:'8px 12px', background:'var(--bg-3)', borderRadius:4, fontSize:11, color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>
                💡 {navigator.platform?.includes('Win')
                  ? <>On Windows, install <span style={{ color:'var(--accent)' }}>Npcap</span> (npcap.com) and <span style={{ color:'var(--accent)' }}>Nmap</span> (nmap.org) separately</>
                  : <>Run <span style={{ color:'var(--accent)' }}>./start.sh</span> to auto-install all available packages</>}
              </div>
            </div>
          </div>
          {/* Data */}
          <div className="sv-card">
            <div className="sv-card-title"><Database size={11} /> Data & Storage</div>
            <div className="sv-card-body">
              <div className="sv-row">
                <div className="sv-label">Scan History<small>Stored in SQLite locally</small></div>
                <a href="/api/history" target="_blank" style={{ color:'var(--accent)', fontSize:11 }}>View</a>
              </div>
              <div className="sv-row">
                <div className="sv-label">Encryption Key<small>~/.cernis/keyring (0600)</small></div>
                <span style={{ fontSize:11, color:'var(--green)', fontFamily:'var(--font-mono)' }}>AES-128 · Active</span>
              </div>
            </div>
          </div>

          {/* Internet / API Keys */}
          <div className="sv-card">
            <div className="sv-card-title"><Database size={11} /> API Keys</div>
            <div className="sv-card-body">
              <ShodanKeyRow />
            </div>
          </div>

        {/* Spacer to ensure last card is fully visible when scrolled */}
        <div style={{ height: 200, flexShrink: 0 }} />
        </div>
      </div>
    </>
  )
}
