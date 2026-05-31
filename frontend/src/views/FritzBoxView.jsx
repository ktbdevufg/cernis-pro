import React, { useState, useEffect } from 'react'
import { Router, Wifi, Globe, Activity, FileText, RefreshCw, LogIn, LogOut, Signal, Edit3, Trash2 } from 'lucide-react'

const css = `
.fritz-view { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
.fritz-header {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 20px; border-bottom: 1px solid var(--border);
  background: var(--bg-1); flex-shrink: 0;
}
.fritz-title { font-size: 13px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); }
.fritz-body { flex: 1; overflow-y: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 16px; }

/* Connect form */
.fritz-connect {
  background: var(--bg-2); border: 1px solid var(--border); border-radius: 8px;
  padding: 24px; display: flex; flex-direction: column; align-items: center; gap: 16px;
}
.fritz-connect-title { font-size: 15px; font-weight: 700; color: var(--text-primary); }
.fritz-connect-sub { font-size: 12px; color: var(--text-muted); text-align: center; }
.fritz-form { display: flex; flex-direction: column; gap: 10px; width: 100%; max-width: 360px; }
.fritz-input {
  background: var(--bg-3); border: 1px solid var(--border);
  color: var(--text-primary); padding: 8px 12px; border-radius: 4px;
  font-size: 13px; font-family: var(--font-mono);
}
.fritz-input:focus { border-color: var(--accent-dim); outline: none; }
.fritz-input-row { display: flex; gap: 8px; }
.fritz-login-btn {
  display: flex; align-items: center; justify-content: center; gap: 6px;
  background: var(--accent); color: var(--bg-0);
  padding: 9px; border-radius: 4px; font-size: 13px; font-weight: 700;
  cursor: pointer; border: none; transition: all 0.15s;
}
.fritz-login-btn:hover { background: #33ddff; }
.fritz-login-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.fritz-detect-btn {
  background: none; border: 1px solid var(--border); color: var(--text-secondary);
  padding: 7px 14px; border-radius: 4px; font-size: 12px; font-weight: 600;
  cursor: pointer; transition: all 0.12s;
}
.fritz-detect-btn:hover { border-color: var(--border-bright); color: var(--text-primary); }

/* Status grid */
.fritz-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.fritz-card {
  background: var(--bg-2); border: 1px solid var(--border); border-radius: 6px; padding: 14px;
}
.fritz-card-title {
  font-size: 9px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--text-muted); margin-bottom: 10px; display: flex; align-items: center; gap: 5px;
}
.fritz-kv { display: flex; justify-content: space-between; gap: 8px; margin-bottom: 5px; font-size: 12px; }
.fritz-k { color: var(--text-muted); }
.fritz-v { font-family: var(--font-mono); color: var(--text-primary); text-align: right; }
.fritz-v.accent  { color: var(--accent); }
.fritz-v.green   { color: var(--green); }
.fritz-v.red     { color: var(--red); }
.fritz-v.orange  { color: var(--orange); }

/* Big metric */
.fritz-big-val { font-size: 22px; font-weight: 700; font-family: var(--font-mono); color: var(--accent); }
.fritz-big-unit { font-size: 11px; color: var(--text-muted); }

/* WLAN clients table */
.fritz-clients-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.fritz-clients-table th {
  background: var(--bg-3); border-bottom: 1px solid var(--border);
  padding: 6px 10px; text-align: left; font-size: 9px; font-weight: 700;
  letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-muted);
}
.fritz-clients-table td {
  padding: 6px 10px; border-bottom: 1px solid var(--border);
  font-family: var(--font-mono); color: var(--text-secondary);
}
.fritz-clients-table tr:hover td { background: var(--bg-3); }
.signal-bar { display: flex; align-items: center; gap: 6px; }
.signal-dots { display: flex; gap: 2px; }
.signal-dot { width: 5px; height: 5px; border-radius: 50%; background: var(--bg-4); }
.signal-dot.on-good { background: var(--green); }
.signal-dot.on-ok   { background: var(--yellow); }
.signal-dot.on-bad  { background: var(--orange); }

/* Log */
.fritz-log { display: flex; flex-direction: column; gap: 2px; }
.fritz-log-row {
  display: flex; gap: 10px; padding: 5px 8px; border-radius: 3px;
  font-size: 11px; font-family: var(--font-mono);
  border-bottom: 1px solid var(--border);
}
.fritz-log-ts  { color: var(--text-muted); flex-shrink: 0; width: 120px; }
.fritz-log-msg { color: var(--text-secondary); flex: 1; }
.fritz-log-msg.warn  { color: var(--orange); }
.fritz-log-msg.error { color: var(--red); }

/* Tab bar */
.fritz-tabs { display: flex; gap: 4px; margin-bottom: 4px; }
.fritz-tab {
  padding: 5px 14px; border-radius: 4px; font-size: 11px; font-weight: 600; cursor: pointer;
  background: var(--bg-3); border: 1px solid var(--border); color: var(--text-muted);
  text-transform: uppercase; letter-spacing: 0.06em; transition: all 0.1s;
}
.fritz-tab.active { background: rgba(0,212,255,0.1); border-color: var(--accent-dim); color: var(--accent); }

.fritz-error { color: var(--red); font-size: 12px; font-family: var(--font-mono); text-align: center; }
.fritz-logout-btn {
  display: flex; align-items: center; gap: 4px;
  background: none; border: 1px solid var(--border); color: var(--text-muted);
  padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600;
  cursor: pointer; transition: all 0.12s;
}
.fritz-logout-btn:hover { border-color: var(--red); color: var(--red); }
`

function SignalBars({ dbm }) {
  const level = dbm >= -50 ? 4 : dbm >= -65 ? 3 : dbm >= -75 ? 2 : 1
  const cls = dbm >= -65 ? 'on-good' : dbm >= -75 ? 'on-ok' : 'on-bad'
  return (
    <div className="signal-bar">
      <div className="signal-dots">
        {[1,2,3,4].map(i => (
          <div key={i} className={`signal-dot ${i <= level ? cls : ''}`} />
        ))}
      </div>
      <span style={{ fontSize:10, color: 'var(--text-muted)', fontFamily:'var(--font-mono)' }}>
        {dbm} dBm
      </span>
    </div>
  )
}

function KV({ k, v, cls = '' }) {
  return (
    <div className="fritz-kv">
      <span className="fritz-k">{k}</span>
      <span className={`fritz-v ${cls}`}>{v ?? '—'}</span>
    </div>
  )
}

function fmtBytes(b) {
  if (!b) return '—'
  if (b > 1e9) return `${(b/1e9).toFixed(1)} GB`
  if (b > 1e6) return `${(b/1e6).toFixed(1)} MB`
  return `${(b/1e3).toFixed(0)} KB`
}

function fmtUptime(s) {
  if (!s) return '—'
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  return d > 0 ? `${d}d ${h}h ${m}m` : `${h}h ${m}m`
}

export default function FritzBoxView({ connected: connectedProp, onConnect, status: statusProp }) {
  const [connected, setConnected] = useState(connectedProp || false)
  const [host, setHost]           = useState('fritz.box')
  const [user, setUser]           = useState('')
  const [password, setPassword]   = useState('')
  const [status, setStatus]       = useState(statusProp || null)
  const [clients, setClients]     = useState([])
  const [log, setLog]             = useState([])
  const [tab, setTab]             = useState('overview')
  const [portForwards, setPortForwards] = useState([])
  const [loading, setLoading]     = useState(false)
  const [error, setError]         = useState(null)
  const [detecting, setDetecting] = useState(false)
  const [editing, setEditing]     = useState(false)

  // On mount: check if saved credentials exist → auto-reconnect
  React.useEffect(() => {
    if (connected) return
    fetch('/api/fritz/status').then(r => r.json()).then(data => {
      if (data.reachable && !data.auth_error && data.model) {
        setStatus(data)
        setHost(data.host || 'fritz.box')
        setConnected(true)
        onConnect && onConnect(data)
        loadAll()
      } else if (data.host) {
        setHost(data.host)
      }
    }).catch(() => {})
  }, [])

  // Sync with parent state when switching back to this view
  React.useEffect(() => {
    if (connectedProp && !connected) {
      setConnected(true)
    }
    if (statusProp && !status) {
      setStatus(statusProp)
      loadAll()
    }
  }, [connectedProp, statusProp])

  const handleDetect = async () => {
    setDetecting(true)
    setError(null)
    try {
      const res = await fetch('/api/fritz/detect')
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      if (data.found) {
        setHost(data.host)
      } else {
        setError('No FritzBox found — enter address manually')
      }
    } catch (e) {
      setError('Detection failed: ' + e.message)
    }
    setDetecting(false)
  }

  const handleConnect = async () => {
    setLoading(true); setError(null)
    try {
      const res = await fetch('/api/fritz/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host, user, password }),
      })
      let data
      try { data = await res.json() }
      catch (e) { throw new Error('Server returned invalid response — check backend logs') }
      if (!res.ok) { setError(data.error || 'Connection failed'); setLoading(false); return }
      setStatus(data.status)
      setConnected(true)
      setEditing(false)
      onConnect && onConnect(data.status)
      loadAll()
    } catch (e) {
      setError(String(e.message || e))
    }
    setLoading(false)
  }

  const handleEdit = () => {
    // Switch to login form but keep host/user pre-filled
    setEditing(true)
    setConnected(false)
    setPassword('')
    setError(null)
  }

  const handleDeleteCredentials = async () => {
    try {
      await fetch('/api/fritz/disconnect', { method: 'POST' })
    } catch (_) { /* ignore */ }
    setConnected(false)
    setEditing(false)
    setStatus(null)
    setClients([])
    setLog([])
    setPortForwards([])
    setHost('fritz.box')
    setUser('')
    setPassword('')
    setError(null)
  }

  const loadAll = async () => {
    const [cl, lg, pf] = await Promise.all([
      fetch('/api/fritz/wlan-clients').then(r => r.json()).catch(() => []),
      fetch('/api/fritz/log?limit=80').then(r => r.json()).catch(() => []),
      fetch('/api/fritz/port-forwardings').then(r => r.json()).catch(() => []),
    ])
    setClients(cl)
    setLog(lg)
    setPortForwards(Array.isArray(pf) ? pf : [])
  }

  const refresh = async () => {
    setLoading(true)
    const st = await fetch('/api/fritz/status').then(r => r.json()).catch(() => null)
    if (st) setStatus(st)
    await loadAll()
    setLoading(false)
  }

  const logClass = (msg) => {
    const m = msg.toLowerCase()
    if (m.includes('fehler') || m.includes('error') || m.includes('fail')) return 'error'
    if (m.includes('warn') || m.includes('disconnect') || m.includes('getrennt')) return 'warn'
    return ''
  }

  if (!connected) {
    return (
      <>
        <style>{css}</style>
        <div className="fritz-view">
          <div className="fritz-header">
            <Router size={14} color="var(--accent)" />
            <span className="fritz-title">FritzBox</span>
          </div>
          <div className="fritz-body">
            <div className="fritz-connect">
              <Router size={40} color="var(--accent)" style={{ opacity: 0.6 }} />
              <div className="fritz-connect-title">Connect to FritzBox</div>
              <div className="fritz-connect-sub">
                CERNIS PRO will auto-detect your FritzBox or you can enter the address manually.
                Login requires a FritzBox user with TR-064 access.
              </div>
              <div className="fritz-form">
                <div className="fritz-input-row">
                  <input className="fritz-input" style={{ flex:1 }} value={host}
                    onChange={e => setHost(e.target.value)} placeholder="fritz.box" />
                  <button className="fritz-detect-btn" onClick={handleDetect} disabled={detecting}>
                    {detecting ? '…' : '🔍 Detect'}
                  </button>
                </div>
                <input className="fritz-input" value={user}
                  onChange={e => setUser(e.target.value)} placeholder="Username (optional)" />
                <input className="fritz-input" type="password" value={password}
                  onChange={e => setPassword(e.target.value)} placeholder="Password" />
                {error && <div className="fritz-error">✗ {error}</div>}
                <button className="fritz-login-btn" onClick={handleConnect} disabled={loading}>
                  <LogIn size={15} />{loading ? 'Connecting…' : 'Connect'}
                </button>
              </div>
              <div style={{ fontSize:10, color:'var(--text-muted)', textAlign:'center', maxWidth:320 }}>
                Note: Most FritzBox models allow access without password on local network.
                If you use FritzBox user accounts, enable TR-064 in the FritzBox settings.
              </div>
            </div>
          </div>
        </div>
      </>
    )
  }

  const s = status || {}
  const isFiber = s.model && (s.model.toLowerCase().includes('fiber') || s.model.includes('5590') || s.model.includes('5530'))

  return (
    <>
      <style>{css}</style>
      <div className="fritz-view">
        <div className="fritz-header">
          <Router size={14} color="var(--accent)" />
          <span className="fritz-title">FritzBox</span>
          <span style={{ fontSize:11, color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>
            {s.model} · {host}
          </span>
          <button onClick={refresh} disabled={loading} style={{ marginLeft:'auto', background:'none', border:'none', color:'var(--text-muted)', cursor:'pointer' }}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          </button>
          <button className="fritz-logout-btn" onClick={handleEdit} title="Edit credentials">
            <Edit3 size={12} /> Edit
          </button>
          <button className="fritz-logout-btn" onClick={handleDeleteCredentials} title="Delete credentials and disconnect">
            <Trash2 size={12} /> Delete
          </button>
        </div>

        <div className="fritz-body">
          <div className="fritz-tabs">
            {[['overview','Overview'],['wlan','WLAN Clients'],['log','Event Log']].map(([v,l]) => (
              <button key={v} className={`fritz-tab${tab===v?' active':''}`} onClick={() => setTab(v)}>{l}</button>
            ))}
          </div>

          {/* ── Overview ── */}
          {tab === 'overview' && (
            <div className="fritz-grid">
              {/* WAN */}
              <div className="fritz-card">
                <div className="fritz-card-title"><Globe size={10} /> WAN / Internet</div>
                <KV k="Status" v={s.wan_connected ? 'Connected' : 'Offline'}
                  cls={s.wan_connected ? 'green' : 'red'} />
                <KV k="External IPv4" v={s.wan_ip_external} cls="accent" />
                {s.wan_ip_external_v6 && <KV k="External IPv6" v={s.wan_ip_external_v6.substring(0,24)+'…'} />}
                <KV k="Uptime" v={fmtUptime(s.wan_uptime_secs)} cls="green" />
                <KV k="↑ Sent" v={fmtBytes(s.wan_bytes_sent)} />
                <KV k="↓ Received" v={fmtBytes(s.wan_bytes_recv)} />
              </div>

              {/* DSL / Fiber */}
              <div className="fritz-card">
                {isFiber ? (
                  <>
                    <div className="fritz-card-title"><Activity size={10} /> Fiber / WAN Link</div>
                    <KV k="Link Status" v={s.dsl_sync ? 'Up' : 'Down'} cls={s.dsl_sync ? 'green' : 'red'} />
                    <KV k="Downstream" v={s.wan_downstream_kbps ? `${(s.wan_downstream_kbps/1000).toFixed(0)} Mbit/s` : '—'} cls="accent" />
                    <KV k="Upstream" v={s.wan_upstream_kbps ? `${(s.wan_upstream_kbps/1000).toFixed(0)} Mbit/s` : '—'} />
                    <KV k="↑ Sent" v={fmtBytes(s.wan_bytes_sent)} />
                    <KV k="↓ Received" v={fmtBytes(s.wan_bytes_recv)} />
                  </>
                ) : (
                  <>
                    <div className="fritz-card-title"><Activity size={10} /> DSL Line</div>
                    <KV k="Sync" v={s.dsl_sync ? 'Online' : 'No Sync'} cls={s.dsl_sync ? 'green' : 'red'} />
                    <KV k="Downstream" v={s.dsl_downstream_kbps ? `${(s.dsl_downstream_kbps/1000).toFixed(1)} Mbit/s` : '—'} cls="accent" />
                    <KV k="Upstream" v={s.dsl_upstream_kbps ? `${(s.dsl_upstream_kbps/1000).toFixed(1)} Mbit/s` : '—'} />
                    <KV k="SNR Down" v={s.dsl_snr_downstream ? `${s.dsl_snr_downstream} dB` : '—'} cls="green" />
                    <KV k="SNR Up" v={s.dsl_snr_upstream ? `${s.dsl_snr_upstream} dB` : '—'} />
                    <KV k="Attn. Down" v={s.dsl_attn_downstream ? `${s.dsl_attn_downstream} dB` : '—'} />
                  </>
                )}
              </div>

              {/* WLAN 2.4 GHz */}
              <div className="fritz-card">
                <div className="fritz-card-title"><Wifi size={10} /> WLAN 2.4 GHz</div>
                <KV k="Status" v={s.wlan_24_enabled ? 'Enabled' : 'Disabled'} cls={s.wlan_24_enabled ? 'green' : 'red'} />
                <KV k="SSID" v={s.wlan_24_ssid} cls="accent" />
                <KV k="Channel" v={s.wlan_24_channel || '—'} />
                <KV k="Clients" v={s.wlan_24_clients ?? '—'} cls="green" />
              </div>

              {/* WLAN 5 GHz */}
              <div className="fritz-card">
                <div className="fritz-card-title"><Wifi size={10} /> WLAN 5 GHz</div>
                <KV k="Status" v={s.wlan_5_enabled ? 'Enabled' : 'Disabled'} cls={s.wlan_5_enabled ? 'green' : 'red'} />
                <KV k="SSID" v={s.wlan_5_ssid} cls="accent" />
                <KV k="Channel" v={s.wlan_5_channel || '—'} />
                <KV k="Clients" v={s.wlan_5_clients ?? '—'} cls="green" />
              </div>

              {/* Device info */}
              <div className="fritz-card" style={{ gridColumn: 'span 2' }}>
                <div className="fritz-card-title"><Router size={10} /> Device</div>
                <div style={{ display:'flex', gap:32 }}>
                  <div style={{ flex:1 }}>
                    <KV k="Model" v={s.model} cls="accent" />
                    <KV k="Firmware" v={s.firmware} />
                  </div>
                  <div style={{ flex:1 }}>
                    <KV k="Total Hosts" v={s.total_hosts} />
                    <KV k="WLAN Clients" v={(s.wlan_24_clients||0) + (s.wlan_5_clients||0)} cls="green" />
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ── WLAN Clients ── */}
          {tab === 'wlan' && (
            <div>
              <table className="fritz-clients-table">
                <thead>
                  <tr>
                    <th>IP</th><th>MAC</th><th>Vendor</th>
                    <th>Hostname</th><th>Band</th><th>Signal</th><th>Speed</th>
                  </tr>
                </thead>
                <tbody>
                  {clients.map((c, i) => (
                    <tr key={i}>
                      <td style={{ color:'var(--text-primary)', fontWeight:500 }}>{c.ip || '—'}</td>
                      <td>{c.mac}</td>
                      <td style={{ fontFamily:'sans-serif', fontSize:11 }}>{c.vendor || '—'}</td>
                      <td>{c.hostname || '—'}</td>
                      <td>
                        <span style={{
                          padding:'1px 6px', borderRadius:3, fontSize:10,
                          background: c.band==='5GHz' ? 'rgba(0,212,255,0.1)' : 'rgba(187,134,252,0.1)',
                          color: c.band==='5GHz' ? 'var(--accent)' : 'var(--purple)',
                          border: `1px solid ${c.band==='5GHz' ? 'rgba(0,212,255,0.2)' : 'rgba(187,134,252,0.2)'}`,
                        }}>{c.band}</span>
                      </td>
                      <td><SignalBars dbm={c.signal_dbm} /></td>
                      <td>{c.speed_mbps ? `${c.speed_mbps} Mbps` : '—'}</td>
                    </tr>
                  ))}
                  {clients.length === 0 && (
                    <tr><td colSpan={7} style={{ textAlign:'center', color:'var(--text-muted)', padding:20 }}>
                      No WLAN clients — or FritzBox requires credentials for this data
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          )}

          {/* ── Event Log ── */}
          
              {tab === 'portfw' && (
                <div style={{ padding:14 }}>
                  {portForwards.length === 0 ? (
                    <div style={{ color:'var(--text-muted)', fontSize:12 }}>No port forwardings configured</div>
                  ) : (
                    <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
                      <thead>
                        <tr style={{ background:'var(--bg-3)' }}>
                          {['', 'Description', 'Protocol', 'External', 'Internal IP', 'Internal Port'].map(h => (
                            <th key={h} style={{ padding:'6px 10px', textAlign:'left', fontSize:9, fontWeight:700, letterSpacing:'0.1em', textTransform:'uppercase', color:'var(--text-muted)', borderBottom:'1px solid var(--border)' }}>{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {portForwards.map((pf, i) => (
                          <tr key={i} style={{ borderBottom:'1px solid var(--border)', opacity: pf.enabled ? 1 : 0.4 }}>
                            <td style={{ padding:'5px 10px' }}><span style={{ color: pf.enabled ? 'var(--green)' : 'var(--text-muted)' }}>{pf.enabled ? '●' : '○'}</span></td>
                            <td style={{ padding:'5px 10px', color:'var(--text-primary)', fontWeight:500 }}>{pf.description || '—'}</td>
                            <td style={{ padding:'5px 10px', fontFamily:'var(--font-mono)' }}>{pf.protocol}</td>
                            <td style={{ padding:'5px 10px', fontFamily:'var(--font-mono)', color:'var(--accent)' }}>{pf.external_port}</td>
                            <td style={{ padding:'5px 10px', fontFamily:'var(--font-mono)' }}>{pf.internal_ip}</td>
                            <td style={{ padding:'5px 10px', fontFamily:'var(--font-mono)' }}>{pf.internal_port}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}
              {tab === 'log' && (
            <div className="fritz-log">
              {log.map((e, i) => (
                <div key={i} className="fritz-log-row">
                  <span className="fritz-log-ts">{e.timestamp}</span>
                  <span className={`fritz-log-msg ${logClass(e.message)}`}>{e.message}</span>
                </div>
              ))}
              {log.length === 0 && (
                <div style={{ textAlign:'center', color:'var(--text-muted)', padding:20, fontSize:12 }}>
                  No log entries
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </>
  )
}
