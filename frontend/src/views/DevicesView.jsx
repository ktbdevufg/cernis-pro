import React, { useState, useEffect } from 'react'
import { Database, RefreshCw, Search, Tag, Clock, CheckCircle, AlertCircle } from 'lucide-react'

const css = `
.devices-view { position: absolute; inset: 0; display: flex; flex-direction: column; }
.devices-header {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 20px; border-bottom: 1px solid var(--border);
  background: var(--bg-1); flex-shrink: 0;
}
.devices-title { font-size: 13px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); }
.devices-search {
  background: var(--bg-3); border: 1px solid var(--border);
  color: var(--text-primary); padding: 5px 10px; border-radius: 4px;
  font-size: 12px; font-family: var(--font-mono); width: 200px;
}
.devices-search:focus { border-color: var(--accent-dim); outline: none; }
.stat-chips { display: flex; gap: 6px; margin-left: auto; }
.stat-chip {
  padding: 3px 10px; border-radius: 3px; font-size: 10px; font-weight: 700;
  letter-spacing: 0.06em; text-transform: uppercase; font-family: var(--font-mono);
  border: 1px solid var(--border);
}
.stat-chip.total   { color: var(--accent); border-color: rgba(0,212,255,0.3); background: rgba(0,212,255,0.06); }
.stat-chip.known   { color: var(--green); border-color: rgba(0,230,118,0.3); background: rgba(0,230,118,0.06); }
.stat-chip.unknown { color: var(--orange); border-color: rgba(255,153,0,0.3); background: rgba(255,153,0,0.06); }
.stat-chip.active  { color: var(--purple); border-color: rgba(187,134,252,0.3); background: rgba(187,134,252,0.06); }

.devices-table-wrap { flex: 1; overflow-y: auto; }
.devices-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.devices-table thead { position: sticky; top: 0; z-index: 5; }
.devices-table th {
  background: var(--bg-2); border-bottom: 2px solid var(--border); border-right: 1px solid var(--border);
  padding: 0 12px; height: 30px; text-align: left;
  font-size: 9px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-muted);
}
.devices-table th:last-child { border-right: none; }
.devices-table td {
  padding: 0 12px; height: 36px; border-bottom: 1px solid var(--border); border-right: 1px solid var(--border);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; vertical-align: middle;
}
.devices-table td:last-child { border-right: none; }
.devices-table tr:hover td { background: var(--bg-3); cursor: pointer; }
.devices-table tr.unknown td:first-child { border-left: 2px solid var(--orange); }
.devices-table tr.known td:first-child { border-left: 2px solid var(--green); }

.d-ip     { font-family: var(--font-mono); font-size: 11px; color: var(--text-primary); font-weight: 500; }
.d-mac    { font-family: var(--font-mono); font-size: 10px; color: var(--text-muted); }
.d-vendor { font-size: 11px; color: var(--text-secondary); }
.d-label  { font-size: 11px; color: var(--yellow); font-style: italic; }
.d-date   { font-family: var(--font-mono); font-size: 10px; color: var(--text-muted); }
.d-count  { font-family: var(--font-mono); font-size: 11px; color: var(--accent); text-align: right; }
.d-ports  { font-family: var(--font-mono); font-size: 10px; color: var(--text-secondary); }

.known-toggle {
  width: 20px; height: 20px; border-radius: 50%; border: none; cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  background: none; transition: all 0.1s;
}
.known-toggle.is-known  { color: var(--green); }
.known-toggle.not-known { color: var(--text-muted); }
.known-toggle:hover { transform: scale(1.2); }

.filter-bar {
  display: flex; align-items: center; gap: 8px;
  padding: 6px 20px; background: var(--bg-1); border-bottom: 1px solid var(--border); flex-shrink: 0;
}
.filter-btn {
  padding: 3px 10px; border-radius: 3px; font-size: 10px; font-weight: 600; cursor: pointer;
  background: var(--bg-3); border: 1px solid var(--border); color: var(--text-muted);
  text-transform: uppercase; letter-spacing: 0.06em; transition: all 0.1s;
}
.filter-btn.active { background: rgba(0,212,255,0.1); border-color: var(--accent-dim); color: var(--accent); }
`

function fmtDate(s) {
  if (!s) return '—'
  try {
    const d = new Date(s)
    const now = new Date()
    const diff = now - d
    if (diff < 60000)  return 'just now'
    if (diff < 3600000) return `${Math.floor(diff/60000)}m ago`
    if (diff < 86400000) return `${Math.floor(diff/3600000)}h ago`
    return d.toLocaleDateString('de-DE', { day:'2-digit', month:'2-digit', year:'2-digit' })
  } catch { return s }
}

export default function DevicesView() {
  const [devices, setDevices] = useState([])
  const [stats, setStats] = useState({})
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('all')
  const [loading, setLoading] = useState(true)

  const load = async () => {
    setLoading(true)
    const [devs, st] = await Promise.all([
      fetch('/api/devices').then(r => r.json()),
      fetch('/api/devices/stats').then(r => r.json()),
    ])
    setDevices(devs)
    setStats(st)
    setLoading(false)
  }

  useEffect(() => { load() }, [])

  const toggleKnown = async (e, mac, isKnown) => {
    e.stopPropagation()
    await fetch(`/api/devices/${encodeURIComponent(mac)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_known: !isKnown }),
    })
    load()
  }

  const filtered = devices.filter(d => {
    if (filter === 'known'   && !d.is_known) return false
    if (filter === 'unknown' && d.is_known)  return false
    if (filter === 'active') {
      const diff = new Date() - new Date(d.last_seen)
      if (diff > 86400000) return false
    }
    if (search) {
      const q = search.toLowerCase()
      return [d.mac, d.last_ip, d.vendor, d.label, d.hostname, d.tags?.join(' ')].some(
        f => f && f.toLowerCase().includes(q)
      )
    }
    return true
  })

  return (
    <>
      <style>{css}</style>
      <div className="devices-view">
        <div className="devices-header">
          <Database size={14} color="var(--accent)" />
          <span className="devices-title">Device Database</span>
          <input className="devices-search" value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search IP, MAC, vendor…" />
          <div className="stat-chips">
            <span className="stat-chip total">Total {stats.total || 0}</span>
            <span className="stat-chip known">Known {stats.known || 0}</span>
            <span className="stat-chip unknown">Unknown {stats.unknown || 0}</span>
            <span className="stat-chip active">Active 24h {stats.active_24h || 0}</span>
          </div>
          <button onClick={load} style={{ background:'none', border:'none', color:'var(--text-muted)', cursor:'pointer', marginLeft:4 }}>
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>

        <div className="filter-bar">
          {[['all','All'],['known','Known'],['unknown','Unknown'],['active','Active 24h']].map(([v,l]) => (
            <button key={v} className={`filter-btn${filter===v?' active':''}`} onClick={() => setFilter(v)}>{l}</button>
          ))}
          <span style={{ marginLeft:'auto', fontSize:10, color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>
            {filtered.length} devices · Click ✓ to mark as known
          </span>
        </div>

        <div className="devices-table-wrap">
          <table className="devices-table">
            <thead>
              <tr>
                <th style={{width:30}}></th>
                <th style={{width:120}}>Last IP</th>
                <th style={{width:140}}>MAC</th>
                <th style={{width:180}}>Vendor</th>
                <th style={{width:140}}>Hostname</th>
                <th style={{width:130}}>Label</th>
                <th style={{width:120}}>First Seen</th>
                <th style={{width:120}}>Last Seen</th>
                <th style={{width:60}}>Seen</th>
                <th style={{width:140}}>Open Ports</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(d => (
                <tr key={d.mac} className={d.is_known ? 'known' : 'unknown'}>
                  <td>
                    <button className={`known-toggle${d.is_known ? ' is-known' : ' not-known'}`}
                      onClick={e => toggleKnown(e, d.mac, d.is_known)}
                      title={d.is_known ? 'Mark unknown' : 'Mark known'}>
                      {d.is_known ? <CheckCircle size={14} /> : <AlertCircle size={14} />}
                    </button>
                  </td>
                  <td><span className="d-ip">{d.last_ip || '—'}</span></td>
                  <td><span className="d-mac">{d.mac}</span></td>
                  <td><span className="d-vendor">{d.vendor || '—'}</span></td>
                  <td><span style={{fontSize:11, color:'var(--accent)'}}>{d.hostname || '—'}</span></td>
                  <td><span className="d-label">{d.label || '—'}</span></td>
                  <td><span className="d-date">{fmtDate(d.first_seen)}</span></td>
                  <td><span className="d-date">{fmtDate(d.last_seen)}</span></td>
                  <td><span className="d-count">{d.times_seen}×</span></td>
                  <td><span className="d-ports">{(d.open_ports||[]).slice(0,5).join(', ')}{(d.open_ports||[]).length>5?` +${d.open_ports.length-5}`:''}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length === 0 && !loading && (
            <div style={{ padding:40, textAlign:'center', color:'var(--text-muted)', fontSize:13 }}>
              No devices found — run a scan to populate the database
            </div>
          )}
        </div>
      </div>
    </>
  )
}
