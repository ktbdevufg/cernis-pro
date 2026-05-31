import React, { useState, useEffect } from 'react'
import { X, GitCompare, Plus, Minus, Equal } from 'lucide-react'

const css = `
.diff-overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,0.8);
  z-index: 700; display: flex; flex-direction: column;
}
.diff-header {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 18px; border-bottom: 1px solid var(--border);
  background: var(--bg-1); flex-shrink: 0;
}
.diff-title { font-size: 14px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); flex: 1; }
.diff-close { background: none; color: var(--text-muted); padding: 4px; border-radius: 4px; display: flex; cursor: pointer; }
.diff-close:hover { background: var(--bg-4); color: var(--text-primary); }

.diff-selector {
  display: flex; align-items: center; gap: 12px;
  padding: 12px 18px; background: var(--bg-2); border-bottom: 1px solid var(--border); flex-shrink: 0;
}
.diff-select-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; }
.diff-select {
  background: var(--bg-3); border: 1px solid var(--border);
  color: var(--text-primary); padding: 6px 10px; border-radius: 4px;
  font-size: 12px; font-family: var(--font-mono); flex: 1; max-width: 280px;
}
.diff-vs { color: var(--text-muted); font-size: 12px; font-weight: 700; }
.diff-run-btn {
  display: flex; align-items: center; gap: 5px;
  background: var(--accent); color: var(--bg-0);
  padding: 7px 16px; border-radius: 4px; font-size: 12px; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.08em; cursor: pointer;
}
.diff-run-btn:hover { background: #33ddff; }
.diff-run-btn:disabled { opacity: 0.5; cursor: not-allowed; }

.diff-stats {
  display: flex; gap: 16px;
  padding: 8px 18px; background: var(--bg-1); border-bottom: 1px solid var(--border); flex-shrink: 0;
}
.diff-stat { display: flex; align-items: center; gap: 6px; font-size: 12px; font-family: var(--font-mono); }
.diff-stat-val { font-size: 18px; font-weight: 700; }
.diff-stat.new    .diff-stat-val { color: var(--green); }
.diff-stat.gone   .diff-stat-val { color: var(--red); }
.diff-stat.portchg .diff-stat-val { color: var(--orange); }
.diff-stat.same   .diff-stat-val { color: var(--text-muted); }

.diff-body { flex: 1; overflow-y: auto; padding: 12px 18px; display: flex; flex-direction: column; gap: 4px; }
.diff-row {
  display: flex; align-items: flex-start; gap: 10px;
  padding: 8px 12px; border-radius: 4px; font-size: 12px;
  border: 1px solid transparent;
}
.diff-row.new  { background: rgba(0,230,118,0.06); border-color: rgba(0,230,118,0.2); }
.diff-row.gone { background: rgba(255,61,61,0.06); border-color: rgba(255,61,61,0.2); }
.diff-row.changed { background: rgba(255,153,0,0.06); border-color: rgba(255,153,0,0.2); }
.diff-row.same { opacity: 0.5; }

.diff-badge {
  flex-shrink: 0; width: 18px; height: 18px; border-radius: 3px;
  display: flex; align-items: center; justify-content: center; margin-top: 1px;
}
.diff-badge.new  { background: rgba(0,230,118,0.2); color: var(--green); }
.diff-badge.gone { background: rgba(255,61,61,0.2); color: var(--red); }
.diff-badge.changed { background: rgba(255,153,0,0.2); color: var(--orange); }
.diff-badge.same { background: var(--bg-4); color: var(--text-muted); }

.diff-ip { font-family: var(--font-mono); font-weight: 600; color: var(--text-primary); width: 120px; flex-shrink: 0; }
.diff-info { flex: 1; display: flex; flex-direction: column; gap: 3px; }
.diff-host { font-size: 11px; color: var(--accent); }
.diff-ports { display: flex; flex-wrap: wrap; gap: 3px; }
.diff-port { font-size: 10px; padding: 1px 5px; border-radius: 2px; font-family: var(--font-mono); }
.diff-port.added   { background: rgba(0,230,118,0.15); color: var(--green); border: 1px solid rgba(0,230,118,0.3); }
.diff-port.removed { background: rgba(255,61,61,0.12); color: var(--red); border: 1px solid rgba(255,61,61,0.3); text-decoration: line-through; }
.diff-port.same    { background: rgba(0,212,255,0.08); color: var(--accent); border: 1px solid rgba(0,212,255,0.15); }

.diff-empty { flex: 1; display: flex; align-items: center; justify-content: center; color: var(--text-muted); font-size: 13px; }
`

function computeDiff(scanA, scanB) {
  const mapA = Object.fromEntries((scanA?.hosts || []).map(h => [h.ip, h]))
  const mapB = Object.fromEntries((scanB?.hosts || []).map(h => [h.ip, h]))
  const allIps = [...new Set([...Object.keys(mapA), ...Object.keys(mapB)])]

  return allIps.sort((a, b) => {
    const toNum = ip => ip.split('.').reduce((acc,n) => acc*256+parseInt(n), 0)
    return toNum(a) - toNum(b)
  }).map(ip => {
    const a = mapA[ip], b = mapB[ip]
    if (!a && b) return { ip, type: 'new', host: b, portsA: [], portsB: b.ports || [] }
    if (a && !b) return { ip, type: 'gone', host: a, portsA: a.ports || [], portsB: [] }

    const portsA = new Set((a.ports || []).map(p => p.port))
    const portsB = new Set((b.ports || []).map(p => p.port))
    const added   = [...portsB].filter(p => !portsA.has(p))
    const removed = [...portsA].filter(p => !portsB.has(p))
    const same    = [...portsB].filter(p => portsA.has(p))
    const changed = added.length > 0 || removed.length > 0

    return {
      ip, type: changed ? 'changed' : 'same', host: b,
      portsA: a.ports || [], portsB: b.ports || [],
      added, removed, same,
    }
  })
}

export default function PortDiff({ onClose }) {
  const [history, setHistory] = useState([])
  const [scanIdA, setScanIdA] = useState('')
  const [scanIdB, setScanIdB] = useState('')
  const [scanA, setScanA] = useState(null)
  const [scanB, setScanB] = useState(null)
  const [diff, setDiff] = useState(null)
  const [loading, setLoading] = useState(false)
  const [showSame, setShowSame] = useState(false)

  useEffect(() => {
    fetch('/api/history?limit=20').then(r => r.json()).then(data => {
      setHistory(data)
      if (data.length >= 2) { setScanIdA(String(data[1].id)); setScanIdB(String(data[0].id)) }
      else if (data.length === 1) { setScanIdA(String(data[0].id)) }
    })
  }, [])

  const runDiff = async () => {
    if (!scanIdA || !scanIdB) return
    setLoading(true)
    const [resA, resB] = await Promise.all([
      fetch(`/api/history/${scanIdA}`).then(r => r.json()),
      fetch(`/api/history/${scanIdB}`).then(r => r.json()),
    ])
    setScanA(resA); setScanB(resB)
    setDiff(computeDiff(resA, resB))
    setLoading(false)
  }

  const counts = diff ? {
    new: diff.filter(r => r.type === 'new').length,
    gone: diff.filter(r => r.type === 'gone').length,
    changed: diff.filter(r => r.type === 'changed').length,
    same: diff.filter(r => r.type === 'same').length,
  } : null

  const displayed = diff ? (showSame ? diff : diff.filter(r => r.type !== 'same')) : []

  const fmtDate = (s) => {
    if (!s) return ''
    return new Date(s + 'Z').toLocaleString('de-DE', { dateStyle:'short', timeStyle:'short' })
  }

  return (
    <>
      <style>{css}</style>
      <div className="diff-overlay">
        <div className="diff-header">
          <GitCompare size={16} color="var(--accent)" />
          <span className="diff-title">Scan Diff — Port Changes</span>
          <button className="diff-close" onClick={onClose}><X size={16} /></button>
        </div>

        <div className="diff-selector">
          <span className="diff-select-label">Scan A</span>
          <select className="diff-select" value={scanIdA} onChange={e => setScanIdA(e.target.value)}>
            <option value="">— Select scan —</option>
            {history.map(h => (
              <option key={h.id} value={h.id}>#{h.id} · {fmtDate(h.scanned_at)} · {h.cidr} · {h.host_count} hosts</option>
            ))}
          </select>
          <span className="diff-vs">→</span>
          <span className="diff-select-label">Scan B</span>
          <select className="diff-select" value={scanIdB} onChange={e => setScanIdB(e.target.value)}>
            <option value="">— Select scan —</option>
            {history.map(h => (
              <option key={h.id} value={h.id}>#{h.id} · {fmtDate(h.scanned_at)} · {h.cidr} · {h.host_count} hosts</option>
            ))}
          </select>
          <button className="diff-run-btn" onClick={runDiff} disabled={!scanIdA || !scanIdB || loading}>
            {loading ? '…' : <><GitCompare size={13} /> Compare</>}
          </button>
        </div>

        {counts && (
          <div className="diff-stats">
            <div className="diff-stat new">
              <div className="diff-stat-val">{counts.new}</div>
              <div>New hosts</div>
            </div>
            <div className="diff-stat gone">
              <div className="diff-stat-val">{counts.gone}</div>
              <div>Gone hosts</div>
            </div>
            <div className="diff-stat portchg">
              <div className="diff-stat-val">{counts.changed}</div>
              <div>Port changes</div>
            </div>
            <div className="diff-stat same">
              <div className="diff-stat-val">{counts.same}</div>
              <div>Unchanged</div>
            </div>
            <label style={{ marginLeft:'auto', display:'flex', alignItems:'center', gap:6, fontSize:11, color:'var(--text-muted)', cursor:'pointer' }}>
              <input type="checkbox" checked={showSame} onChange={e => setShowSame(e.target.checked)} />
              Show unchanged
            </label>
          </div>
        )}

        <div className="diff-body">
          {!diff && <div className="diff-empty">Select two scans and click Compare</div>}
          {displayed.map(row => (
            <div key={row.ip} className={`diff-row ${row.type}`}>
              <div className={`diff-badge ${row.type}`}>
                {row.type === 'new'     && <Plus size={11} />}
                {row.type === 'gone'    && <Minus size={11} />}
                {row.type === 'changed' && <span style={{fontSize:10,fontWeight:700}}>Δ</span>}
                {row.type === 'same'    && <Equal size={11} />}
              </div>
              <span className="diff-ip">{row.ip}</span>
              <div className="diff-info">
                {row.host.hostname && <span className="diff-host">{row.host.hostname}</span>}
                <div className="diff-ports">
                  {row.type === 'new' && row.portsB.map(p =>
                    <span key={p.port} className="diff-port added">{p.port}</span>)}
                  {row.type === 'gone' && row.portsA.map(p =>
                    <span key={p.port} className="diff-port removed">{p.port}</span>)}
                  {row.type === 'changed' && <>
                    {(row.added||[]).map(p => <span key={`a${p}`} className="diff-port added">+{p}</span>)}
                    {(row.removed||[]).map(p => <span key={`r${p}`} className="diff-port removed">-{p}</span>)}
                    {(row.same||[]).slice(0,4).map(p => <span key={`s${p}`} className="diff-port same">{p}</span>)}
                    {(row.same||[]).length > 4 && <span style={{fontSize:10,color:'var(--text-muted)'}}>+{row.same.length-4} same</span>}
                  </>}
                  {row.type === 'same' && row.portsB.slice(0,6).map(p =>
                    <span key={p.port} className="diff-port same">{p.port}</span>)}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </>
  )
}
