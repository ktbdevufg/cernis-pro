import React, { useState, useEffect, useRef } from 'react'
import { Plus, Trash2, Activity, Wifi, Globe, Server } from 'lucide-react'

const css = `
.monitor-view {
  flex: 1; display: flex; flex-direction: column; overflow: hidden; background: var(--bg-0);
}
.monitor-header {
  display: flex; align-items: center; gap: 12px;
  padding: 12px 20px; border-bottom: 1px solid var(--border);
  background: var(--bg-1); flex-shrink: 0;
}
.monitor-title { font-size: 13px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); }
.monitor-body { flex: 1; overflow-y: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 16px; }

/* Status cards */
.status-cards { display: flex; gap: 10px; flex-wrap: wrap; }
.status-card {
  background: var(--bg-2); border: 1px solid var(--border); border-radius: 6px;
  padding: 12px 16px; min-width: 160px; flex: 1;
  display: flex; flex-direction: column; gap: 6px;
  transition: border-color 0.2s;
}
.status-card.up   { border-color: rgba(0,230,118,0.3); }
.status-card.down { border-color: rgba(255,61,61,0.4); background: rgba(255,61,61,0.04); }
.status-card.unknown { border-color: var(--border); }
.sc-top { display: flex; align-items: center; gap: 8px; }
.sc-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
.sc-dot.up   { background: var(--green); box-shadow: 0 0 8px var(--green); }
.sc-dot.down { background: var(--red); box-shadow: 0 0 8px var(--red); animation: pulse-dot 0.8s infinite; }
.sc-dot.unknown { background: var(--text-muted); }
.sc-label { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-secondary); flex: 1; }
.sc-status { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; }
.sc-status.up   { color: var(--green); }
.sc-status.down { color: var(--red); }
.sc-rtt { font-family: var(--font-mono); font-size: 20px; font-weight: 600; color: var(--text-primary); }
.sc-rtt.fast { color: var(--green); }
.sc-rtt.med  { color: var(--yellow); }
.sc-rtt.slow { color: var(--orange); }
.sc-loss { font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); }
.sc-loss.bad { color: var(--orange); }

/* RTT Graph */
.rtt-graph-wrap {
  background: var(--bg-2); border: 1px solid var(--border); border-radius: 6px;
  overflow: hidden;
}
.rtt-graph-header {
  display: flex; align-items: center; gap: 8px;
  padding: 10px 14px; border-bottom: 1px solid var(--border);
  font-size: 10px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-muted);
}
.rtt-graph-tabs { display: flex; gap: 4px; margin-left: auto; }
.rtt-tab {
  padding: 2px 8px; border-radius: 3px; font-size: 10px; cursor: pointer;
  background: var(--bg-3); border: 1px solid var(--border); color: var(--text-muted);
  font-family: var(--font-mono); transition: all 0.1s;
}
.rtt-tab.active { background: rgba(0,212,255,0.1); border-color: var(--accent-dim); color: var(--accent); }
.rtt-graph-canvas { height: 120px; padding: 8px 12px; }
.rtt-graph-canvas svg { width: 100%; height: 100%; overflow: visible; }

/* Event log */
.event-log-wrap {
  background: var(--bg-2); border: 1px solid var(--border); border-radius: 6px;
  flex: 1; min-height: 200px; display: flex; flex-direction: column;
}
.event-log-header {
  display: flex; align-items: center; gap: 8px;
  padding: 10px 14px; border-bottom: 1px solid var(--border);
  font-size: 10px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-muted);
  flex-shrink: 0;
}
.event-log-body { flex: 1; overflow-y: auto; }
.event-row {
  display: flex; align-items: center; gap: 10px;
  padding: 6px 14px; border-bottom: 1px solid var(--border);
  font-size: 11px; font-family: var(--font-mono);
}
.event-row:last-child { border-bottom: none; }
.event-time { color: var(--text-muted); width: 60px; flex-shrink: 0; }
.event-label { color: var(--text-secondary); width: 140px; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.event-msg { flex: 1; }
.event-msg.up      { color: var(--green); }
.event-msg.down    { color: var(--red); }
.event-msg.degraded { color: var(--orange); }
.event-rtt { color: var(--text-muted); width: 70px; text-align: right; flex-shrink: 0; }

/* Add target */
.add-target-row {
  display: flex; gap: 8px; align-items: center;
  padding: 10px 14px; border-top: 1px solid var(--border);
  flex-shrink: 0;
}
.add-target-input {
  background: var(--bg-3); border: 1px solid var(--border);
  color: var(--text-primary); padding: 5px 8px; border-radius: 4px;
  font-size: 12px; font-family: var(--font-mono); flex: 1;
}
.add-target-input:focus { border-color: var(--accent-dim); outline: none; }
.add-btn {
  display: flex; align-items: center; gap: 4px;
  background: rgba(0,212,255,0.1); border: 1px solid var(--accent-dim);
  color: var(--accent); padding: 5px 10px; border-radius: 4px;
  font-size: 11px; font-weight: 700; cursor: pointer;
}
.add-btn:hover { background: rgba(0,212,255,0.2); }
`

function RTTMiniGraph({ data, targetId, color = 'var(--accent)' }) {
  if (!data || data.length < 2) {
    return (
      <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:'100%', color:'var(--text-muted)', fontSize:11 }}>
        Collecting data…
      </div>
    )
  }

  const W = 600, H = 90
  const maxRtt = Math.max(...data.map(d => d.rtt_ms).filter(r => r > 0), 50)
  const points = data.map((d, i) => {
    const x = (i / (data.length - 1)) * W
    const y = d.rtt_ms > 0 ? H - (d.rtt_ms / maxRtt) * H * 0.9 : H
    return `${x},${y}`
  }).join(' ')

  const areaPoints = `0,${H} ${points} ${W},${H}`

  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
      <defs>
        <linearGradient id={`grad-${targetId}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0.02" />
        </linearGradient>
      </defs>
      {/* Grid lines */}
      {[0.25, 0.5, 0.75].map(p => (
        <line key={p} x1={0} y1={H * p} x2={W} y2={H * p}
          stroke="rgba(255,255,255,0.04)" strokeWidth={1} />
      ))}
      {/* Area */}
      <polygon points={areaPoints} fill={`url(#grad-${targetId})`} />
      {/* Line */}
      <polyline points={points} fill="none" stroke={color} strokeWidth={2}
        strokeLinejoin="round" strokeLinecap="round" />
      {/* Loss markers */}
      {data.filter(d => d.loss_pct > 0).map((d, i) => {
        const xi = data.indexOf(d)
        const x = (xi / (data.length - 1)) * W
        return <line key={i} x1={x} y1={0} x2={x} y2={H}
          stroke="rgba(255,153,0,0.4)" strokeWidth={1} strokeDasharray="3,3" />
      })}
      {/* Max label */}
      <text x={W - 2} y={12} textAnchor="end" fontSize={9} fill="rgba(200,212,232,0.4)"
        fontFamily="JetBrains Mono, monospace">{maxRtt.toFixed(0)}ms</text>
    </svg>
  )
}

export default function MonitorView({ monitorStatus, onAddTarget, onRemoveTarget }) {
  const [events, setEvents] = useState([])
  const [rttData, setRttData] = useState({})
  const [activeTarget, setActiveTarget] = useState(null)
  const [newHost, setNewHost] = useState('')
  const [newLabel, setNewLabel] = useState('')
  const wsRef = useRef(null)

  useEffect(() => {
    // Load event history
    fetch('/api/monitor/events?limit=50').then(r => r.json()).then(setEvents).catch(() => {})

    // WebSocket for live updates
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const wsBase = window.CERNIS_WS_BASE || `${protocol}://${window.location.host}`
    const ws = new WebSocket(`${wsBase}/ws/monitor`)
    wsRef.current = ws

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data)
      if (msg.type === 'monitor_update') {
        setRttData(prev => {
          const arr = [...(prev[msg.target_id] || []), { rtt_ms: msg.rtt_ms, loss_pct: msg.loss_pct, ts: msg.ts }]
          return { ...prev, [msg.target_id]: arr.slice(-120) }
        })
        if (msg.event) {
          setEvents(prev => [{
            target_id: msg.target_id, label: msg.label,
            event: msg.event, rtt_ms: msg.rtt_ms,
            datetime: new Date().toLocaleTimeString('de-DE', { hour:'2-digit', minute:'2-digit', second:'2-digit' }),
          }, ...prev.slice(0, 99)])
        }
      }
    }

    // Load initial RTT history for all targets
    if (monitorStatus) {
      Object.keys(monitorStatus).forEach(tid => {
        fetch(`/api/monitor/rtt/${tid}?limit=120`).then(r => r.json()).then(data => {
          setRttData(prev => ({ ...prev, [tid]: data }))
        }).catch(() => {})
      })
    }

    return () => ws.close()
  }, [])

  // First target as default for graph
  useEffect(() => {
    if (!activeTarget && monitorStatus && Object.keys(monitorStatus).length > 0) {
      setActiveTarget(Object.keys(monitorStatus)[0])
    }
  }, [monitorStatus])

  const handleAddTarget = async () => {
    if (!newHost) return
    const id = `custom_${newHost.replace(/\./g, '_')}`
    await fetch('/api/monitor/targets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, label: newLabel || newHost, host: newHost, interface: '', enabled: true }),
    })
    setNewHost(''); setNewLabel('')
    if (onAddTarget) onAddTarget()
  }

  const rttClass = (rtt) => rtt < 5 ? 'fast' : rtt < 50 ? 'med' : rtt > 0 ? 'slow' : ''
  const graphColor = (tid) => {
    if (tid?.includes('internet')) return 'var(--purple)'
    if (tid?.includes('gw')) return 'var(--accent)'
    return 'var(--green)'
  }

  // Summarize: online/offline counts
  const targets = Object.entries(monitorStatus || {})
  const online  = targets.filter(([,v]) => v.alive === true).length
  const offline = targets.filter(([,v]) => v.alive === false).length
  const unknown = targets.filter(([,v]) => v.alive === null || v.alive === undefined).length

  return (
    <>
      <style>{css}</style>
      <div className="monitor-view">
        <div className="monitor-header">
          <Activity size={14} color="var(--accent)" />
          <span className="monitor-title">Live Connectivity Monitor</span>
          <span style={{ fontSize:11, color:'var(--text-muted)', fontFamily:'var(--font-mono)', marginLeft:'auto' }}>
            Interval: 5s · {Object.keys(monitorStatus || {}).length} targets
          </span>
        </div>

        <div className="monitor-body">
          {/* Status cards */}
          <div className="status-cards">
            {Object.entries(monitorStatus || {}).map(([tid, s]) => {
              const data = rttData[tid] || []
              const lastRtt = data[data.length - 1]?.rtt_ms || -1
              const status = s.alive === true ? 'up' : s.alive === false ? 'down' : 'unknown'
              return (
                <div key={tid} className={`status-card ${status}`}
                  style={{ cursor:'pointer', opacity: activeTarget === tid ? 1 : 0.8 }}
                  onClick={() => setActiveTarget(tid)}>
                  <div className="sc-top">
                    <div className={`sc-dot ${status}`} />
                    <span className="sc-label">{s.label || tid}</span>
                    <span className={`sc-status ${status}`}>{status.toUpperCase()}</span>
                  </div>
                  <div className={`sc-rtt ${rttClass(lastRtt)}`}>
                    {lastRtt > 0 ? `${lastRtt.toFixed(1)}ms` : '—'}
                  </div>
                  {data[data.length-1]?.loss_pct > 0 && (
                    <div className={`sc-loss${data[data.length-1].loss_pct > 20 ? ' bad' : ''}`}>
                      Loss: {data[data.length-1].loss_pct}%
                    </div>
                  )}
                </div>
              )
            })}
          </div>

          {/* RTT Graph */}
          <div className="rtt-graph-wrap">
            <div className="rtt-graph-header">
              <Activity size={11} /> RTT History
              <div className="rtt-graph-tabs">
                {Object.keys(monitorStatus || {}).map(tid => (
                  <button key={tid} className={`rtt-tab${activeTarget === tid ? ' active' : ''}`}
                    onClick={() => setActiveTarget(tid)}>
                    {(monitorStatus[tid]?.label || tid).substring(0,10)}
                  </button>
                ))}
              </div>
            </div>
            <div className="rtt-graph-canvas">
              {activeTarget && (
                <RTTMiniGraph
                  data={rttData[activeTarget] || []}
                  targetId={activeTarget}
                  color={graphColor(activeTarget)}
                />
              )}
            </div>
          </div>

          {/* Event Log */}
          <div className="event-log-wrap">
            <div className="event-log-header">
              <Server size={11} /> Event Log
              <span style={{ marginLeft:'auto', fontSize:10 }}>{events.length} events</span>
            </div>
            <div className="event-log-body">
              {events.length === 0 && (
                <div style={{ padding:'20px', textAlign:'center', color:'var(--text-muted)', fontSize:12 }}>
                  No events yet — monitoring active…
                </div>
              )}
              {events.map((evt, i) => (
                <div key={i} className="event-row">
                  <span className="event-time">{evt.datetime}</span>
                  <span className="event-label">{evt.label}</span>
                  <span className={`event-msg ${evt.event}`}>
                    {evt.event === 'up'       && '✓ Back ONLINE'}
                    {evt.event === 'down'     && '✗ OFFLINE'}
                    {evt.event === 'degraded' && '⚠ DEGRADED'}
                  </span>
                  <span className="event-rtt">
                    {evt.rtt_ms > 0 ? `${evt.rtt_ms}ms` : '—'}
                  </span>
                </div>
              ))}
            </div>
            {/* Add custom target */}
            <div className="add-target-row">
              <input className="add-target-input" value={newLabel}
                onChange={e => setNewLabel(e.target.value)}
                placeholder="Label (e.g. NAS)" style={{ maxWidth: 120 }} />
              <input className="add-target-input" value={newHost}
                onChange={e => setNewHost(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleAddTarget()}
                placeholder="IP / Host to monitor" />
              <button className="add-btn" onClick={handleAddTarget}>
                <Plus size={12} /> Add
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}
