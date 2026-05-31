import React, { useEffect, useRef, useState, useCallback } from 'react'
import { X, ZoomIn, ZoomOut, Maximize2 } from 'lucide-react'

const css = `
.topo-overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,0.85);
  z-index: 700; display: flex; flex-direction: column;
}
.topo-header {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 18px; border-bottom: 1px solid var(--border);
  background: var(--bg-1); flex-shrink: 0;
}
.topo-title { font-size: 14px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); flex: 1; }
.topo-close { background: none; color: var(--text-muted); padding: 4px; border-radius: 4px; display: flex; cursor: pointer; }
.topo-close:hover { background: var(--bg-4); color: var(--text-primary); }
.topo-toolbar {
  display: flex; align-items: center; gap: 6px;
  padding: 8px 14px; border-bottom: 1px solid var(--border);
  background: var(--bg-2); flex-shrink: 0;
}
.topo-btn {
  display: flex; align-items: center; gap: 4px;
  background: var(--bg-3); border: 1px solid var(--border);
  color: var(--text-secondary); padding: 5px 10px; border-radius: 4px;
  font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em;
  cursor: pointer; transition: all 0.12s;
}
.topo-btn:hover { border-color: var(--border-bright); color: var(--text-primary); }
.topo-legend { display: flex; align-items: center; gap: 14px; margin-left: auto; font-size: 10px; color: var(--text-muted); }
.topo-legend-item { display: flex; align-items: center; gap: 5px; }
.topo-legend-dot { width: 10px; height: 10px; border-radius: 50%; }
.topo-canvas { flex: 1; position: relative; overflow: hidden; cursor: grab; }
.topo-canvas:active { cursor: grabbing; }
.topo-canvas svg { width: 100%; height: 100%; }

/* Node tooltip */
.topo-tooltip {
  position: absolute; pointer-events: none; z-index: 10;
  background: var(--bg-2); border: 1px solid var(--border-bright);
  border-radius: 5px; padding: 8px 12px;
  font-size: 11px; font-family: var(--font-mono);
  box-shadow: 0 4px 20px rgba(0,0,0,0.6);
  min-width: 160px;
}
.topo-tooltip-ip   { color: var(--accent); font-weight: 600; margin-bottom: 3px; }
.topo-tooltip-row  { color: var(--text-secondary); line-height: 1.6; }
.topo-tooltip-row span { color: var(--text-muted); margin-right: 4px; }

.topo-icon-btn {
  background: var(--bg-3); border: 1px solid var(--border); color: var(--text-secondary);
  width: 30px; height: 30px; border-radius: 4px; display: flex; align-items: center; justify-content: center;
  cursor: pointer; transition: all 0.12s;
}
.topo-icon-btn:hover { border-color: var(--border-bright); color: var(--text-primary); }
`

// Simple force-directed layout
function useForceLayout(nodes, edges, width, height) {
  const [positions, setPositions] = useState({})
  const animRef = useRef(null)

  useEffect(() => {
    if (!nodes.length || !width || !height) return
    if (animRef.current) cancelAnimationFrame(animRef.current)

    // Init positions
    const pos = {}
    nodes.forEach((n, i) => {
      if (n.isGateway) {
        pos[n.id] = { x: width / 2, y: height / 2, vx: 0, vy: 0 }
      } else {
        const angle = (i / nodes.length) * Math.PI * 2
        const r = Math.min(width, height) * 0.35
        pos[n.id] = {
          x: width / 2 + Math.cos(angle) * r * (0.6 + Math.random() * 0.4),
          y: height / 2 + Math.sin(angle) * r * (0.6 + Math.random() * 0.4),
          vx: 0, vy: 0,
        }
      }
    })

    let iter = 0
    const tick = () => {
      if (iter > 200) { setPositions({ ...pos }); return }
      iter++

      // Repulsion
      nodes.forEach(a => {
        nodes.forEach(b => {
          if (a.id === b.id) return
          const dx = pos[a.id].x - pos[b.id].x
          const dy = pos[a.id].y - pos[b.id].y
          const dist = Math.sqrt(dx*dx + dy*dy) || 1
          const force = 3000 / (dist * dist)
          pos[a.id].vx += (dx / dist) * force
          pos[a.id].vy += (dy / dist) * force
        })
      })

      // Attraction (edges)
      edges.forEach(e => {
        const a = pos[e.source], b = pos[e.target]
        if (!a || !b) return
        const dx = b.x - a.x, dy = b.y - a.y
        const dist = Math.sqrt(dx*dx + dy*dy) || 1
        const force = (dist - 120) * 0.04
        a.vx += (dx / dist) * force; a.vy += (dy / dist) * force
        b.vx -= (dx / dist) * force; b.vy -= (dy / dist) * force
      })

      // Center gravity
      nodes.forEach(n => {
        pos[n.id].vx += (width/2 - pos[n.id].x) * 0.003
        pos[n.id].vy += (height/2 - pos[n.id].y) * 0.003
      })

      // Integrate + dampen
      nodes.forEach(n => {
        if (n.isGateway) return
        pos[n.id].vx *= 0.85; pos[n.id].vy *= 0.85
        pos[n.id].x  = Math.max(40, Math.min(width-40, pos[n.id].x + pos[n.id].vx))
        pos[n.id].y  = Math.max(40, Math.min(height-40, pos[n.id].y + pos[n.id].vy))
      })

      if (iter % 10 === 0) setPositions({ ...pos })
      animRef.current = requestAnimationFrame(tick)
    }
    animRef.current = requestAnimationFrame(tick)
    return () => { if (animRef.current) cancelAnimationFrame(animRef.current) }
  }, [nodes.length, width, height])

  return positions
}

function nodeColor(host) {
  if (host.isGateway) return '#00d4ff'
  if (host.is_ndi)   return '#ff6b35'
  if (host.is_unknown) return '#ff9900'
  const ports = host.ports || []
  if (ports.some(p => [80,443,8080,8443].includes(p.port))) return '#bb86fc'
  if (ports.some(p => [22].includes(p.port))) return '#00e676'
  return '#4a6a99'
}

export default function TopologyView({ hosts, gateway, onClose }) {
  const [lldpNeighbors, setLldpNeighbors] = React.useState([])

  React.useEffect(() => {
    fetch('/api/lldp/neighbors').then(r=>r.json()).then(data => {
      if (Array.isArray(data) && data.length > 0) setLldpNeighbors(data)
    }).catch(()=>{})
  }, [])
  const canvasRef = useRef(null)
  const [size, setSize] = useState({ w: 0, h: 0 })
  const [tooltip, setTooltip] = useState(null)
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const panStart = useRef(null)

  useEffect(() => {
    const el = canvasRef.current
    if (!el) return
    const ro = new ResizeObserver(entries => {
      const { width, height } = entries[0].contentRect
      setSize({ w: width, h: height })
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  const nodes = [
    ...(gateway ? [{ id: gateway, label: gateway, isGateway: true, vendor: 'Gateway/Router', ports: [] }] : []),
    ...hosts.map(h => ({ ...h, id: h.ip, label: h.hostname || h.ip })),
  ]
  const gatewayId = gateway
  const edges = hosts.map(h => ({ source: gatewayId || hosts[0]?.ip, target: h.ip })).filter(e => e.source && e.target && e.source !== e.target)

  const positions = useForceLayout(nodes, edges, size.w, size.h)

  const handleMouseMove = (e) => {
    if (panStart.current) {
      const dx = e.clientX - panStart.current.x
      const dy = e.clientY - panStart.current.y
      setPan({ x: panStart.current.panX + dx, y: panStart.current.panY + dy })
    }
  }
  const handleMouseDown = (e) => {
    panStart.current = { x: e.clientX, y: e.clientY, panX: pan.x, panY: pan.y }
  }
  const handleMouseUp = () => { panStart.current = null }

  const handleWheel = (e) => {
    e.preventDefault()
    setZoom(z => Math.max(0.3, Math.min(3, z - e.deltaY * 0.001)))
  }

  return (
    <>
      <style>{css}</style>
      <div className="topo-overlay">
        <div className="topo-header">
          <span className="topo-title">⬡ Network Topology — {hosts.length} hosts</span>
          <button className="topo-close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="topo-toolbar">
          <button className="topo-icon-btn" onClick={() => setZoom(z => Math.min(3, z+0.2))}><ZoomIn size={14} /></button>
          <button className="topo-icon-btn" onClick={() => setZoom(z => Math.max(0.3, z-0.2))}><ZoomOut size={14} /></button>
          <button className="topo-icon-btn" onClick={() => { setZoom(1); setPan({x:0,y:0}) }}><Maximize2 size={14} /></button>
          <span style={{ fontSize:11, color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>
            {Math.round(zoom*100)}% · drag to pan · scroll to zoom
          </span>
          <div className="topo-legend">
            {[['Gateway','#00d4ff'],['Web Server','#bb86fc'],['SSH','#00e676'],['NDI','#ff6b35'],['Unknown','#ff9900'],['Other','#4a6a99']].map(([l,c])=>(
              <div key={l} className="topo-legend-item">
                <div className="topo-legend-dot" style={{ background: c }} />
                <span>{l}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="topo-canvas" ref={canvasRef}
          onMouseDown={handleMouseDown} onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp} onMouseLeave={handleMouseUp}
          onWheel={handleWheel}>
          <svg>
            <defs>
              <radialGradient id="bg-grad">
                <stop offset="0%" stopColor="#0f1520" />
                <stop offset="100%" stopColor="#080c12" />
              </radialGradient>
            </defs>
            <rect width="100%" height="100%" fill="url(#bg-grad)" />

            <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
              {/* Edges */}
              {edges.map((e, i) => {
                const a = positions[e.source], b = positions[e.target]
                if (!a || !b) return null
                return (
                  <line key={i}
                    x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                    stroke="rgba(0,212,255,0.12)" strokeWidth={1} />
                )
              })}

              {/* Nodes */}
              {nodes.map(node => {
                const pos = positions[node.id]
                if (!pos) return null
                const color = nodeColor(node)
                const r = node.isGateway ? 22 : 14
                const host = hosts.find(h => h.ip === node.id) || node
                return (
                  <g key={node.id} style={{ cursor: 'pointer' }}
                    onMouseEnter={e => {
                      const rect = canvasRef.current.getBoundingClientRect()
                      setTooltip({ host, x: e.clientX - rect.left, y: e.clientY - rect.top })
                    }}
                    onMouseLeave={() => setTooltip(null)}>
                    {/* Glow */}
                    <circle cx={pos.x} cy={pos.y} r={r + 8}
                      fill={color} opacity={0.06} />
                    {/* Ring */}
                    <circle cx={pos.x} cy={pos.y} r={r + 3}
                      fill="none" stroke={color} strokeWidth={1} opacity={0.3} />
                    {/* Node */}
                    <circle cx={pos.x} cy={pos.y} r={r}
                      fill={`${color}22`} stroke={color} strokeWidth={node.isGateway ? 2 : 1.5} />
                    {/* Label */}
                    <text x={pos.x} y={pos.y + r + 14}
                      textAnchor="middle" fontSize={9}
                      fill="rgba(200,212,232,0.7)"
                      fontFamily="JetBrains Mono, monospace">
                      {node.label.length > 20 ? node.label.substring(0,18)+'…' : node.label}
                    </text>
                    {/* Port count badge */}
                    {(host.ports?.length > 0) && (
                      <text x={pos.x} y={pos.y + 4} textAnchor="middle"
                        fontSize={node.isGateway ? 10 : 8} fill={color}
                        fontFamily="JetBrains Mono, monospace" fontWeight="700">
                        {host.ports.length}p
                      </text>
                    )}
                    {node.isGateway && (
                      <text x={pos.x} y={pos.y + 5} textAnchor="middle"
                        fontSize={10} fill={color} fontFamily="JetBrains Mono, monospace" fontWeight="700">
                        GW
                      </text>
                    )}
                  </g>
                )
              })}
            </g>
          </svg>

          {/* Tooltip */}
          {tooltip && (
            <div className="topo-tooltip" style={{
              left: Math.min(tooltip.x + 12, (size.w || 800) - 200),
              top: Math.min(tooltip.y + 12, (size.h || 600) - 140),
            }}>
              <div className="topo-tooltip-ip">{tooltip.host.ip}</div>
              {tooltip.host.hostname && <div className="topo-tooltip-row"><span>host</span>{tooltip.host.hostname}</div>}
              {tooltip.host.vendor   && <div className="topo-tooltip-row"><span>vendor</span>{tooltip.host.vendor}</div>}
              {tooltip.host.mac      && <div className="topo-tooltip-row"><span>mac</span>{tooltip.host.mac}</div>}
              {tooltip.host.ports?.length > 0 && (
                <div className="topo-tooltip-row">
                  <span>ports</span>{tooltip.host.ports.slice(0,6).map(p=>p.port).join(', ')}
                  {tooltip.host.ports.length > 6 && ` +${tooltip.host.ports.length-6}`}
                </div>
              )}
              {tooltip.host.os_guess && <div className="topo-tooltip-row"><span>os</span>{tooltip.host.os_guess.substring(0,30)}</div>}
              {tooltip.host.rtt_ms > 0 && <div className="topo-tooltip-row"><span>rtt</span>{tooltip.host.rtt_ms.toFixed(1)} ms</div>}
              {tooltip.host.is_ndi && <div className="topo-tooltip-row" style={{color:'var(--ndi)'}}>● NDI Device</div>}
              {tooltip.host.is_unknown && <div className="topo-tooltip-row" style={{color:'var(--orange)'}}>⚠ Unknown Device</div>}
            </div>
          )}
        </div>
      </div>
    </>
  )
}
