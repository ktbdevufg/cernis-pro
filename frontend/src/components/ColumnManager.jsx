import React, { useState, useRef } from 'react'
import { Columns, X, GripVertical, Eye, EyeOff, RotateCcw } from 'lucide-react'

const css = `
.col-mgr-btn {
  display: flex; align-items: center; gap: 5px;
  background: var(--bg-3);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  padding: 6px 12px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  transition: all 0.15s;
}
.col-mgr-btn:hover { border-color: var(--border-bright); color: var(--text-primary); }
.col-mgr-btn.has-hidden { border-color: var(--accent-dim); color: var(--accent); }

.col-mgr-overlay {
  position: fixed; inset: 0;
  background: rgba(0,0,0,0.55);
  z-index: 600;
  display: flex; align-items: flex-start; justify-content: center;
  padding-top: 80px;
}
.col-mgr-panel {
  background: var(--bg-2);
  border: 1px solid var(--border-bright);
  border-radius: 8px;
  width: 360px;
  box-shadow: 0 24px 64px rgba(0,0,0,0.7);
  overflow: hidden;
}
.col-mgr-header {
  display: flex; align-items: center; gap: 8px;
  padding: 14px 18px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-3);
}
.col-mgr-title {
  font-size: 13px; font-weight: 700;
  letter-spacing: 0.1em; text-transform: uppercase;
  color: var(--text-primary); flex: 1;
}
.col-mgr-close {
  background: none; color: var(--text-muted); padding: 3px; border-radius: 3px;
  display: flex; cursor: pointer;
}
.col-mgr-close:hover { background: var(--bg-4); color: var(--text-primary); }

.col-mgr-sub {
  font-size: 10px; color: var(--text-muted);
  padding: 8px 18px;
  border-bottom: 1px solid var(--border);
  font-family: var(--font-mono);
}

.col-list { padding: 8px; display: flex; flex-direction: column; gap: 2px; }

.col-item {
  display: flex; align-items: center; gap: 8px;
  padding: 8px 10px;
  border-radius: 5px;
  border: 1px solid transparent;
  cursor: default;
  transition: background 0.1s, border-color 0.1s;
  user-select: none;
}
.col-item:hover { background: var(--bg-3); border-color: var(--border); }
.col-item.dragging {
  background: var(--bg-4); border-color: var(--accent-dim);
  opacity: 0.8; cursor: grabbing;
}
.col-item.drag-over { border-color: var(--accent); background: rgba(0,212,255,0.06); }

.col-grip {
  color: var(--text-muted); cursor: grab; flex-shrink: 0;
  display: flex; align-items: center;
}
.col-grip:active { cursor: grabbing; }

.col-item-label {
  flex: 1;
  font-size: 13px;
  color: var(--text-primary);
}
.col-item-label.hidden { color: var(--text-muted); text-decoration: line-through; }

.col-item-desc {
  font-size: 10px; color: var(--text-muted);
  font-family: var(--font-mono);
}

.col-vis-btn {
  display: flex; align-items: center; justify-content: center;
  width: 28px; height: 28px;
  border-radius: 4px;
  background: none;
  border: 1px solid var(--border);
  color: var(--text-muted);
  cursor: pointer;
  transition: all 0.1s;
  flex-shrink: 0;
}
.col-vis-btn:hover { border-color: var(--border-bright); color: var(--text-primary); }
.col-vis-btn.visible { border-color: var(--accent-dim); color: var(--accent); background: rgba(0,212,255,0.08); }

.col-mgr-footer {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 16px;
  border-top: 1px solid var(--border);
  background: var(--bg-1);
}
.col-mgr-count { font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); }
.col-mgr-count span { color: var(--accent); }
.btn-reset {
  display: flex; align-items: center; gap: 4px;
  background: none; border: 1px solid var(--border);
  color: var(--text-muted); padding: 4px 10px;
  border-radius: 4px; font-size: 11px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.06em;
  cursor: pointer; transition: all 0.1s;
}
.btn-reset:hover { border-color: var(--border-bright); color: var(--text-secondary); }
`

export const ALL_COLUMNS = [
  { id: 'ping',     label: 'Status',      desc: 'Online/offline indicator',    width: 36  },
  { id: 'ipv4',     label: 'IPv4',        desc: 'IPv4 address',                width: 130 },
  { id: 'ipv6',     label: 'IPv6',        desc: 'IPv6 address',                width: 160 },
  { id: 'mac',      label: 'MAC',         desc: 'Hardware address',            width: 144 },
  { id: 'vendor',   label: 'Vendor',      desc: 'NIC manufacturer (OUI)',      width: 180 },
  { id: 'hostname', label: 'Hostname',    desc: 'Reverse DNS / mDNS name',     width: 180 },
  { id: 'label',    label: 'Label',       desc: 'Custom device label',         width: 130 },
  { id: 'tags',     label: 'Tags',        desc: 'Custom tags',                 width: 130 },
  { id: 'ports',    label: 'TCP Ports',   desc: 'Open ports found',            width: 200 },
  { id: 'mdns',     label: 'mDNS / NDI',  desc: 'Bonjour & NDI services',      width: 160 },
  { id: 'ssdp',     label: 'UPnP/SSDP',  desc: 'SSDP/UPnP services',         width: 140 },
  { id: 'os',       label: 'OS Guess',    desc: 'OS fingerprint (nmap)',       width: 180 },
  { id: 'smb',      label: 'SMB Name',    desc: 'NetBIOS/SMB name',           width: 130 },
  { id: 'rtt',      label: 'Ping ms',     desc: 'Round-trip time',             width: 80  },
]

export const DEFAULT_VISIBLE = ['ping','ipv4','ipv6','mac','vendor','hostname','ports','mdns','os','rtt']
export const DEFAULT_ORDER   = ALL_COLUMNS.map(c => c.id)

export default function ColumnManager({ order, visible, onChange }) {
  const [open, setOpen] = useState(false)
  const [localOrder, setLocalOrder] = useState(order)
  const [localVisible, setLocalVisible] = useState(new Set(visible))
  const dragIdx = useRef(null)
  const [dragOver, setDragOver] = useState(null)

  const hiddenCount = ALL_COLUMNS.length - localVisible.size

  const openPanel = () => {
    setLocalOrder(order)
    setLocalVisible(new Set(visible))
    setOpen(true)
  }

  const toggleVis = (id) => {
    setLocalVisible(prev => {
      const next = new Set(prev)
      if (next.has(id)) { if (next.size > 1) next.delete(id) }
      else next.add(id)
      // Persist immediately
      const newVis = Array.from(next)
      onChange(localOrder, newVis)
      return next
    })
  }

  // Drag handlers
  const onDragStart = (e, idx) => {
    dragIdx.current = idx
    e.dataTransfer.effectAllowed = 'move'
  }
  const onDragOver = (e, idx) => {
    e.preventDefault()
    setDragOver(idx)
  }
  const onDrop = (e, idx) => {
    e.preventDefault()
    if (dragIdx.current === null || dragIdx.current === idx) return
    const next = [...localOrder]
    const [moved] = next.splice(dragIdx.current, 1)
    next.splice(idx, 0, moved)
    setLocalOrder(next)
    dragIdx.current = null
    setDragOver(null)
    onChange(next, Array.from(localVisible))
  }
  const onDragEnd = () => { dragIdx.current = null; setDragOver(null) }

  const reset = () => {
    setLocalOrder(DEFAULT_ORDER)
    setLocalVisible(new Set(DEFAULT_VISIBLE))
    onChange(DEFAULT_ORDER, DEFAULT_VISIBLE)
  }

  const orderedCols = localOrder
    .map(id => ALL_COLUMNS.find(c => c.id === id))
    .filter(Boolean)

  return (
    <>
      <style>{css}</style>
      <button
        className={`col-mgr-btn${hiddenCount > 0 ? ' has-hidden' : ''}`}
        onClick={openPanel}
      >
        <Columns size={13} />
        Columns
        {hiddenCount > 0 && <span style={{ color: 'var(--accent)', marginLeft: 2 }}>({ALL_COLUMNS.length - hiddenCount}/{ALL_COLUMNS.length})</span>}
      </button>

      {open && (
        <div className="col-mgr-overlay" onClick={e => e.target === e.currentTarget && setOpen(false)}>
          <div className="col-mgr-panel">
            <div className="col-mgr-header">
              <Columns size={14} color="var(--accent)" />
              <span className="col-mgr-title">Column Manager</span>
              <button className="col-mgr-close" onClick={() => setOpen(false)}><X size={15} /></button>
            </div>
            <div className="col-mgr-sub">
              Drag to reorder · Click eye to show/hide · Changes save automatically
            </div>

            <div className="col-list">
              {orderedCols.map((col, idx) => (
                <div
                  key={col.id}
                  className={`col-item${dragOver === idx ? ' drag-over' : ''}`}
                  draggable
                  onDragStart={e => onDragStart(e, idx)}
                  onDragOver={e => onDragOver(e, idx)}
                  onDrop={e => onDrop(e, idx)}
                  onDragEnd={onDragEnd}
                >
                  <span className="col-grip"><GripVertical size={14} /></span>
                  <span className={`col-item-label${!localVisible.has(col.id) ? ' hidden' : ''}`}>
                    {col.label}
                  </span>
                  <span className="col-item-desc">{col.desc}</span>
                  <button
                    className={`col-vis-btn${localVisible.has(col.id) ? ' visible' : ''}`}
                    onClick={() => toggleVis(col.id)}
                    title={localVisible.has(col.id) ? 'Hide column' : 'Show column'}
                  >
                    {localVisible.has(col.id) ? <Eye size={13} /> : <EyeOff size={13} />}
                  </button>
                </div>
              ))}
            </div>

            <div className="col-mgr-footer">
              <span className="col-mgr-count">
                <span>{localVisible.size}</span> / {ALL_COLUMNS.length} visible
              </span>
              <button className="btn-reset" onClick={reset}>
                <RotateCcw size={11} /> Reset
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
