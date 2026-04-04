import React, { useState, useMemo } from 'react'
import { ChevronUp, ChevronDown, ChevronsUpDown } from 'lucide-react'
import { ALL_COLUMNS } from './ColumnManager.jsx'

const css = `
.host-table-wrap { flex: 1; overflow: auto; position: relative; }
.host-table { width: 100%; border-collapse: collapse; font-size: 12px; table-layout: fixed; }
.host-table thead { position: sticky; top: 0; z-index: 10; }
.host-table th {
  background: var(--bg-2);
  border-bottom: 2px solid var(--border); border-right: 1px solid var(--border);
  padding: 0 10px; height: 30px; text-align: left;
  font-size: 9px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase;
  color: var(--text-muted); white-space: nowrap; cursor: pointer; user-select: none;
  overflow: hidden; text-overflow: ellipsis; transition: color 0.15s, background 0.15s;
}
.host-table th:last-child { border-right: none; }
.host-table th:hover { color: var(--text-primary); background: var(--bg-3); }
.host-table th.sorted { color: var(--accent); }
.th-inner { display: flex; align-items: center; gap: 4px; }
.host-table tbody tr {
  border-bottom: 1px solid var(--border); cursor: pointer; transition: background 0.08s;
  animation: fade-in-row 0.18s ease forwards;
}
.host-table tbody tr:hover { background: var(--bg-3); }
.host-table tbody tr.selected { background: rgba(0,212,255,0.07); }
.host-table tbody tr.unknown-device { border-left: 2px solid var(--orange); }
.host-table td {
  padding: 0 10px; height: var(--row-h);
  border-right: 1px solid var(--border);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  color: var(--text-secondary); vertical-align: middle;
}
.host-table td:last-child { border-right: none; }
.cell-ip   { font-family: var(--font-mono); font-size: 12px; color: var(--text-primary) !important; font-weight: 500; }
.cell-mac  { font-family: var(--font-mono); font-size: 10px; color: var(--text-muted) !important; }
.cell-host { font-size: 11px; color: var(--accent) !important; }
.cell-label{ font-size: 11px; color: var(--yellow) !important; font-style: italic; }
.cell-rtt  { font-family: var(--font-mono); font-size: 11px; }
.cell-rtt.fast { color: var(--green) !important; }
.cell-rtt.med  { color: var(--yellow) !important; }
.cell-rtt.slow { color: var(--orange) !important; }
.chips { display: flex; flex-wrap: wrap; gap: 2px; align-items: center; overflow: hidden; }
.chip { font-size: 10px; padding: 1px 5px; border-radius: 2px; white-space: nowrap; }
.chip-port { background: rgba(0,212,255,0.08); color: var(--accent); border: 1px solid rgba(0,212,255,0.2); font-family: var(--font-mono); padding: 1px 4px; }
.chip-mdns { background: rgba(187,134,252,0.1); color: var(--purple); border: 1px solid rgba(187,134,252,0.2); }
.chip-ndi  { background: rgba(255,107,53,0.15); color: var(--ndi); border: 1px solid rgba(255,107,53,0.3); font-weight:700; }
.chip-ssdp { background: rgba(0,230,118,0.1); color: var(--green); border: 1px solid rgba(0,230,118,0.2); }
.chip-tag  { background: rgba(255,224,51,0.1); color: var(--yellow); border: 1px solid rgba(255,224,51,0.2); border-radius: 10px; }
.chip-more { font-size: 10px; color: var(--text-muted); }
.unknown-badge {
  font-size: 9px; padding: 1px 5px; border-radius: 2px;
  background: rgba(255,153,0,0.15); color: var(--orange);
  border: 1px solid rgba(255,153,0,0.3); font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.05em;
}
.table-empty {
  position: absolute; inset: 0; display: flex; flex-direction: column;
  align-items: center; justify-content: center; gap: 10px;
  color: var(--text-muted); font-size: 13px; pointer-events: none;
}
`

function SortIcon({ dir }) {
  if (dir === 'asc') return <ChevronUp size={10} />
  if (dir === 'desc') return <ChevronDown size={10} />
  return <ChevronsUpDown size={10} style={{ opacity: 0.3 }} />
}

function Cell({ col, host }) {
  const muted = <span style={{ color: 'var(--text-muted)' }}>—</span>
  switch (col.id) {
    case 'ping':
      return (
        <div style={{ display:'flex', alignItems:'center', gap:4 }}>
          <span className="ping-dot alive" />
          {host.is_unknown && <span className="unknown-badge">NEW</span>}
        </div>
      )
    case 'ipv4':     return <span className="cell-ip">{host.ip}</span>
    case 'ipv6':     return <span style={{ fontSize:10, fontFamily:'var(--font-mono)', color:'var(--text-muted)' }}>{host.ipv6 || host.ipv6_global || '—'}</span>
    case 'mac':      return <span className="cell-mac">{host.mac || '—'}</span>
    case 'vendor':   return <span style={{ fontSize:11 }}>{host.vendor || '—'}</span>
    case 'hostname': return <span className="cell-host">{host.hostname || '—'}</span>
    case 'label':    return <span className="cell-label">{host.label || '—'}</span>
    case 'smb':      return <span style={{ fontSize:11, fontFamily:'var(--font-mono)' }}>{host.smb_name || '—'}</span>
    case 'os':       return <span style={{ fontSize:11 }}>{host.os_guess || '—'}</span>
    case 'rtt': {
      const r = host.rtt_ms
      if (!r || r <= 0) return muted
      const cls = r < 5 ? 'fast' : r < 50 ? 'med' : 'slow'
      const label = r < 1 ? '<1' : r.toFixed(1)
      return <span className={`cell-rtt ${cls}`}>{label}</span>
    }
    case 'ports': {
      const p = host.ports
      if (!p || p.length === 0) return muted
      return (
        <div className="chips">
          {p.slice(0,5).map(x => <span key={x.port} className="chip chip-port" title={x.service}>{x.port}</span>)}
          {p.length > 5 && <span className="chip-more">+{p.length-5}</span>}
        </div>
      )
    }
    case 'mdns': {
      const s = host.mdns_services || []
      if (s.length === 0 && !host.is_ndi) return muted
      return (
        <div className="chips">
          {host.is_ndi && <span className="chip chip-ndi">NDI</span>}
          {s.filter(x=>!x.is_ndi).slice(0,2).map((x,i) =>
            <span key={i} className="chip chip-mdns" title={x.type}>{x.type.split('._')[0].replace('_','')}</span>)}
          {s.length > 3 && <span className="chip-more">+{s.length-3}</span>}
        </div>
      )
    }
    case 'ssdp': {
      const s = host.ssdp_services || []
      if (s.length === 0) return muted
      return (
        <div className="chips">
          {s.slice(0,2).map((x,i) =>
            <span key={i} className="chip chip-ssdp" title={x.st}>{x.server?.split('/')[0]?.substring(0,12)||'UPnP'}</span>)}
          {s.length > 2 && <span className="chip-more">+{s.length-2}</span>}
        </div>
      )
    }
    case 'tags': {
      const t = host.tags || []
      if (t.length === 0) return muted
      return (
        <div className="chips">
          {t.slice(0,3).map((x,i) => <span key={i} className="chip chip-tag">{x}</span>)}
          {t.length > 3 && <span className="chip-more">+{t.length-3}</span>}
        </div>
      )
    }
    default: return muted
  }
}

export default function HostTable({ hosts, selectedIp, onSelect, columnOrder, columnVisible }) {
  const [sortCol, setSortCol] = useState('ipv4')
  const [sortDir, setSortDir] = useState('asc')

  const visibleSet = new Set(columnVisible)
  const cols = (columnOrder || [])
    .map(id => ALL_COLUMNS.find(c => c.id === id))
    .filter(c => c && visibleSet.has(c.id))

  const handleSort = (id) => {
    if (sortCol === id) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortCol(id); setSortDir('asc') }
  }

  const sorted = useMemo(() => {
    return [...hosts].sort((a, b) => {
      let va, vb
      switch (sortCol) {
        case 'ipv4':     va = a.ip?.split('.').map(Number).reduce((acc,n)=>acc*256+n,0)||0; vb = b.ip?.split('.').map(Number).reduce((acc,n)=>acc*256+n,0)||0; break
        case 'vendor':   va = a.vendor   || ''; vb = b.vendor   || ''; break
        case 'hostname': va = a.hostname || ''; vb = b.hostname || ''; break
        case 'label':    va = a.label    || ''; vb = b.label    || ''; break
        case 'rtt':      va = a.rtt_ms   || 9999; vb = b.rtt_ms || 9999; break
        case 'ports':    va = a.ports?.length || 0; vb = b.ports?.length || 0; break
        default:         va = ''; vb = ''
      }
      if (typeof va === 'number') return sortDir === 'asc' ? va-vb : vb-va
      return sortDir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va)
    })
  }, [hosts, sortCol, sortDir])

  return (
    <>
      <style>{css}</style>
      <div className="host-table-wrap">
        {hosts.length === 0 && (
          <div className="table-empty">
            <div style={{ fontSize:40, opacity:0.1 }}>⬡</div>
            <span>No hosts found — start a scan</span>
          </div>
        )}
        <table className="host-table">
          <thead>
            <tr>
              {cols.map(col => (
                <th key={col.id} className={sortCol===col.id?'sorted':''} style={{ width: col.width }} onClick={() => handleSort(col.id)}>
                  <div className="th-inner">{col.label}<SortIcon dir={sortCol===col.id?sortDir:null}/></div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map(host => (
              <tr key={host.ip}
                className={[selectedIp===host.ip?'selected':'', host.is_unknown?'unknown-device':''].join(' ')}
                onClick={() => onSelect(host)}>
                {cols.map(col => (
                  <td key={col.id} style={{ width: col.width }}><Cell col={col} host={host} /></td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}
