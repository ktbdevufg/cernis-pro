import React, { useState, useEffect } from 'react'
import { Shield, AlertTriangle, CheckCircle, RefreshCw, Trash2, Eye } from 'lucide-react'

const css = `
.security-view { position: absolute; inset: 0; display: flex; flex-direction: column; }
.sec-header {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 20px; border-bottom: 1px solid var(--border);
  background: var(--bg-1); flex-shrink: 0;
}
.sec-title { font-size: 13px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); }
.sec-body { flex: 1; overflow-y: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 16px; }

.sec-summary-cards { display: flex; gap: 10px; }
.sec-card {
  flex: 1; background: var(--bg-2); border: 1px solid var(--border);
  border-radius: 6px; padding: 14px 16px;
  display: flex; flex-direction: column; gap: 4px;
}
.sec-card.alert  { border-color: rgba(255,61,61,0.4); background: rgba(255,61,61,0.04); }
.sec-card.warn   { border-color: rgba(255,153,0,0.3); background: rgba(255,153,0,0.04); }
.sec-card.clean  { border-color: rgba(0,230,118,0.3); background: rgba(0,230,118,0.04); }
.sec-card-num    { font-size: 28px; font-weight: 700; font-family: var(--font-mono); }
.sec-card.alert  .sec-card-num { color: var(--red); }
.sec-card.warn   .sec-card-num { color: var(--orange); }
.sec-card.clean  .sec-card-num { color: var(--green); }
.sec-card-label  { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-muted); }

.sec-section-title {
  font-size: 10px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--text-muted); margin-bottom: 8px; display: flex; align-items: center; gap: 6px;
}

.scan-btn-arp {
  display: flex; align-items: center; gap: 6px;
  background: var(--accent); color: var(--bg-0);
  padding: 7px 16px; border-radius: 4px; font-size: 12px; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.08em; cursor: pointer;
  transition: all 0.15s; border: none;
}
.scan-btn-arp:hover { background: #33ddff; }
.scan-btn-arp:disabled { opacity: 0.5; cursor: not-allowed; }

/* Alert list */
.alert-list { display: flex; flex-direction: column; gap: 6px; }
.alert-item {
  display: flex; gap: 12px; align-items: flex-start;
  padding: 10px 14px; border-radius: 5px; border: 1px solid transparent;
}
.alert-item.high   { background: rgba(255,61,61,0.07); border-color: rgba(255,61,61,0.3); }
.alert-item.medium { background: rgba(255,153,0,0.07); border-color: rgba(255,153,0,0.25); }
.alert-item.low    { background: rgba(255,224,51,0.05); border-color: rgba(255,224,51,0.2); }
.alert-icon { flex-shrink: 0; margin-top: 2px; }
.alert-icon.high   { color: var(--red); }
.alert-icon.medium { color: var(--orange); }
.alert-icon.low    { color: var(--yellow); }
.alert-body { flex: 1; }
.alert-type  { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); margin-bottom: 3px; }
.alert-msg   { font-size: 12px; color: var(--text-primary); font-family: var(--font-mono); line-height: 1.5; }
.alert-meta  { font-size: 10px; color: var(--text-muted); margin-top: 3px; font-family: var(--font-mono); }
.alert-sev {
  flex-shrink: 0; padding: 2px 7px; border-radius: 3px;
  font-size: 9px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; align-self: flex-start;
}
.alert-sev.high   { background: rgba(255,61,61,0.2); color: var(--red); }
.alert-sev.medium { background: rgba(255,153,0,0.2); color: var(--orange); }
.alert-sev.low    { background: rgba(255,224,51,0.15); color: var(--yellow); }

/* Baseline table */
.baseline-table { width: 100%; border-collapse: collapse; font-size: 11px; }
.baseline-table th {
  background: var(--bg-2); border-bottom: 1px solid var(--border); border-right: 1px solid var(--border);
  padding: 6px 10px; text-align: left; font-size: 9px; font-weight: 700;
  letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-muted);
}
.baseline-table td {
  padding: 5px 10px; border-bottom: 1px solid var(--border); border-right: 1px solid var(--border);
  font-family: var(--font-mono); color: var(--text-secondary);
}
.baseline-table td:last-child, .baseline-table th:last-child { border-right: none; }
.baseline-table tr:hover td { background: var(--bg-3); }
.no-alerts {
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  gap: 8px; padding: 32px; color: var(--green); text-align: center;
}
`

function AlertItem({ alert }) {
  const typeLabels = {
    mac_changed:  'MAC Address Changed',
    ip_conflict:  'IP Conflict Detected',
    new_device:   'New Device',
  }
  return (
    <div className={`alert-item ${alert.severity}`}>
      <div className={`alert-icon ${alert.severity}`}>
        <AlertTriangle size={16} />
      </div>
      <div className="alert-body">
        <div className="alert-type">{typeLabels[alert.alert_type] || alert.alert_type}</div>
        <div className="alert-msg">{alert.message}</div>
        <div className="alert-meta">
          {alert.old_mac && <span>Old: {alert.old_mac} ({alert.old_vendor}) → </span>}
          {alert.new_mac && <span>New: {alert.new_mac} ({alert.new_vendor})</span>}
          {alert.datetime && <span style={{marginLeft:8}}>{alert.datetime}</span>}
        </div>
      </div>
      <span className={`alert-sev ${alert.severity}`}>{alert.severity}</span>
    </div>
  )
}

export default function SecurityView() {
  const [alerts, setAlerts] = useState([])
  const [baseline, setBaseline] = useState([])
  const [scanning, setScanning] = useState(false)
  const [tab, setTab] = useState('alerts')

  const load = async () => {
    const [al, bl] = await Promise.all([
      fetch('/api/security/arp-alerts').then(r => r.json()),
      fetch('/api/security/arp-baseline').then(r => r.json()),
    ])
    setAlerts(al)
    setBaseline(bl)
  }

  useEffect(() => { load() }, [])

  const runScan = async () => {
    setScanning(true)
    const res = await fetch('/api/security/arp-scan', { method: 'POST' })
    const data = await res.json()
    setScanning(false)
    load()
  }

  const clearBaseline = async () => {
    if (!confirm('Clear ARP baseline? All devices will be treated as new on next scan.')) return
    await fetch('/api/security/arp-baseline', { method: 'DELETE' })
    load()
  }

  const high   = alerts.filter(a => a.severity === 'high').length
  const medium = alerts.filter(a => a.severity === 'medium').length
  const cardType = high > 0 ? 'alert' : medium > 0 ? 'warn' : 'clean'

  return (
    <>
      <style>{css}</style>
      <div className="security-view">
        <div className="sec-header">
          <Shield size={14} color="var(--accent)" />
          <span className="sec-title">Security — ARP Guard</span>
          <div style={{ display:'flex', gap:6, marginLeft:'auto' }}>
            {[['alerts',`Alerts (${alerts.length})`],['baseline',`Baseline (${baseline.length})`]].map(([v,l]) => (
              <button key={v} onClick={() => setTab(v)} style={{
                padding:'4px 12px', borderRadius:4, fontSize:11, fontWeight:700, cursor:'pointer',
                background: tab===v ? 'rgba(0,212,255,0.1)' : 'var(--bg-3)',
                border: `1px solid ${tab===v ? 'var(--accent-dim)' : 'var(--border)'}`,
                color: tab===v ? 'var(--accent)' : 'var(--text-secondary)',
                textTransform:'uppercase', letterSpacing:'0.06em',
              }}>{l}</button>
            ))}
          </div>
        </div>

        <div className="sec-body">
          {/* Summary cards */}
          <div className="sec-summary-cards">
            <div className={`sec-card ${high > 0 ? 'alert' : 'clean'}`}>
              <div className="sec-card-num">{high}</div>
              <div className="sec-card-label">High Severity</div>
            </div>
            <div className={`sec-card ${medium > 0 ? 'warn' : 'clean'}`}>
              <div className="sec-card-num">{medium}</div>
              <div className="sec-card-label">Medium Severity</div>
            </div>
            <div className={`sec-card ${cardType}`}>
              <div className="sec-card-num">{baseline.length}</div>
              <div className="sec-card-label">Baseline Entries</div>
            </div>
            <div style={{ display:'flex', flexDirection:'column', gap:6, justifyContent:'center' }}>
              <button className="scan-btn-arp" onClick={runScan} disabled={scanning}>
                <Shield size={13} />{scanning ? 'Scanning…' : 'Scan ARP Now'}
              </button>
              <button onClick={clearBaseline} style={{
                display:'flex', alignItems:'center', gap:4, padding:'5px 10px', borderRadius:4,
                background:'none', border:'1px solid var(--border)', color:'var(--text-muted)',
                fontSize:11, cursor:'pointer', fontWeight:600, textTransform:'uppercase',
              }}>
                <Trash2 size={11} /> Clear Baseline
              </button>
            </div>
          </div>

          {/* Alerts tab */}
          {tab === 'alerts' && (
            <div>
              <div className="sec-section-title"><AlertTriangle size={11} /> ARP Alerts</div>
              {alerts.length === 0 ? (
                <div className="no-alerts">
                  <CheckCircle size={32} />
                  <span>No ARP anomalies detected</span>
                  <span style={{fontSize:11, color:'var(--text-muted)'}}>Run a scan to check your network</span>
                </div>
              ) : (
                <div className="alert-list">
                  {alerts.map((a, i) => <AlertItem key={i} alert={a} />)}
                </div>
              )}
            </div>
          )}

          {/* Baseline tab */}
          {tab === 'baseline' && (
            <div>
              <div className="sec-section-title"><Eye size={11} /> Known ARP Baseline ({baseline.length} entries)</div>
              <table className="baseline-table">
                <thead>
                  <tr>
                    <th>IP</th><th>MAC</th><th>Vendor</th>
                    <th>First Seen</th><th>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {baseline.map((b, i) => (
                    <tr key={i}>
                      <td style={{color:'var(--text-primary)', fontWeight:500}}>{b.ip}</td>
                      <td>{b.mac}</td>
                      <td style={{fontFamily:'sans-serif', fontSize:11}}>{b.vendor || '—'}</td>
                      <td style={{fontSize:10}}>{b.first_seen ? new Date(b.first_seen*1000).toLocaleString('de-DE') : '—'}</td>
                      <td style={{fontSize:10}}>{b.last_seen  ? new Date(b.last_seen*1000).toLocaleString('de-DE')  : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </>
  )
}
