import React, { useState, useEffect } from 'react'
import { FileText, Download, Search, AlertTriangle, Shield, ExternalLink, RefreshCw } from 'lucide-react'

const css = `
.report-view { position: absolute; inset: 0; display: flex; flex-direction: column; }
.report-header {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 20px; border-bottom: 1px solid var(--border);
  background: var(--bg-1); flex-shrink: 0;
}
.report-title { font-size: 13px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); }
.report-body { flex: 1; overflow-y: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 16px; }

/* PDF export card */
.export-card {
  background: var(--bg-2); border: 1px solid var(--border); border-radius: 6px; padding: 16px;
}
.export-card-title {
  font-size: 10px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--text-muted); margin-bottom: 12px; display: flex; align-items: center; gap: 6px;
}
.scan-select-row { display: flex; gap: 8px; align-items: center; }
.scan-select {
  background: var(--bg-3); border: 1px solid var(--border);
  color: var(--text-primary); padding: 7px 10px; border-radius: 4px;
  font-size: 12px; font-family: var(--font-mono); flex: 1;
}
.export-pdf-btn {
  display: flex; align-items: center; gap: 6px;
  background: var(--accent); color: var(--bg-0);
  padding: 7px 16px; border-radius: 4px; font-size: 12px; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.08em; cursor: pointer; border: none;
  transition: all 0.15s; white-space: nowrap;
}
.export-pdf-btn:hover { background: #33ddff; }
.export-pdf-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.export-csv-btn {
  display: flex; align-items: center; gap: 5px;
  background: var(--bg-3); border: 1px solid var(--border);
  color: var(--text-secondary); padding: 7px 12px; border-radius: 4px;
  font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em;
  cursor: pointer; border: none; transition: all 0.12s;
}
.export-csv-btn:hover { color: var(--text-primary); }

/* CVE section */
.cve-section { background: var(--bg-2); border: 1px solid var(--border); border-radius: 6px; }
.cve-header {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 16px; border-bottom: 1px solid var(--border);
}
.cve-header-title {
  font-size: 10px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--text-muted);
}
.cve-host-select {
  background: var(--bg-3); border: 1px solid var(--border);
  color: var(--text-primary); padding: 5px 8px; border-radius: 4px;
  font-size: 12px; font-family: var(--font-mono); flex: 1; max-width: 200px;
}
.cve-scan-btn {
  display: flex; align-items: center; gap: 5px;
  background: rgba(0,212,255,0.1); border: 1px solid var(--accent-dim);
  color: var(--accent); padding: 5px 12px; border-radius: 4px;
  font-size: 11px; font-weight: 700; text-transform: uppercase; cursor: pointer;
}
.cve-scan-btn:hover { background: rgba(0,212,255,0.2); }
.cve-scan-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.cve-list { padding: 8px; display: flex; flex-direction: column; gap: 6px; }
.cve-item {
  display: flex; gap: 10px; padding: 10px 12px; border-radius: 5px; border: 1px solid transparent;
}
.cve-item.CRITICAL { background: rgba(255,61,61,0.07); border-color: rgba(255,61,61,0.3); }
.cve-item.HIGH     { background: rgba(255,153,0,0.07); border-color: rgba(255,153,0,0.25); }
.cve-item.MEDIUM   { background: rgba(255,224,51,0.05); border-color: rgba(255,224,51,0.2); }
.cve-item.LOW      { background: rgba(0,230,118,0.05); border-color: rgba(0,230,118,0.2); }
.cve-score-badge {
  flex-shrink: 0; width: 44px; height: 44px; border-radius: 6px;
  display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 1px;
}
.cve-score-badge.CRITICAL { background: rgba(255,61,61,0.2); }
.cve-score-badge.HIGH     { background: rgba(255,153,0,0.2); }
.cve-score-badge.MEDIUM   { background: rgba(255,224,51,0.15); }
.cve-score-badge.LOW      { background: rgba(0,230,118,0.12); }
.cve-score-num  { font-family: var(--font-mono); font-size: 15px; font-weight: 700; line-height: 1; }
.cve-score-sev  { font-size: 7px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
.CRITICAL .cve-score-num, .CRITICAL .cve-score-sev { color: var(--red); }
.HIGH     .cve-score-num, .HIGH     .cve-score-sev { color: var(--orange); }
.MEDIUM   .cve-score-num, .MEDIUM   .cve-score-sev { color: var(--yellow); }
.LOW      .cve-score-num, .LOW      .cve-score-sev { color: var(--green); }
.cve-body { flex: 1; min-width: 0; }
.cve-id   { font-family: var(--font-mono); font-size: 12px; font-weight: 700; color: var(--accent); margin-bottom: 3px; }
.cve-desc { font-size: 11px; color: var(--text-secondary); line-height: 1.5; margin-bottom: 4px; }
.cve-meta { display: flex; gap: 12px; font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); }
.cve-link { display: flex; align-items: center; gap: 3px; color: var(--accent); text-decoration: none; }
.cve-link:hover { text-decoration: underline; }
.cve-port-chip {
  padding: 1px 6px; border-radius: 2px; font-size: 10px; font-family: var(--font-mono);
  background: rgba(0,212,255,0.08); color: var(--accent); border: 1px solid rgba(0,212,255,0.15);
}
.cve-empty {
  padding: 30px; text-align: center; color: var(--text-muted); font-size: 12px;
  display: flex; flex-direction: column; align-items: center; gap: 8px;
}
`

function fmtDate(s) {
  if (!s) return ''
  return new Date(s + 'Z').toLocaleString('de-DE', { dateStyle:'short', timeStyle:'short' })
}

export default function ReportView({ hosts }) {
  const [history, setHistory]       = useState([])
  const [selectedScan, setSelected] = useState('')
  const [exporting, setExporting]   = useState(false)
  const [cveHost, setCveHost]       = useState('')
  const [cves, setCves]             = useState([])
  const [cveLoading, setCveLoading] = useState(false)
  const [cveError, setCveError]     = useState(null)

  useEffect(() => {
    fetch('/api/history?limit=20').then(r => r.json()).then(data => {
      setHistory(data)
      if (data.length > 0) setSelected(String(data[0].id))
    }).catch(() => {})
  }, [])

  const downloadFile = async (url) => {
    // WebKit2GTK/Tauri: window.location.href with Content-Disposition: attachment
    // triggers a download without navigating away from the page
    setExporting(true)
    try {
      // Pre-check for errors (PDF might fail with reportlab missing etc.)
      const res = await fetch(url)
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }))
        alert(err.error || `Export failed: HTTP ${res.status}`)
        setExporting(false)
        return
      }
      // Response is OK — trigger actual download via location
      window.location.href = url
    } catch (e) {
      alert('Export failed: ' + e.message)
    }
    setExporting(false)
  }

  const exportPDF = () => {
    if (!selectedScan) return
    downloadFile(`/api/export/pdf?scan_id=${selectedScan}`)
  }

  const exportCSV = () => {
    if (!selectedScan) return
    downloadFile(`/api/export/csv?scan_id=${selectedScan}`)
  }

  const exportJSON = () => {
    if (!selectedScan) return
    downloadFile(`/api/export/json?scan_id=${selectedScan}`)
  }

  const runCveLookup = async () => {
    const host = hosts.find(h => h.ip === cveHost)
    if (!host || !host.ports || host.ports.length === 0) {
      setCveError('No open ports found for this host. Run a port scan first.')
      return
    }
    setCveLoading(true); setCveError(null); setCves([])
    try {
      const res = await fetch('/api/cve/lookup-v2', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ports: host.ports, external_ip: host.ip }),
      })
      const data = await res.json()
      setCves(data)
      if (data.length === 0) setCveError('No CVEs found for the open ports on this host.')
    } catch (e) {
      setCveError('CVE lookup failed: ' + e.message)
    }
    setCveLoading(false)
  }

  const hostsWithPorts = hosts.filter(h => h.ports && h.ports.length > 0)

  return (
    <>
      <style>{css}</style>
      <div className="report-view">
        <div className="report-header">
          <FileText size={14} color="var(--accent)" />
          <span className="report-title">Reports & CVE Lookup</span>
        </div>

        <div className="report-body">

          {/* PDF Export */}
          <div className="export-card">
            <div className="export-card-title"><Download size={11} /> Export Scan Report</div>
            <div className="scan-select-row">
              <select className="scan-select" value={selectedScan}
                onChange={e => setSelected(e.target.value)}>
                <option value="">— Select scan —</option>
                {history.map(h => (
                  <option key={h.id} value={h.id}>
                    #{h.id} · {fmtDate(h.scanned_at)} · {h.cidr} · {h.host_count} hosts
                  </option>
                ))}
              </select>
              <button className="export-pdf-btn" onClick={exportPDF} disabled={!selectedScan}>
                <FileText size={13} /> PDF Report
              </button>
              <button className="export-csv-btn" onClick={exportCSV} disabled={!selectedScan}>
                <Download size={12} /> CSV
              </button>
              <button className="export-csv-btn" onClick={exportJSON} disabled={!selectedScan}>
                <Download size={12} /> JSON
              </button>
            </div>
            {!selectedScan && (
              <div style={{ fontSize:11, color:'var(--text-muted)', marginTop:8 }}>
                Run a scan first to generate a report. The PDF includes all hosts, open ports, OS guesses and security highlights.
              </div>
            )}
          </div>

          {/* CVE Lookup */}
          <div className="cve-section">
            <div className="cve-header">
              <AlertTriangle size={12} color="var(--orange)" />
              <span className="cve-header-title">CVE Vulnerability Lookup</span>
              <select className="cve-host-select" value={cveHost}
                onChange={e => { setCveHost(e.target.value); setCves([]); setCveError(null) }}>
                <option value="">— Select host —</option>
                {hostsWithPorts.map(h => (
                  <option key={h.ip} value={h.ip}>
                    {h.ip} {h.hostname ? `(${h.hostname})` : ''} — {h.ports.length} ports
                  </option>
                ))}
              </select>
              <button className="cve-scan-btn" onClick={runCveLookup}
                disabled={!cveHost || cveLoading}>
                {cveLoading
                  ? <><RefreshCw size={11} className="animate-spin" /> Querying NVD…</>
                  : <><Search size={11} /> Lookup CVEs</>}
              </button>
            </div>

            {hostsWithPorts.length === 0 && (
              <div className="cve-empty">
                <Shield size={28} style={{ opacity:0.2 }} />
                <span>No hosts with open ports — run a scan first</span>
              </div>
            )}

            {cveError && (
              <div style={{ padding:'12px 16px', color:'var(--orange)', fontSize:12, fontFamily:'var(--font-mono)' }}>
                ⚠ {cveError}
              </div>
            )}

            {cveLoading && (
              <div className="cve-empty">
                <RefreshCw size={24} className="animate-spin" style={{ color:'var(--accent)' }} />
                <span>Querying NIST NVD database…</span>
                <span style={{ fontSize:10 }}>This may take 10–30 seconds (API rate limit)</span>
              </div>
            )}

            {cves.length > 0 && (
              <div className="cve-list">
                <div style={{ padding:'6px 12px', fontSize:10, color:'var(--text-muted)', borderBottom:'1px solid var(--border)' }}>
                  {cves.length} CVE(s) found for {cveHost} · Source: NIST NVD
                </div>
                {cves.map((cve, i) => (
                  <div key={i} className={`cve-item ${cve.severity}`}>
                    <div className={`cve-score-badge ${cve.severity}`}>
                      <span className="cve-score-num">{cve.cvss_score.toFixed(1)}</span>
                      <span className="cve-score-sev">{cve.severity}</span>
                    </div>
                    <div className="cve-body">
                      <div className="cve-id">
                        {cve.cve_id}
                        {cve.port > 0 && <span className="cve-port-chip" style={{ marginLeft:8 }}>Port {cve.port}</span>}
                        {cve.is_public && <span style={{ marginLeft:6, padding:'1px 5px', borderRadius:2, fontSize:9, fontWeight:700, background:'rgba(255,61,61,0.2)', color:'var(--red)', border:'1px solid rgba(255,61,61,0.3)' }}>PUBLIC</span>}
                        {cve.is_public === false && <span style={{ marginLeft:6, padding:'1px 5px', borderRadius:2, fontSize:9, fontWeight:700, background:'rgba(0,212,255,0.1)', color:'var(--accent)', border:'1px solid rgba(0,212,255,0.2)' }}>LOCAL</span>}
                      </div>
                      <div className="cve-desc">{cve.description}</div>
                      <div className="cve-meta">
                        <span>{cve.published}</span>
                        {cve.service && <span>{cve.service}</span>}
                        <a href={cve.url} target="_blank" rel="noreferrer" className="cve-link">
                          <ExternalLink size={10} /> NVD
                        </a>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  )
}
