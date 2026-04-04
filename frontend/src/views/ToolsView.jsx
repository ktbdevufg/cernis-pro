import React, { useState, useEffect, useRef } from 'react'
import { Wrench, Search, GitBranch, Globe, Activity, Shield, RefreshCw, Wifi, Zap } from 'lucide-react'

const css = `
@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
.tools-view { position: absolute; inset: 0; display: flex; flex-direction: column; }
.tools-header {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 20px; border-bottom: 1px solid var(--border);
  background: var(--bg-1); flex-shrink: 0;
}
.tools-title { font-size: 13px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); }
.tools-tabs { display: flex; gap: 4px; padding: 8px 20px; background: var(--bg-1); border-bottom: 1px solid var(--border); flex-shrink: 0; }
.tools-tab {
  display: flex; align-items: center; gap: 5px;
  padding: 5px 14px; border-radius: 4px; font-size: 11px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.06em; cursor: pointer;
  background: var(--bg-3); border: 1px solid var(--border); color: var(--text-muted);
  transition: all 0.1s;
}
.tools-tab.active { background: rgba(0,212,255,0.1); border-color: var(--accent-dim); color: var(--accent); }
.tools-body { flex: 1; overflow-y: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 12px; }

/* Input row */
.tool-input-row {
  display: flex; gap: 8px; align-items: center;
  background: var(--bg-2); border: 1px solid var(--border); border-radius: 6px; padding: 12px 14px;
}
.tool-input {
  background: var(--bg-3); border: 1px solid var(--border);
  color: var(--text-primary); padding: 7px 10px; border-radius: 4px;
  font-size: 13px; font-family: var(--font-mono); flex: 1;
}
.tool-input:focus { border-color: var(--accent-dim); outline: none; }
.tool-run-btn {
  display: flex; align-items: center; gap: 5px;
  background: var(--accent); color: var(--bg-0);
  padding: 7px 16px; border-radius: 4px; font-size: 12px; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.08em; cursor: pointer; border: none;
}
.tool-run-btn:hover { background: #33ddff; }
.tool-run-btn:disabled { opacity: 0.5; cursor: not-allowed; }

/* Traceroute */
.traceroute-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.traceroute-table th {
  background: var(--bg-3); border-bottom: 1px solid var(--border);
  padding: 6px 10px; text-align: left; font-size: 9px; font-weight: 700;
  letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-muted);
}
.traceroute-table td { padding: 5px 10px; border-bottom: 1px solid var(--border); font-family: var(--font-mono); }
.traceroute-table tr:hover td { background: var(--bg-3); }
.hop-rtt.fast { color: var(--green); } .hop-rtt.med { color: var(--yellow); } .hop-rtt.slow { color: var(--orange); }
.hop-timeout { color: var(--text-muted); font-style: italic; }

/* DNS */
.dns-section { margin-bottom: 10px; }
.dns-rtype { font-size: 9px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-muted); margin-bottom: 4px; }
.dns-records { display: flex; flex-wrap: wrap; gap: 4px; }
.dns-record {
  padding: 3px 9px; border-radius: 3px; font-size: 11px; font-family: var(--font-mono);
  background: rgba(0,212,255,0.08); color: var(--accent); border: 1px solid rgba(0,212,255,0.2);
}
.dns-empty { color: var(--text-muted); font-size: 11px; font-style: italic; }

/* Bandwidth */
.bw-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 8px; }
.bw-card {
  background: var(--bg-2); border: 1px solid var(--border); border-radius: 5px; padding: 12px 14px;
}
.bw-iface { font-family: var(--font-mono); font-size: 12px; font-weight: 700; color: var(--accent); margin-bottom: 8px; }
.bw-row { display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 4px; }
.bw-key { color: var(--text-muted); }
.bw-val { font-family: var(--font-mono); color: var(--text-primary); }
.bw-val.up   { color: var(--orange); }
.bw-val.down { color: var(--green); }

/* SNMP */
.snmp-result { background: var(--bg-2); border: 1px solid var(--border); border-radius: 6px; padding: 14px; }
.snmp-kv { display: flex; gap: 8px; margin-bottom: 5px; font-size: 12px; }
.snmp-k { color: var(--text-muted); width: 110px; flex-shrink: 0; }
.snmp-v { font-family: var(--font-mono); color: var(--text-primary); }
.snmp-ifaces { margin-top: 10px; }
.snmp-iface-item { display: flex; gap: 10px; padding: 4px 8px; background: var(--bg-3); border-radius: 3px; margin-bottom: 3px; font-size: 11px; font-family: var(--font-mono); }
.snmp-if-name { color: var(--accent); width: 120px; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; }
.snmp-if-speed { color: var(--text-secondary); width: 70px; }
.snmp-if-status { font-weight: 700; }
.snmp-if-status.up   { color: var(--green); }
.snmp-if-status.down { color: var(--red); }

/* DHCP */
.dhcp-result { display: flex; flex-direction: column; gap: 6px; }
.dhcp-server {
  display: flex; align-items: center; gap: 12px; padding: 10px 14px;
  border-radius: 4px; border: 1px solid var(--border); background: var(--bg-3);
}
.dhcp-server.rogue { border-color: rgba(255,61,61,0.4); background: rgba(255,61,61,0.06); }
.dhcp-server.known { border-color: rgba(0,230,118,0.3); background: rgba(0,230,118,0.05); }
.dhcp-rogue-badge { padding: 2px 7px; border-radius: 3px; font-size: 9px; font-weight: 700; text-transform: uppercase; background: rgba(255,61,61,0.2); color: var(--red); border: 1px solid rgba(255,61,61,0.3); }
.dhcp-known-badge { padding: 2px 7px; border-radius: 3px; font-size: 9px; font-weight: 700; text-transform: uppercase; background: rgba(0,230,118,0.15); color: var(--green); border: 1px solid rgba(0,230,118,0.3); }
`

const TOOL_TABS = [
  { id: 'traceroute', label: 'Traceroute', icon: GitBranch },
  { id: 'dns',        label: 'DNS Lookup', icon: Globe },
  { id: 'bandwidth',  label: 'Bandwidth',  icon: Activity },
  { id: 'snmp',       label: 'SNMP',       icon: Search },
  { id: 'dhcp',       label: 'Rogue DHCP', icon: Shield },
  { id: 'internet',   label: 'Internet',   icon: Globe },
  { id: 'speedtest',  label: 'Speed Test', icon: Zap },
]

export default function ToolsView({ selectedIface }) {
  const [tab, setTab]         = useState('traceroute')
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState(null)

  // Traceroute
  const [trTarget, setTrTarget]   = useState('8.8.8.8')
  const [trHops, setTrHops]       = useState([])

  // DNS
  const [dnsQuery, setDnsQuery]   = useState('')
  const [dnsResults, setDnsResults] = useState([])

  // Bandwidth
  const [bwData, setBwData]       = useState([])
  const bwTimer                   = useRef(null)

  // SNMP
  const [snmpIP, setSnmpIP]       = useState('')
  const [snmpComm, setSnmpComm]   = useState('public')
  const [snmpResult, setSnmpResult] = useState(null)

  // DHCP
  const [dhcpServers, setDhcpServers] = useState([])
  // Internet Tools state
  const [extIP, setExtIP]               = useState(null)
  const [portCheck, setPortCheck]       = useState(null)
  const [portToCheck, setPortToCheck]   = useState('443')
  const [shodanData, setShodanData]     = useState(null)
  const [speedData, setSpeedData]       = useState(null)
  const [speedRunning, setSpeedRunning] = useState(false)

  // Auto-refresh bandwidth
  useEffect(() => {
    if (tab === 'internet' && !extIP) {
      fetch('/api/internet/external-ip').then(r=>r.json()).then(setExtIP).catch(()=>{})
      fetch('/api/internet/shodan', { method:'POST', headers:{'Content-Type':'application/json'}, body:'{}' })
        .then(r=>r.json()).then(setShodanData).catch(()=>{})
    }
    if (tab === 'bandwidth') {
      const fetchBW = () => fetch('/api/tools/bandwidth').then(r=>r.json()).then(setBwData).catch(()=>{})
      fetchBW()
      bwTimer.current = setInterval(fetchBW, 2000)
    }
    return () => { if (bwTimer.current) clearInterval(bwTimer.current) }
  }, [tab])

  const run = async () => {
    setLoading(true); setError(null)
    try {
      if (tab === 'traceroute') {
        setTrHops([])
        const res = await fetch('/api/tools/traceroute', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: trTarget }),
        })
        const data = await res.json()
        if (!res.ok) throw new Error(data.error)
        setTrHops(data)
      } else if (tab === 'dns') {
        const res = await fetch('/api/tools/dns', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: dnsQuery }),
        })
        const data = await res.json()
        if (!res.ok) throw new Error(data.error)
        setDnsResults(data)
      } else if (tab === 'snmp') {
        const res = await fetch('/api/snmp/query', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: snmpIP, communities: [snmpComm, 'public', 'private'] }),
        })
        const data = await res.json()
        if (!res.ok) throw new Error(data.error)
        setSnmpResult(data)
      } else if (tab === 'internet') {
        const res = await fetch('/api/internet/port-check', {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ port: parseInt(portToCheck) })
        })
        setPortCheck(await res.json())
      } else if (tab === 'speedtest') {
        setSpeedRunning(true)
        const res = await fetch('/api/internet/speedtest', { method:'POST' })
        setSpeedData(await res.json())
        setSpeedRunning(false)
      } else if (tab === 'dhcp') {
        const gateway = selectedIface?.gateway || null
        const res = await fetch('/api/tools/rogue-dhcp', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ gateway }),
        })
        const data = await res.json()
        if (!res.ok) throw new Error(data.error)
        setDhcpServers(data)
      }
    } catch (e) {
      setError(e.message || String(e))
    }
    setLoading(false)
  }

  const rttClass = r => r < 10 ? 'fast' : r < 50 ? 'med' : 'slow'
  const fmtBytes = b => b > 1e9 ? `${(b/1e9).toFixed(1)} GB` : b > 1e6 ? `${(b/1e6).toFixed(1)} MB` : `${(b/1e3).toFixed(0)} KB`

  return (
    <>
      <style>{css}</style>
      <div className="tools-view">
        <div className="tools-header">
          <Wrench size={14} color="var(--accent)" />
          <span className="tools-title">Network Tools</span>
        </div>

        <div className="tools-tabs">
          {TOOL_TABS.map(({ id, label, icon: Icon }) => (
            <button key={id} className={`tools-tab${tab===id?' active':''}`}
              onClick={() => { setTab(id); setError(null) }}>
              <Icon size={12} />{label}
            </button>
          ))}
        </div>

        <div className="tools-body">
          {error && <div style={{ color:'var(--red)', fontFamily:'var(--font-mono)', fontSize:12, padding:'8px 12px', background:'rgba(255,61,61,0.08)', borderRadius:4, border:'1px solid rgba(255,61,61,0.3)' }}>✗ {error}</div>}

          {/* ── Traceroute ── */}
          {tab === 'traceroute' && (
            <>
              <div className="tool-input-row">
                <input className="tool-input" value={trTarget} onChange={e => setTrTarget(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && run()} placeholder="Hostname or IP (e.g. 8.8.8.8)" />
                <button className="tool-run-btn" onClick={run} disabled={loading}>
                  {loading ? <RefreshCw size={13} className="animate-spin" /> : <GitBranch size={13} />}
                  {loading ? 'Running…' : 'Trace'}
                </button>
              </div>
              {trHops.length > 0 && (
                <table className="traceroute-table">
                  <thead><tr><th>#</th><th>IP</th><th>Hostname</th><th>RTT</th></tr></thead>
                  <tbody>
                    {trHops.map(h => (
                      <tr key={h.hop}>
                        <td style={{ color:'var(--text-muted)', width:30 }}>{h.hop}</td>
                        <td style={{ color:'var(--text-primary)', fontWeight:500 }}>{h.ip}</td>
                        <td style={{ color:'var(--text-secondary)' }}>{h.hostname !== h.ip ? h.hostname : '—'}</td>
                        <td className={h.timeout ? 'hop-timeout' : `hop-rtt ${rttClass(h.rtt_ms)}`}>
                          {h.timeout ? '* * *' : `${h.rtt_ms.toFixed(2)} ms`}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          )}

          {/* ── DNS ── */}
          {tab === 'dns' && (
            <>
              <div className="tool-input-row">
                <input className="tool-input" value={dnsQuery} onChange={e => setDnsQuery(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && run()} placeholder="Domain or IP (e.g. google.com or 8.8.8.8)" />
                <button className="tool-run-btn" onClick={run} disabled={loading || !dnsQuery}>
                  {loading ? <RefreshCw size={13} className="animate-spin" /> : <Globe size={13} />}
                  {loading ? 'Looking up…' : 'Lookup'}
                </button>
              </div>
              {dnsResults.length > 0 && (
                <div style={{ background:'var(--bg-2)', border:'1px solid var(--border)', borderRadius:6, padding:14 }}>
                  <div style={{ fontFamily:'var(--font-mono)', fontSize:12, color:'var(--accent)', marginBottom:12 }}>{dnsResults[0]?.query}</div>
                  {dnsResults.map((r, i) => r.records.length > 0 && (
                    <div key={i} className="dns-section">
                      <div className="dns-rtype">{r.record_type}</div>
                      <div className="dns-records">
                        {r.records.map((rec, j) => <span key={j} className="dns-record">{rec}</span>)}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}

          {/* ── Bandwidth ── */}
          {tab === 'bandwidth' && (
            <>
              <div style={{ fontSize:11, color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>
                Live bandwidth per interface · auto-refresh 2s
              </div>
              <div className="bw-grid">
                {bwData.map(iface => (
                  <div key={iface.interface} className="bw-card">
                    <div className="bw-iface">{iface.interface}</div>
                    <div className="bw-row"><span className="bw-key">↓ Download</span><span className="bw-val down">{iface.mbps_recv.toFixed(2)} Mbit/s</span></div>
                    <div className="bw-row"><span className="bw-key">↑ Upload</span><span className="bw-val up">{iface.mbps_sent.toFixed(2)} Mbit/s</span></div>
                    <div className="bw-row"><span className="bw-key">Total ↓</span><span className="bw-val">{fmtBytes(iface.bytes_recv)}</span></div>
                    <div className="bw-row"><span className="bw-key">Total ↑</span><span className="bw-val">{fmtBytes(iface.bytes_sent)}</span></div>
                  </div>
                ))}
                {bwData.length === 0 && <div style={{ color:'var(--text-muted)', fontSize:12 }}>Loading…</div>}
              </div>
            </>
          )}

          {/* ── SNMP ── */}
          {tab === 'snmp' && (
            <>
              <div className="tool-input-row">
                <input className="tool-input" value={snmpIP} onChange={e => setSnmpIP(e.target.value)}
                  placeholder="Device IP (e.g. 192.168.1.1)" />
                <input className="tool-input" value={snmpComm} onChange={e => setSnmpComm(e.target.value)}
                  placeholder="Community" style={{ maxWidth:120 }} />
                <button className="tool-run-btn" onClick={run} disabled={loading || !snmpIP}>
                  {loading ? <RefreshCw size={13} className="animate-spin" /> : <Search size={13} />}
                  {loading ? 'Querying…' : 'Query'}
                </button>
              </div>
              {snmpResult && (
                <div className="snmp-result">
                  {!snmpResult.reachable ? (
                    <div style={{ color:'var(--red)', fontFamily:'var(--font-mono)', fontSize:12 }}>
                      Device not reachable via SNMP (community: {snmpResult.community || 'none worked'})
                    </div>
                  ) : (
                    <>
                      <div className="snmp-kv"><span className="snmp-k">Device</span><span className="snmp-v" style={{ color:'var(--accent)' }}>{snmpResult.sys_name || '—'}</span></div>
                      <div className="snmp-kv"><span className="snmp-k">Description</span><span className="snmp-v">{snmpResult.sys_desc?.substring(0,80) || '—'}</span></div>
                      <div className="snmp-kv"><span className="snmp-k">Community</span><span className="snmp-v">{snmpResult.community}</span></div>
                      <div className="snmp-kv"><span className="snmp-k">Uptime</span><span className="snmp-v">{snmpResult.uptime_secs > 0 ? `${Math.floor(snmpResult.uptime_secs/3600)}h ${Math.floor((snmpResult.uptime_secs%3600)/60)}m` : '—'}</span></div>
                      <div className="snmp-kv"><span className="snmp-k">Location</span><span className="snmp-v">{snmpResult.sys_location || '—'}</span></div>
                      {snmpResult.interfaces?.length > 0 && (
                        <div className="snmp-ifaces">
                          <div style={{ fontSize:9, fontWeight:700, letterSpacing:'0.1em', textTransform:'uppercase', color:'var(--text-muted)', marginBottom:6 }}>
                            Interfaces ({snmpResult.interfaces.length})
                          </div>
                          {snmpResult.interfaces.slice(0,8).map((iface, i) => (
                            <div key={i} className="snmp-iface-item">
                              <span className="snmp-if-name">{iface.description}</span>
                              <span className="snmp-if-speed">{iface.speed_mbps > 0 ? `${iface.speed_mbps} Mbps` : '—'}</span>
                              <span className={`snmp-if-status ${iface.oper_status}`}>{iface.oper_status.toUpperCase()}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}
            </>
          )}

          {/* ── Rogue DHCP ── */}
          {tab === 'dhcp' && (
            <>
              <div style={{ background:'var(--bg-2)', border:'1px solid var(--border)', borderRadius:6, padding:12, fontSize:12, color:'var(--text-secondary)' }}>
                <b style={{ color:'var(--text-primary)' }}>Rogue DHCP Detection</b><br />
                Sends a DHCP Discover broadcast and listens for responses.
                Any server other than your known gateway ({selectedIface?.gateway || 'unknown'}) is flagged as rogue.
                Requires <span style={{ color:'var(--accent)', fontFamily:'var(--font-mono)' }}>scapy</span> for active detection.
              </div>
              <div style={{ display:'flex', justifyContent:'center' }}>
                <button className="tool-run-btn" onClick={run} disabled={loading} style={{ padding:'10px 32px' }}>
                  {loading ? <RefreshCw size={13} className="animate-spin" /> : <Shield size={14} />}
                  {loading ? 'Scanning…' : 'Detect Rogue DHCP'}
                </button>
              </div>
              {dhcpServers.length > 0 && (
                <div className="dhcp-result">
                  {dhcpServers.map((s, i) => (
                    <div key={i} className={`dhcp-server ${s.is_rogue ? 'rogue' : s.is_known ? 'known' : ''}`}>
                      <div style={{ flex:1 }}>
                        <div style={{ fontFamily:'var(--font-mono)', fontWeight:600, color:'var(--text-primary)' }}>{s.ip}</div>
                        {s.mac && <div style={{ fontSize:10, color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>{s.mac}</div>}
                      </div>
                      {s.is_rogue  && <span className="dhcp-rogue-badge">⚠ ROGUE</span>}
                      {s.is_known  && <span className="dhcp-known-badge">✓ GATEWAY</span>}
                      {!s.is_rogue && !s.is_known && <span style={{ fontSize:10, color:'var(--text-muted)' }}>Unknown</span>}
                    </div>
                  ))}
                </div>
              )}
              {dhcpServers.length === 0 && !loading && (
                <div style={{ textAlign:'center', color:'var(--text-muted)', fontSize:12, padding:16 }}>
                  Click "Detect" to scan for DHCP servers
                </div>
              )}
            </>
          )}

          {/* ── Internet ── */}
          {tab === 'internet' && (
            <>
              {/* External IP */}
              <div style={{ background:'var(--bg-2)', border:'1px solid var(--border)', borderRadius:6, padding:14 }}>
                <div style={{ fontSize:10, fontWeight:700, letterSpacing:'0.1em', textTransform:'uppercase', color:'var(--text-muted)', marginBottom:8 }}>External IP</div>
                {extIP ? (
                  <div style={{ fontFamily:'var(--font-mono)', fontSize:20, color:'var(--accent)', fontWeight:700 }}>
                    {extIP.ip || '—'}
                  </div>
                ) : <div style={{ color:'var(--text-muted)', fontSize:12 }}>Loading…</div>}
              </div>

              {/* Port Check */}
              <div style={{ background:'var(--bg-2)', border:'1px solid var(--border)', borderRadius:6, padding:14 }}>
                <div style={{ fontSize:10, fontWeight:700, letterSpacing:'0.1em', textTransform:'uppercase', color:'var(--text-muted)', marginBottom:8 }}>External Port Check</div>
                <div style={{ display:'flex', gap:8 }}>
                  <input className="tool-input" value={portToCheck}
                    onChange={e => setPortToCheck(e.target.value)}
                    placeholder="Port (e.g. 443)" style={{ width:120 }} />
                  <button className="tool-run-btn" onClick={run} disabled={loading}>
                    {loading ? <RefreshCw size={13}/> : <Globe size={13}/>} Check
                  </button>
                </div>
                {portCheck && (
                  <div style={{ marginTop:10, fontFamily:'var(--font-mono)', fontSize:13 }}>
                    Port {portCheck.port}:
                    <span style={{ marginLeft:8, fontWeight:700, color: portCheck.open ? 'var(--green)' : 'var(--red)' }}>
                      {portCheck.open ? '✓ OPEN' : '✗ CLOSED'}
                    </span>
                    {portCheck.note && <div style={{ fontSize:10, color:'var(--text-muted)', marginTop:4 }}>{portCheck.note}</div>}
                  </div>
                )}
              </div>

              {/* Shodan */}
              {shodanData && !shodanData.error && (
                <div style={{ background:'var(--bg-2)', border:'1px solid var(--border)', borderRadius:6, padding:14 }}>
                  <div style={{ fontSize:10, fontWeight:700, letterSpacing:'0.1em', textTransform:'uppercase', color:'var(--text-muted)', marginBottom:8 }}>
                    Shodan InternetDB — {shodanData.ip}
                  </div>
                  {shodanData.ports?.length > 0 && (
                    <div style={{ marginBottom:8 }}>
                      <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:4 }}>Open Ports</div>
                      <div style={{ display:'flex', gap:4, flexWrap:'wrap' }}>
                        {shodanData.ports.map(p => (
                          <span key={p} style={{ padding:'2px 7px', borderRadius:3, fontSize:11, fontFamily:'var(--font-mono)', background:'rgba(0,212,255,0.1)', color:'var(--accent)', border:'1px solid rgba(0,212,255,0.2)' }}>{p}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {shodanData.vulns?.length > 0 && (
                    <div style={{ marginBottom:8 }}>
                      <div style={{ fontSize:10, color:'var(--red)', marginBottom:4, fontWeight:700 }}>⚠ Known Vulnerabilities</div>
                      <div style={{ display:'flex', gap:4, flexWrap:'wrap' }}>
                        {shodanData.vulns.map(v => (
                          <span key={v} style={{ padding:'2px 7px', borderRadius:3, fontSize:11, fontFamily:'var(--font-mono)', background:'rgba(255,61,61,0.1)', color:'var(--red)', border:'1px solid rgba(255,61,61,0.3)' }}>{v}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {shodanData.hostnames?.length > 0 && (
                    <div style={{ fontSize:11, color:'var(--text-muted)' }}>
                      Hostnames: {shodanData.hostnames.join(', ')}
                    </div>
                  )}
                  {shodanData.ports?.length === 0 && shodanData.vulns?.length === 0 && (
                    <div style={{ color:'var(--green)', fontSize:12 }}>✓ No open ports or known vulnerabilities found</div>
                  )}
                  <div style={{ fontSize:9, color:'var(--text-muted)', marginTop:8 }}>Source: {shodanData.source}</div>
                </div>
              )}
            </>
          )}

          {/* ── Speed Test ── */}
          {tab === 'speedtest' && (
            <>
              <div style={{ textAlign:'center', padding:'20px 0' }}>
                <button className="tool-run-btn" onClick={run} disabled={speedRunning || loading}
                  style={{ padding:'12px 32px', fontSize:13 }}>
                  {speedRunning ? <RefreshCw size={16} style={{animation:"spin 1s linear infinite"}}/> : <Zap size={16}/>}
                  {speedRunning ? 'Testing… (may take 30s)' : 'Start Speed Test'}
                </button>
              </div>
              {speedData && (
                <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:10 }}>
                  {[
                    ['↓ Download', speedData.download_mbps, 'var(--green)'],
                    ['↑ Upload',   speedData.upload_mbps,   'var(--orange)'],
                    ['Ping',       speedData.ping_ms,        'var(--accent)'],
                  ].map(([label, val, color]) => (
                    <div key={label} style={{ background:'var(--bg-2)', border:'1px solid var(--border)', borderRadius:6, padding:'16px', textAlign:'center' }}>
                      <div style={{ fontSize:28, fontWeight:700, fontFamily:'var(--font-mono)', color }}>{val || '—'}</div>
                      <div style={{ fontSize:10, color:'var(--text-muted)', marginTop:4, textTransform:'uppercase', letterSpacing:'0.08em' }}>
                        {label} {label !== 'Ping' ? 'Mbit/s' : 'ms'}
                      </div>
                    </div>
                  ))}
                </div>
              )}
              {speedData?.error && <div style={{ color:'var(--red)', fontFamily:'var(--font-mono)', fontSize:12 }}>✗ {speedData.error}</div>}
              {!speedData && !speedRunning && (
                <div style={{ color:'var(--text-muted)', fontSize:12, textAlign:'center', padding:16 }}>
                  Uses Cloudflare speed servers. Download: 10MB test, Upload: 1MB test.
                </div>
              )}
            </>
          )}

        </div>
      </div>
    </>
  )
}
