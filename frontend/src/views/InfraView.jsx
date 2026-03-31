import React, { useState, useEffect, useRef } from 'react'
import { Server, Activity, Network, Globe, Radio, Wifi, Plus, Trash2, RefreshCw, Play, Square, Download, Copy, Check } from 'lucide-react'

const css = `
.infra-view { position: absolute; inset: 0; display: flex; flex-direction: column; }
.infra-header {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 20px; border-bottom: 1px solid var(--border);
  background: var(--bg-1); flex-shrink: 0;
}
.infra-title { font-size: 13px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); }
.infra-tabs { display: flex; gap: 4px; padding: 8px 20px; background: var(--bg-1); border-bottom: 1px solid var(--border); flex-shrink: 0; flex-wrap: wrap; }
.i-tab {
  display: flex; align-items: center; gap: 5px;
  padding: 5px 12px; border-radius: 4px; font-size: 11px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.06em; cursor: pointer;
  background: var(--bg-3); border: 1px solid var(--border); color: var(--text-muted); transition: all 0.1s;
}
.i-tab.active { background: rgba(0,212,255,0.1); border-color: var(--accent-dim); color: var(--accent); }
.infra-body { flex: 1; overflow-y: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 12px; }

/* Cards */
.i-card { background: var(--bg-2); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
.i-card-title {
  display: flex; align-items: center; gap: 8px; padding: 10px 14px;
  border-bottom: 1px solid var(--border); background: var(--bg-3);
  font-size: 10px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--text-muted);
}
.i-card-body { padding: 14px; }

/* Agent cards */
.agent-card {
  display: flex; align-items: center; gap: 12px; padding: 10px 14px;
  background: var(--bg-3); border: 1px solid var(--border); border-radius: 5px; margin-bottom: 6px;
}
.agent-status { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.agent-status.online  { background: var(--green); box-shadow: 0 0 6px var(--green); }
.agent-status.offline { background: var(--text-muted); }
.agent-name { font-size: 12px; font-weight: 700; color: var(--text-primary); }
.agent-url  { font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); }
.agent-info { font-size: 10px; color: var(--text-secondary); font-family: var(--font-mono); }

/* Metrics */
.metrics-url {
  display: flex; align-items: center; gap: 8px; padding: 8px 12px;
  background: var(--bg-3); border: 1px solid var(--border); border-radius: 4px;
  font-family: var(--font-mono); font-size: 11px; color: var(--accent); margin-bottom: 6px;
}
.copy-btn {
  background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 2px; display: flex;
}
.copy-btn:hover { color: var(--text-primary); }

/* Packet capture */
.packet-table { width: 100%; border-collapse: collapse; font-size: 11px; font-family: var(--font-mono); }
.packet-table th {
  background: var(--bg-3); border-bottom: 1px solid var(--border); padding: 5px 8px;
  text-align: left; font-size: 9px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-muted);
}
.packet-table td { padding: 3px 8px; border-bottom: 1px solid rgba(42,52,72,0.5); }
.packet-table tr:hover td { background: var(--bg-3); }
.proto-badge {
  display: inline-block; padding: 1px 5px; border-radius: 2px; font-size: 9px; font-weight: 700;
}
.proto-TCP { background: rgba(0,212,255,0.1); color: var(--accent); }
.proto-HTTPS { background: rgba(0,230,118,0.1); color: var(--green); }
.proto-UDP  { background: rgba(187,134,252,0.1); color: var(--purple); }
.proto-DNS  { background: rgba(255,224,51,0.1); color: var(--yellow); }
.proto-HTTP { background: rgba(255,153,0,0.1); color: var(--orange); }
.proto-ICMP { background: rgba(255,61,61,0.1); color: var(--red); }
.proto-mDNS { background: rgba(187,134,252,0.1); color: var(--purple); }
.proto-SSH  { background: rgba(0,230,118,0.1); color: var(--green); }
.proto-L2   { background: var(--bg-4); color: var(--text-muted); }

/* Stats grid */
.stats-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 8px; margin-bottom: 12px; }
.stat-box { background: var(--bg-3); border: 1px solid var(--border); border-radius: 4px; padding: 10px 12px; }
.stat-box-val { font-size: 20px; font-weight: 700; font-family: var(--font-mono); color: var(--accent); }
.stat-box-key { font-size: 9px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-muted); margin-top: 2px; }

/* LLDP */
.lldp-neighbor {
  background: var(--bg-3); border: 1px solid var(--border); border-radius: 4px; padding: 10px 12px; margin-bottom: 6px;
}
.lldp-name { font-size: 12px; font-weight: 700; color: var(--accent); margin-bottom: 4px; }
.lldp-meta { font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); display: flex; gap: 12px; flex-wrap: wrap; }

/* IPv6 */
.ipv6-row { display: flex; align-items: center; gap: 10px; padding: 6px 10px; background: var(--bg-3); border-radius: 3px; margin-bottom: 4px; font-family: var(--font-mono); font-size: 11px; }
.ipv6-addr { color: var(--accent); flex: 1; }
.ipv6-type { font-size: 9px; padding: 1px 5px; border-radius: 2px; font-weight: 700; }
.ipv6-type.link-local { background: rgba(0,212,255,0.1); color: var(--accent); }
.ipv6-type.global     { background: rgba(0,230,118,0.1); color: var(--green); }
.ipv6-type.ula        { background: rgba(187,134,252,0.1); color: var(--purple); }

/* Form elements */
.i-input {
  background: var(--bg-3); border: 1px solid var(--border); color: var(--text-primary);
  padding: 7px 10px; border-radius: 4px; font-size: 12px; font-family: var(--font-mono);
}
.i-input:focus { border-color: var(--accent-dim); outline: none; }
.i-btn {
  display: flex; align-items: center; gap: 5px; padding: 6px 14px; border-radius: 4px;
  font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em;
  cursor: pointer; border: none; transition: all 0.12s;
}
.i-btn.primary { background: var(--accent); color: var(--bg-0); }
.i-btn.primary:hover { background: #33ddff; }
.i-btn.danger  { background: rgba(255,61,61,0.1); color: var(--red); border: 1px solid rgba(255,61,61,0.3); }
.i-btn.secondary { background: var(--bg-3); border: 1px solid var(--border); color: var(--text-secondary); }
.i-btn.secondary:hover { color: var(--text-primary); }
.i-btn:disabled { opacity: 0.4; cursor: not-allowed; }
`

const TABS = [
  { id: 'agents',  label: 'Remote Agents', icon: Server },
  { id: 'metrics', label: 'Metrics / Grafana', icon: Activity },
  { id: 'ipv6',    label: 'IPv6',  icon: Globe },
  { id: 'lldp',    label: 'LLDP/CDP', icon: Network },
  { id: 'pcap',    label: 'Packet Capture', icon: Radio },
]

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  return (
    <button className="copy-btn" onClick={() => {
      navigator.clipboard.writeText(text)
      setCopied(true); setTimeout(() => setCopied(false), 2000)
    }}>
      {copied ? <Check size={12} color="var(--green)" /> : <Copy size={12} />}
    </button>
  )
}

export default function InfraView({ selectedIface }) {
  const [tab, setTab] = useState('agents')

  // Agents
  const [agents, setAgents]         = useState([])
  const [agentStatus, setAgentStatus] = useState({})
  const [newAgent, setNewAgent]     = useState({ id:'', name:'', url:'', token:'', cidrs:[] })

  // Packet capture
  const [pcapRunning, setPcapRunning] = useState(false)
  const [pcapStats, setPcapStats]     = useState(null)
  const [packets, setPackets]         = useState([])
  const [pcapFilter, setPcapFilter]   = useState('')
  const pcapTimer = useRef(null)

  // LLDP
  const [lldpNeighbors, setLldpNeighbors] = useState([])
  const [lldpCapturing, setLldpCapturing] = useState(false)

  // IPv6
  const [ipv6Hosts, setIpv6Hosts]   = useState([])
  const [ipv6Loading, setIpv6Loading] = useState(false)
  const [ndpTable, setNdpTable]     = useState([])

  useEffect(() => {
    loadAgents()
    fetch('/api/lldp/neighbors').then(r=>r.json()).then(setLldpNeighbors).catch(()=>{})
    fetch('/api/ipv6/ndp').then(r=>r.json()).then(setNdpTable).catch(()=>{})
  }, [])

  // Pcap polling
  useEffect(() => {
    if (tab === 'pcap') {
      const poll = () => {
        fetch('/api/pcap/status').then(r=>r.json()).then(d => {
          setPcapRunning(d.running); setPcapStats(d.stats)
        }).catch(()=>{})
        if (pcapRunning) {
          fetch('/api/pcap/packets?limit=50').then(r=>r.json()).then(setPackets).catch(()=>{})
        }
      }
      poll()
      pcapTimer.current = setInterval(poll, 1000)
    }
    return () => { if (pcapTimer.current) clearInterval(pcapTimer.current) }
  }, [tab, pcapRunning])

  const loadAgents = async () => {
    const data = await fetch('/api/agents').then(r=>r.json()).catch(()=>[])
    setAgents(data)
    // Ping each
    for (const a of data) {
      fetch(`/api/agents/${a.id}/ping`).then(r=>r.json()).then(info => {
        setAgentStatus(prev => ({ ...prev, [a.id]: info }))
      }).catch(() => setAgentStatus(prev => ({ ...prev, [a.id]: { reachable: false } })))
    }
  }

  const addAgent = async () => {
    if (!newAgent.id || !newAgent.url) return
    await fetch('/api/agents', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(newAgent) })
    setNewAgent({ id:'', name:'', url:'', token:'', cidrs:[] })
    loadAgents()
  }

  const deleteAgent = async (id) => {
    await fetch(`/api/agents/${id}`, { method:'DELETE' })
    loadAgents()
  }

  const startPcap = async () => {
    await fetch('/api/pcap/start', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ filter: pcapFilter, interface: selectedIface?.name || '' }) })
    setPcapRunning(true)
  }

  const stopPcap = async () => {
    await fetch('/api/pcap/stop', { method:'POST' })
    setPcapRunning(false)
    fetch('/api/pcap/packets?limit=200').then(r=>r.json()).then(setPackets).catch(()=>{})
  }

  const startLldp = async () => {
    setLldpCapturing(true)
    const data = await fetch('/api/lldp/capture', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ interface: selectedIface?.name || '', duration: 30 }) }).then(r=>r.json()).catch(()=>[])
    setLldpNeighbors(data)
    setLldpCapturing(false)
  }

  const discoverIPv6 = async () => {
    setIpv6Loading(true)
    const data = await fetch('/api/ipv6/discover', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ interface: selectedIface?.name || '', duration: 5 }) }).then(r=>r.json()).catch(()=>[])
    setIpv6Hosts(data)
    const ndp = await fetch('/api/ipv6/ndp').then(r=>r.json()).catch(()=>[])
    setNdpTable(ndp)
    setIpv6Loading(false)
  }

  const fmtBytes = b => b > 1e9 ? `${(b/1e9).toFixed(1)}GB` : b > 1e6 ? `${(b/1e6).toFixed(1)}MB` : b > 1e3 ? `${(b/1e3).toFixed(0)}KB` : `${b}B`

  return (
    <>
      <style>{css}</style>
      <div className="infra-view">
        <div className="infra-header">
          <Server size={14} color="var(--accent)" />
          <span className="infra-title">Infrastructure</span>
        </div>

        <div className="infra-tabs">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button key={id} className={`i-tab${tab===id?' active':''}`} onClick={() => setTab(id)}>
              <Icon size={11} />{label}
            </button>
          ))}
        </div>

        <div className="infra-body">

          {/* ── Remote Agents ── */}
          {tab === 'agents' && (
            <>
              <div className="i-card">
                <div className="i-card-title"><Server size={11}/> Connected Agents</div>
                <div className="i-card-body">
                  {agents.length === 0 && <div style={{ color:'var(--text-muted)', fontSize:12, marginBottom:8 }}>No remote agents configured.</div>}
                  {agents.map(a => {
                    const status = agentStatus[a.id]
                    const online = status?.reachable !== false && !status?.error
                    return (
                      <div key={a.id} className="agent-card">
                        <div className={`agent-status ${online ? 'online' : 'offline'}`} />
                        <div style={{ flex:1 }}>
                          <div className="agent-name">{a.name || a.id}</div>
                          <div className="agent-url">{a.url}</div>
                          {status?.hostname && <div className="agent-info">{status.hostname} · {status.platform?.substring(0,30)}</div>}
                          {status?.error && <div style={{ fontSize:10, color:'var(--red)' }}>{status.error}</div>}
                        </div>
                        <button className="i-btn danger" onClick={() => deleteAgent(a.id)}><Trash2 size={11}/></button>
                      </div>
                    )
                  })}
                  <div style={{ display:'flex', gap:8, flexWrap:'wrap', marginTop:8 }}>
                    <input className="i-input" value={newAgent.id} onChange={e=>setNewAgent(p=>({...p,id:e.target.value}))} placeholder="ID (e.g. netcup)" style={{width:100}} />
                    <input className="i-input" value={newAgent.name} onChange={e=>setNewAgent(p=>({...p,name:e.target.value}))} placeholder="Name" style={{width:120}} />
                    <input className="i-input" value={newAgent.url} onChange={e=>setNewAgent(p=>({...p,url:e.target.value}))} placeholder="http://host:8766" style={{flex:1, minWidth:160}} />
                    <input className="i-input" type="password" value={newAgent.token} onChange={e=>setNewAgent(p=>({...p,token:e.target.value}))} placeholder="Token" style={{width:110}} />
                    <button className="i-btn primary" onClick={addAgent}><Plus size={11}/> Add</button>
                  </div>
                </div>
              </div>

              <div className="i-card">
                <div className="i-card-title"><Server size={11}/> Deploy Agent on Remote Host</div>
                <div className="i-card-body">
                  <div style={{ fontSize:11, color:'var(--text-secondary)', marginBottom:8 }}>Copy the agent script to your remote server (e.g. Netcup VPS):</div>
                  {[
                    'pip install fastapi uvicorn',
                    'python pulsar/backend/modules/agent.py --host 0.0.0.0 --port 8766 --token YOUR_TOKEN',
                  ].map((cmd, i) => (
                    <div key={i} className="metrics-url">
                      <span style={{ flex:1 }}>{cmd}</span>
                      <CopyButton text={cmd} />
                    </div>
                  ))}
                  <div style={{ fontSize:10, color:'var(--text-muted)', marginTop:6 }}>
                    The agent file is at: <code style={{ color:'var(--accent)' }}>pulsar/backend/modules/agent.py</code>
                  </div>
                </div>
              </div>
            </>
          )}

          {/* ── Metrics / Grafana ── */}
          {tab === 'metrics' && (
            <>
              <div className="i-card">
                <div className="i-card-title"><Activity size={11}/> Prometheus / Grafana</div>
                <div className="i-card-body">
                  <div style={{ fontSize:11, color:'var(--text-secondary)', marginBottom:10 }}>
                    Add CERNIS PRO as a Prometheus data source in Grafana:
                  </div>
                  {[
                    ['Prometheus Metrics', 'http://localhost:8765/metrics'],
                    ['InfluxDB Line Protocol', 'http://localhost:8765/api/export/influxdb'],
                    ['Home Assistant REST', 'http://localhost:8765/api/export/homeassistant'],
                  ].map(([label, url]) => (
                    <div key={url} style={{ marginBottom:8 }}>
                      <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:4, fontWeight:700, textTransform:'uppercase', letterSpacing:'0.08em' }}>{label}</div>
                      <div className="metrics-url">
                        <span style={{ flex:1 }}>{url}</span>
                        <a href={url} target="_blank" rel="noreferrer" style={{ color:'var(--accent)', fontSize:10, marginRight:4 }}>Open</a>
                        <CopyButton text={url} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="i-card">
                <div className="i-card-title"><Activity size={11}/> Available Metrics</div>
                <div className="i-card-body">
                  {[
                    ['pulsar_devices_total', 'Total devices in database'],
                    ['pulsar_devices_active_24h', 'Devices seen in last 24h'],
                    ['pulsar_monitor_rtt_ms{target}', 'RTT per monitor target'],
                    ['pulsar_monitor_up{target}', 'Up/down status per target'],
                    ['pulsar_sla_uptime_pct{target}', 'Uptime % last 24h'],
                    ['pulsar_sla_avg_rtt_ms{target}', 'Average RTT last 24h'],
                    ['pulsar_alerts_24h', 'Alerts fired last 24h'],
                    ['pulsar_scans_last_7d', 'Scan count last 7 days'],
                  ].map(([m, d]) => (
                    <div key={m} style={{ display:'flex', gap:12, marginBottom:5, fontSize:11 }}>
                      <code style={{ color:'var(--accent)', fontFamily:'var(--font-mono)', width:260, flexShrink:0 }}>{m}</code>
                      <span style={{ color:'var(--text-muted)' }}>{d}</span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}

          {/* ── IPv6 ── */}
          {tab === 'ipv6' && (
            <>
              <div style={{ display:'flex', gap:8 }}>
                <button className="i-btn primary" onClick={discoverIPv6} disabled={ipv6Loading}>
                  {ipv6Loading ? <RefreshCw size={12} className="animate-spin"/> : <Globe size={12}/>}
                  {ipv6Loading ? 'Discovering…' : 'Discover IPv6 Hosts'}
                </button>
              </div>

              {ndpTable.length > 0 && (
                <div className="i-card">
                  <div className="i-card-title"><Globe size={11}/> NDP Neighbor Table ({ndpTable.length})</div>
                  <div className="i-card-body" style={{ padding:'8px 14px' }}>
                    {ndpTable.map((row, i) => (
                      <div key={i} className="ipv6-row">
                        <span className="ipv6-addr">{row.ipv6}</span>
                        <span className={`ipv6-type ${row.ipv6_type || 'link-local'}`}>
                          {row.ipv6_type || 'link-local'}
                        </span>
                        <span style={{ color:'var(--text-muted)', fontSize:10 }}>{row.mac}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {ipv6Hosts.length > 0 && (
                <div className="i-card">
                  <div className="i-card-title"><Globe size={11}/> Discovered IPv6 Hosts ({ipv6Hosts.length})</div>
                  <div className="i-card-body" style={{ padding:'8px 14px' }}>
                    {ipv6Hosts.map((h, i) => (
                      <div key={i} className="ipv6-row">
                        <span className="ipv6-addr">{h.ipv6}</span>
                        <span className={`ipv6-type ${h.ipv6_type}`}>{h.ipv6_type}</span>
                        <span style={{ color:'var(--text-muted)', fontSize:10 }}>{h.mac}</span>
                        {h.hostname && <span style={{ color:'var(--accent)', fontSize:10 }}>{h.hostname}</span>}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {ndpTable.length === 0 && ipv6Hosts.length === 0 && !ipv6Loading && (
                <div style={{ color:'var(--text-muted)', fontSize:12, padding:20, textAlign:'center' }}>
                  Click "Discover IPv6 Hosts" to scan the local network via NDP multicast
                </div>
              )}
            </>
          )}

          {/* ── LLDP/CDP ── */}
          {tab === 'lldp' && (
            <>
              <div style={{ display:'flex', gap:8, alignItems:'center' }}>
                <button className="i-btn primary" onClick={startLldp} disabled={lldpCapturing}>
                  {lldpCapturing ? <RefreshCw size={12} className="animate-spin"/> : <Network size={12}/>}
                  {lldpCapturing ? 'Capturing 30s…' : 'Start LLDP/CDP Capture'}
                </button>
                <span style={{ fontSize:11, color:'var(--text-muted)' }}>Listens passively for LLDP/CDP frames from switches and routers</span>
              </div>

              {lldpNeighbors.length > 0 ? (
                lldpNeighbors.map((n, i) => (
                  <div key={i} className="lldp-neighbor">
                    <div className="lldp-name">
                      {n.system_name || n.chassis_id || n.source_mac}
                      <span style={{ fontSize:9, marginLeft:8, padding:'1px 5px', borderRadius:2, background: n.protocol==='CDP' ? 'rgba(0,212,255,0.15)' : 'rgba(0,230,118,0.1)', color: n.protocol==='CDP' ? 'var(--accent)' : 'var(--green)', fontWeight:700 }}>{n.protocol}</span>
                    </div>
                    <div className="lldp-meta">
                      {n.port_id && <span>Port: {n.port_id}</span>}
                      {n.source_mac && <span>MAC: {n.source_mac}</span>}
                      {n.system_desc && <span style={{ maxWidth:400, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{n.system_desc.substring(0,60)}</span>}
                      <span style={{ color: n.expired ? 'var(--red)' : 'var(--green)' }}>
                        {n.expired ? 'Expired' : `${n.age_secs}s ago`}
                      </span>
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ color:'var(--text-muted)', fontSize:12, padding:20, textAlign:'center' }}>
                  {lldpCapturing ? 'Listening for LLDP/CDP frames…' : 'No LLDP/CDP neighbors yet. Requires managed switches that send LLDP/CDP.'}
                </div>
              )}
            </>
          )}

          {/* ── Packet Capture ── */}
          {tab === 'pcap' && (
            <>
              <div style={{ display:'flex', gap:8, alignItems:'center', flexWrap:'wrap' }}>
                <input className="i-input" value={pcapFilter} onChange={e=>setPcapFilter(e.target.value)}
                  placeholder="BPF filter (e.g. tcp port 80)" style={{ flex:1, minWidth:200 }} />
                {!pcapRunning ? (
                  <button className="i-btn primary" onClick={startPcap}><Play size={12}/> Start Capture</button>
                ) : (
                  <button className="i-btn danger" onClick={stopPcap}><Square size={12}/> Stop</button>
                )}
                {!pcapRunning && packets.length > 0 && (
                  <a href="/api/pcap/download" className="i-btn secondary" style={{ textDecoration:'none' }}>
                    <Download size={12}/> Download .pcap
                  </a>
                )}
              </div>

              {pcapStats && (
                <div className="stats-grid">
                  <div className="stat-box"><div className="stat-box-val">{pcapStats.total_packets?.toLocaleString()}</div><div className="stat-box-key">Packets</div></div>
                  <div className="stat-box"><div className="stat-box-val">{pcapStats.total_bytes ? fmtBytes(pcapStats.total_bytes) : '—'}</div><div className="stat-box-key">Total</div></div>
                  <div className="stat-box"><div className="stat-box-val">{pcapStats.duration_secs}s</div><div className="stat-box-key">Duration</div></div>
                  <div className="stat-box"><div className="stat-box-val">{Object.keys(pcapStats.protocols || {}).length}</div><div className="stat-box-key">Protocols</div></div>
                </div>
              )}

              {packets.length > 0 && (
                <div style={{ background:'var(--bg-2)', border:'1px solid var(--border)', borderRadius:6, overflow:'hidden' }}>
                  <table className="packet-table">
                    <thead>
                      <tr><th>Time</th><th>Proto</th><th>Src</th><th>Dst</th><th>Len</th><th>Info</th></tr>
                    </thead>
                    <tbody>
                      {packets.slice(-50).reverse().map((p, i) => (
                        <tr key={i}>
                          <td style={{ color:'var(--text-muted)' }}>{new Date(p.timestamp*1000).toLocaleTimeString()}</td>
                          <td><span className={`proto-badge proto-${p.protocol}`}>{p.protocol}</span></td>
                          <td style={{ color:'var(--text-primary)' }}>{p.src_ip}{p.src_port ? `:${p.src_port}` : ''}</td>
                          <td style={{ color:'var(--text-secondary)' }}>{p.dst_ip}{p.dst_port ? `:${p.dst_port}` : ''}</td>
                          <td style={{ color:'var(--text-muted)' }}>{p.length}</td>
                          <td style={{ color:'var(--text-muted)', maxWidth:150, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{p.info}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {packets.length === 0 && !pcapRunning && (
                <div style={{ color:'var(--text-muted)', fontSize:12, padding:20, textAlign:'center' }}>
                  Click "Start Capture" to begin packet capture.<br/>
                  <span style={{ fontSize:10 }}>Requires scapy: pip install scapy</span>
                </div>
              )}
            </>
          )}

        </div>
      </div>
    </>
  )
}
