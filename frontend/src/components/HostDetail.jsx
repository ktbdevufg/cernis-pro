import React, { useState, useEffect } from 'react'
import { X, Wifi, Server, Globe, Radio, Shield, Zap, Tag, FileText, Save, Power, ExternalLink, AlertTriangle, Lock } from 'lucide-react'

const css = `
.host-detail {
  width: 340px; flex-shrink: 0;
  background: var(--bg-1); border-left: 1px solid var(--border);
  display: flex; flex-direction: column; overflow: hidden;
}
.hd-header {
  display: flex; align-items: center; gap: 8px;
  padding: 11px 14px; border-bottom: 1px solid var(--border);
  background: var(--bg-2); flex-shrink: 0;
}
.hd-ip { font-family: var(--font-mono); font-size: 15px; font-weight: 600; color: var(--accent); flex: 1; }
.hd-close { background: none; color: var(--text-muted); padding: 3px; border-radius: 3px; display: flex; cursor: pointer; }
.hd-close:hover { background: var(--bg-4); color: var(--text-primary); }
.hd-body { flex: 1; overflow-y: auto; padding: 12px 14px; display: flex; flex-direction: column; gap: 14px; }

.hd-section {}
.hd-section-title {
  display: flex; align-items: center; gap: 6px;
  font-size: 9px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--text-muted); margin-bottom: 8px;
  padding-bottom: 5px; border-bottom: 1px solid var(--border);
}
.hd-kv { display: flex; gap: 8px; margin-bottom: 5px; }
.hd-key { color: var(--text-muted); width: 86px; flex-shrink: 0; font-size: 11px; padding-top: 1px; }
.hd-val { color: var(--text-primary); font-family: var(--font-mono); font-size: 11px; word-break: break-all; flex: 1; }
.hd-val.accent { color: var(--accent); }
.hd-val.green  { color: var(--green); }
.hd-val.muted  { color: var(--text-muted); }

.rtt-row { display: flex; align-items: center; gap: 8px; flex: 1; }
.rtt-bar { flex: 1; height: 4px; background: var(--bg-4); border-radius: 2px; overflow: hidden; }
.rtt-bar-fill { height: 100%; border-radius: 2px; transition: width 0.3s; }
.rtt-val { font-family: var(--font-mono); font-size: 11px; white-space: nowrap; }

/* Editable fields */
.hd-editable-field {
  background: var(--bg-3); border: 1px solid var(--border);
  border-radius: 4px; padding: 5px 8px;
  font-size: 12px; font-family: var(--font-mono);
  color: var(--text-primary); width: 100%;
  transition: border-color 0.15s;
}
.hd-editable-field:focus { border-color: var(--accent-dim); outline: none; }
.hd-editable-field::placeholder { color: var(--text-muted); }
.hd-field-row { display: flex; gap: 6px; align-items: center; }
.hd-save-btn {
  display: flex; align-items: center; gap: 4px;
  padding: 5px 10px; border-radius: 4px;
  background: rgba(0,212,255,0.1); border: 1px solid var(--accent-dim);
  color: var(--accent); font-size: 11px; font-weight: 600;
  cursor: pointer; white-space: nowrap; transition: all 0.12s;
  text-transform: uppercase; letter-spacing: 0.06em;
}
.hd-save-btn:hover { background: rgba(0,212,255,0.2); }
.hd-save-btn.saved { background: rgba(0,230,118,0.12); border-color: var(--green); color: var(--green); }

/* Tags input */
.tags-wrap { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; }
.tag-item {
  display: inline-flex; align-items: center; gap: 3px;
  padding: 2px 7px; border-radius: 10px;
  background: rgba(255,224,51,0.1); color: var(--yellow);
  border: 1px solid rgba(255,224,51,0.25); font-size: 11px;
}
.tag-remove { cursor: pointer; opacity: 0.6; line-height: 1; }
.tag-remove:hover { opacity: 1; }
.tag-add-input {
  background: none; border: 1px dashed var(--border);
  border-radius: 10px; padding: 2px 8px;
  color: var(--text-secondary); font-size: 11px;
  font-family: var(--font-mono); width: 90px;
  transition: border-color 0.15s;
}
.tag-add-input:focus { border-color: var(--accent-dim); outline: none; border-style: solid; }
.tag-add-input::placeholder { color: var(--text-muted); }

/* Port list */
.port-list { display: flex; flex-direction: column; gap: 2px; }
.port-item {
  display: flex; align-items: center; gap: 8px;
  padding: 4px 8px; border-radius: 3px; background: var(--bg-3);
}
.port-num { font-family: var(--font-mono); color: var(--accent); width: 44px; flex-shrink: 0; font-weight: 600; font-size: 11px; }
.port-svc { color: var(--text-secondary); flex: 1; font-size: 11px; }
.port-open { font-size: 9px; color: var(--green); font-weight: 700; text-transform: uppercase; }

/* mDNS list */
.svc-list { display: flex; flex-direction: column; gap: 4px; }
.svc-item {
  padding: 6px 8px; border-radius: 3px;
  background: var(--bg-3); border: 1px solid var(--border);
}
.svc-item.ndi { border-color: rgba(255,107,53,0.3); background: rgba(255,107,53,0.05); }
.svc-name { font-size: 11px; color: var(--text-primary); font-family: var(--font-mono); margin-bottom: 2px; }
.svc-type { font-size: 10px; color: var(--text-muted); }
.ndi-badge {
  display: inline-block; padding: 1px 5px; border-radius: 2px;
  background: rgba(255,107,53,0.2); color: var(--ndi);
  font-size: 9px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; margin-left: 5px;
}

/* OS guess */
.os-box {
  padding: 8px 10px; background: var(--bg-3); border-radius: 4px;
  font-size: 11px; font-family: var(--font-mono); color: var(--text-secondary);
  border-left: 2px solid var(--accent-dim);
}
.os-acc { font-size: 10px; color: var(--text-muted); margin-top: 3px; }

/* WoL button */
.wol-btn {
  display: flex; align-items: center; justify-content: center; gap: 6px;
  width: 100%; padding: 8px; border-radius: 4px; cursor: pointer;
  background: rgba(0,230,118,0.08); border: 1px solid rgba(0,230,118,0.25);
  color: var(--green); font-size: 12px; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.08em; transition: all 0.15s;
}
.wol-btn:hover { background: rgba(0,230,118,0.15); box-shadow: 0 0 16px rgba(0,230,118,0.15); }
.wol-btn:disabled { opacity: 0.4; cursor: not-allowed; }
.wol-status { font-size: 10px; text-align: center; margin-top: 4px; font-family: var(--font-mono); }
.wol-status.ok  { color: var(--green); }
.wol-status.err { color: var(--red); }

.empty-detail {
  flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center;
  color: var(--text-muted); gap: 8px; font-size: 12px; padding: 20px; text-align: center;
}
`

function KV({ label, value, cls = '' }) {
  if (!value && value !== 0) return null
  return (
    <div className="hd-kv">
      <span className="hd-key">{label}</span>
      <span className={`hd-val ${cls}`}>{value}</span>
    </div>
  )
}

function RTTBar({ rtt }) {
  if (!rtt || rtt <= 0) return null
  const pct = Math.min(100, (rtt / 200) * 100)
  const color = rtt < 5 ? 'var(--green)' : rtt < 50 ? 'var(--yellow)' : 'var(--orange)'
  return (
    <div className="hd-kv">
      <span className="hd-key">Latency</span>
      <div className="rtt-row">
        <div className="rtt-bar">
          <div className="rtt-bar-fill" style={{ width: `${pct}%`, background: `linear-gradient(90deg, var(--green), ${color})` }} />
        </div>
        <span className="rtt-val" style={{ color }}>{rtt.toFixed(1)} ms</span>
      </div>
    </div>
  )
}



function BannerSection({ host, ports }) {
  const [banners, setBanners] = React.useState(null)
  const [loading, setLoading] = React.useState(false)

  const grab = async () => {
    setLoading(true)
    const res = await fetch('/api/tools/banner', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ host, ports }),
    })
    setBanners(await res.json())
    setLoading(false)
  }

  if (!ports?.some(p => [80,443,8080,8443,8000,3000,9000].includes(p.port))) return null

  return (
    <div className="hd-section">
      <div className="hd-section-title">
        <Globe size={10}/> HTTP Banners
        {!banners && !loading && (
          <button onClick={grab} style={{ marginLeft:'auto', background:'rgba(0,212,255,0.1)', border:'1px solid var(--accent-dim)', color:'var(--accent)', padding:'2px 8px', borderRadius:3, fontSize:9, fontWeight:700, cursor:'pointer', textTransform:'uppercase' }}>
            Grab
          </button>
        )}
        {loading && <span style={{ marginLeft:'auto', fontSize:9, color:'var(--text-muted)' }}>fetching…</span>}
      </div>
      {banners && banners.map((b, i) => (
        <div key={i} style={{ background:'var(--bg-3)', borderRadius:4, padding:'7px 10px', marginBottom:4, fontSize:11 }}>
          <div style={{ display:'flex', justifyContent:'space-between', marginBottom:2 }}>
            <span style={{ fontFamily:'var(--font-mono)', color:'var(--accent)' }}>{b.url}</span>
            <span style={{ fontFamily:'var(--font-mono)', color: b.status < 400 ? 'var(--green)' : 'var(--red)' }}>{b.status}</span>
          </div>
          {b.title && <div style={{ color:'var(--text-primary)', fontWeight:600, marginBottom:2 }}>{b.title}</div>}
          {b.server && <div style={{ color:'var(--text-muted)' }}>Server: {b.server}</div>}
          {b.powered_by && <div style={{ color:'var(--text-muted)' }}>Powered by: {b.powered_by}</div>}
          {b.error && <div style={{ color:'var(--red)', fontSize:10 }}>✗ {b.error}</div>}
        </div>
      ))}
    </div>
  )
}

function DefaultCredsSection({ host, ports, vendor }) {
  const [results, setResults] = React.useState(null)
  const [loading, setLoading] = React.useState(false)

  const check = async () => {
    setLoading(true)
    const res = await fetch('/api/security/default-creds', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ host, ports, vendor }),
    })
    setResults(await res.json())
    setLoading(false)
  }

  if (!ports?.some(p => [80,443,8080,8443,21].includes(p.port))) return null

  return (
    <div className="hd-section">
      <div className="hd-section-title" style={{ color:'var(--orange)' }}>
        <AlertTriangle size={10}/> Default Credentials
        {!results && !loading && (
          <button onClick={check} style={{ marginLeft:'auto', background:'rgba(255,153,0,0.1)', border:'1px solid rgba(255,153,0,0.3)', color:'var(--orange)', padding:'2px 8px', borderRadius:3, fontSize:9, fontWeight:700, cursor:'pointer', textTransform:'uppercase' }}>
            Check
          </button>
        )}
        {loading && <span style={{ marginLeft:'auto', fontSize:9, color:'var(--text-muted)' }}>testing…</span>}
      </div>
      {results && results.length === 0 && (
        <div style={{ fontSize:11, color:'var(--green)', padding:'4px 0' }}>✓ No default credentials found</div>
      )}
      {results && results.map((r, i) => (
        <div key={i} style={{ background:'rgba(255,61,61,0.08)', border:'1px solid rgba(255,61,61,0.3)', borderRadius:4, padding:'7px 10px', marginBottom:4 }}>
          <div style={{ color:'var(--red)', fontWeight:700, fontSize:12 }}>⚠ Default credentials work!</div>
          <div style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--text-secondary)', marginTop:3 }}>
            Port {r.port} · {r.username} / {r.password || '(empty)'} · {r.method}
          </div>
        </div>
      ))}
    </div>
  )
}

function TLSSection({ host, ports }) {
  const [results, setResults] = React.useState(null)
  const [loading, setLoading] = React.useState(false)

  const inspect = async () => {
    setLoading(true)
    const res = await fetch('/api/tls/inspect-host', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, ports }),
    })
    const data = await res.json()
    setResults(data)
    setLoading(false)
  }

  const gradeColor = (g) => ({A:'var(--green)',B:'#88cc44',C:'var(--yellow)',F:'var(--red)'})[g] || 'var(--text-muted)'

  return (
    <div className="hd-section">
      <div className="hd-section-title">
        <Shield size={10} /> TLS / SSL
        {!results && !loading && (
          <button onClick={inspect} style={{ marginLeft:'auto', background:'rgba(0,212,255,0.1)', border:'1px solid var(--accent-dim)', color:'var(--accent)', padding:'2px 8px', borderRadius:3, fontSize:9, fontWeight:700, cursor:'pointer', textTransform:'uppercase' }}>
            Inspect
          </button>
        )}
        {loading && <span style={{ marginLeft:'auto', fontSize:9, color:'var(--text-muted)' }}>checking…</span>}
      </div>
      {results && results.map((r, i) => (
        <div key={i} style={{ background:'var(--bg-3)', borderRadius:4, padding:'8px 10px', marginBottom:6, border:`1px solid ${gradeColor(r.grade)}40` }}>
          <div style={{ display:'flex', justifyContent:'space-between', marginBottom:4 }}>
            <span style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--text-primary)' }}>:{r.port}</span>
            <span style={{ fontFamily:'var(--font-mono)', fontSize:16, fontWeight:700, color:gradeColor(r.grade) }}>{r.grade}</span>
          </div>
          <div style={{ fontSize:10, color:'var(--text-muted)', fontFamily:'var(--font-mono)' }}>{r.tls_version} · {r.cipher_name}</div>
          {r.cert && (
            <div style={{ fontSize:10, color:'var(--text-muted)', marginTop:3 }}>
              {r.cert.subject} · {r.cert.days_remaining > 0 ? <span style={{ color: r.cert.days_remaining < 30 ? 'var(--orange)' : 'var(--green)' }}>{r.cert.days_remaining}d left</span> : <span style={{ color:'var(--red)' }}>EXPIRED</span>}
            </div>
          )}
          {r.warnings?.map((w, j) => (
            <div key={j} style={{ fontSize:10, color:'var(--orange)', marginTop:2 }}>⚠ {w}</div>
          ))}
          {r.error && <div style={{ fontSize:10, color:'var(--red)' }}>✗ {r.error}</div>}
        </div>
      ))}
    </div>
  )
}

export default function HostDetail({ host, onClose }) {
  if (!host) return null

  const sendWoL = async () => {
    if (!host.mac) return
    await fetch('/api/wol/send', { method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ mac: host.mac }) })
  }
  const [label, setLabel]   = useState('')
  const [notes, setNotes]   = useState('')
  const [tags, setTags]     = useState([])
  const [tagInput, setTagInput] = useState('')
  const [saved, setSaved]   = useState(false)
  const [wolStatus, setWolStatus] = useState(null)

  useEffect(() => {
    if (host) {
      setLabel(host.label || '')
      setNotes(host.notes || '')
      setTags(host.tags || [])
      setSaved(false)
      setWolStatus(null)
    }
  }, [host?.ip])

  if (!host) {
    return (
      <>
        <style>{css}</style>
        <div className="host-detail">
          <div className="empty-detail">
            <Server size={32} style={{ opacity: 0.2 }} />
            <span>Select a host to view details</span>
          </div>
        </div>
      </>
    )
  }

  const handleSave = async () => {
    if (!host.mac) return
    await fetch(`/api/devices/${encodeURIComponent(host.mac)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label, notes, tags, is_known: true }),
    })
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const addTag = (e) => {
    if ((e.key === 'Enter' || e.key === ',') && tagInput.trim()) {
      e.preventDefault()
      const t = tagInput.trim().replace(',','')
      if (!tags.includes(t)) setTags(prev => [...prev, t])
      setTagInput('')
    }
  }
  const removeTag = (t) => setTags(prev => prev.filter(x => x !== t))

  const handleWol = async () => {
    if (!host.mac) return
    setWolStatus('sending')
    const res = await fetch('/api/wol', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac: host.mac }),
    })
    const data = await res.json()
    setWolStatus(data.ok ? 'ok' : 'err')
    setTimeout(() => setWolStatus(null), 4000)
  }

  return (
    <>
      <style>{css}</style>
      <div className="host-detail">
        {/* Header */}
        <div className="hd-header">
          <span className="ping-dot alive" />
          <span className="hd-ip">{host.ip}</span>
          {host.is_unknown && (
            <span style={{ fontSize:9, padding:'2px 5px', borderRadius:2, background:'rgba(255,153,0,0.15)', color:'var(--orange)', border:'1px solid rgba(255,153,0,0.3)', fontWeight:700 }}>NEW</span>
          )}
          <button className="hd-close" onClick={onClose}><X size={14} /></button>
        </div>

        <div className="hd-body">

          {/* Identity */}
          <div className="hd-section">
            <div className="hd-section-title"><Wifi size={10} />Identity</div>
            <KV label="Hostname" value={host.hostname} cls="accent" />
            <KV label="MAC"      value={host.mac} />
            <KV label="Vendor"   value={host.vendor} />
            <KV label="SMB Name" value={host.smb_name} />
            <KV label="SMB Dom." value={host.smb_domain} />
            <RTTBar rtt={host.rtt_ms} />
          </div>

          {/* Device info (editable) */}
          <div className="hd-section">
            <div className="hd-section-title"><Tag size={10} />Device Info</div>

            <div style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>Label</div>
              <div className="hd-field-row">
                <input className="hd-editable-field" value={label}
                  onChange={e => setLabel(e.target.value)}
                  placeholder="e.g. NAS, Drucker, TV…" />
              </div>
            </div>

            <div style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>Tags</div>
              <div className="tags-wrap">
                {tags.map(t => (
                  <span key={t} className="tag-item">
                    {t}
                    <span className="tag-remove" onClick={() => removeTag(t)}>×</span>
                  </span>
                ))}
                <input className="tag-add-input" value={tagInput}
                  onChange={e => setTagInput(e.target.value)}
                  onKeyDown={addTag}
                  placeholder="+ add tag" />
              </div>
            </div>

            <div style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>Notes</div>
              <textarea className="hd-editable-field" value={notes}
                onChange={e => setNotes(e.target.value)}
                placeholder="Notes about this device…"
                rows={2} style={{ resize: 'vertical', lineHeight: 1.5 }} />
            </div>

            {host.mac && (
              <button className={`hd-save-btn${saved ? ' saved' : ''}`} onClick={handleSave}>
                <Save size={11} />{saved ? 'Saved!' : 'Save Device Info'}
              </button>
            )}
          </div>

          {/* Wake-on-LAN */}
          {host.mac && (
            <div className="hd-section">
              <div className="hd-section-title"><Power size={10} />Wake-on-LAN</div>
              <button className="wol-btn" onClick={handleWol} disabled={wolStatus === 'sending'}>
                <Zap size={14} />
                {wolStatus === 'sending' ? 'Sending…' : 'Send Magic Packet'}
              </button>
              {wolStatus === 'ok'  && <div className="wol-status ok">✓ Magic packet sent to {host.mac}</div>}
              {wolStatus === 'err' && <div className="wol-status err">✗ Failed — check MAC address</div>}
            </div>
          )}

          {/* OS Detection */}
          {host.os_guess && (
            <div className="hd-section">
              <div className="hd-section-title"><Shield size={10} />OS Detection</div>
              <div className="os-box">
                {host.os_guess}
                {host.os_accuracy > 0 && <div className="os-acc">{host.os_accuracy}% confidence · nmap</div>}
              </div>
            </div>
          )}

          {/* Open Ports */}
          {host.ports && (host.ports || []).length > 0 && (
            <div className="hd-section">
              <div className="hd-section-title"><Globe size={10} />Open Ports ({(host.ports || []).length})</div>
              <div className="port-list">
                {(host.ports || []).map(p => (
                  <div key={p.port} className="port-item">
                    <span className="port-num">{p.port}</span>
                    <span className="port-svc">{p.service || '—'}</span>
                    <span className="port-open">open</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* HTTP Banners */}
          <BannerSection host={host.ip} ports={host.ports} />

          {/* Default Credentials */}
          <DefaultCredsSection host={host.ip} ports={host.ports} vendor={host.vendor} />

          {/* TLS Inspector */}
          {host.ports && host.ports.some(p => [443,8443,4443,9443].includes(p.port) || p.service?.toLowerCase().includes('https')) && (
            <TLSSection host={host.ip} ports={host.ports} />
          )}

          {/* mDNS / NDI */}
          {host.mdns_services && host.mdns_services.length > 0 && (
            <div className="hd-section">
              <div className="hd-section-title"><Radio size={10} />mDNS / Bonjour / NDI ({host.mdns_services.length})</div>
              <div className="svc-list">
                {(host.mdns_services || []).map((s, i) => (
                  <div key={i} className={`svc-item${s.is_ndi ? ' ndi' : ''}`}>
                    <div className="svc-name">
                      {s.name.replace(/\.\w+\.local\.$/, '').substring(0, 40)}
                      {s.is_ndi && <span className="ndi-badge">NDI</span>}
                    </div>
                    <div className="svc-type">
                      {s.type.replace('._tcp.local.','').replace('._udp.local.','')} · :{s.port}
                      {s.hostname && ` · ${s.hostname}`}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* UPnP/SSDP */}
          {host.ssdp_services && host.ssdp_services.length > 0 && (
            <div className="hd-section">
              <div className="hd-section-title"><Server size={10} />UPnP / SSDP ({host.ssdp_services.length})</div>
              <div className="svc-list">
                {(host.ssdp_services || []).map((s, i) => (
                  <div key={i} className="svc-item">
                    <div className="svc-name">{s.server || 'UPnP Device'}</div>
                    <div className="svc-type">{s.st}</div>
                    {s.location && (
                      <a href={s.location} target="_blank" rel="noreferrer"
                        style={{ fontSize:10, color:'var(--accent)', display:'flex', alignItems:'center', gap:3, marginTop:2 }}>
                        <ExternalLink size={9} /> {s.location.substring(0,50)}
                      </a>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>
      </div>
    </>
  )
}
