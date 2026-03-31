import React, { useState, useEffect } from 'react'
import { Bell, Plus, Trash2, RefreshCw, Mail, Monitor, AlertTriangle, CheckCircle } from 'lucide-react'

const css = `
.alerts-view { position: absolute; inset: 0; display: flex; flex-direction: column; }
.alerts-header {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 20px; border-bottom: 1px solid var(--border);
  background: var(--bg-1); flex-shrink: 0;
}
.alerts-title { font-size: 13px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); }
.alerts-tabs { display: flex; gap: 4px; padding: 8px 20px; background: var(--bg-1); border-bottom: 1px solid var(--border); flex-shrink: 0; }
.at-tab {
  padding: 5px 14px; border-radius: 4px; font-size: 11px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.06em; cursor: pointer;
  background: var(--bg-3); border: 1px solid var(--border); color: var(--text-muted); transition: all 0.1s;
}
.at-tab.active { background: rgba(0,212,255,0.1); border-color: var(--accent-dim); color: var(--accent); }
.alerts-body { flex: 1; overflow-y: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 12px; }

/* Rules */
.rule-card {
  background: var(--bg-2); border: 1px solid var(--border); border-radius: 5px; padding: 12px 14px;
  display: flex; align-items: center; gap: 12px;
}
.rule-card.disabled { opacity: 0.5; }
.rule-info { flex: 1; }
.rule-name { font-size: 12px; font-weight: 700; color: var(--text-primary); margin-bottom: 3px; }
.rule-meta { font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); display: flex; gap: 10px; }
.rule-channel { display: flex; align-items: center; gap: 3px; font-size: 10px; }
.rule-channel.active { color: var(--accent); }
.rule-channel.inactive { color: var(--text-muted); }

/* History */
.hist-row {
  display: flex; gap: 10px; padding: 7px 12px; border-radius: 3px;
  background: var(--bg-3); border: 1px solid var(--border); margin-bottom: 4px;
}
.hist-time { font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); width: 140px; flex-shrink: 0; }
.hist-type { font-size: 10px; font-weight: 700; text-transform: uppercase; width: 100px; flex-shrink: 0; }
.hist-type.host_down { color: var(--red); }
.hist-type.new_device { color: var(--orange); }
.hist-type.cert_expiry { color: var(--yellow); }
.hist-msg { font-size: 11px; color: var(--text-secondary); flex: 1; }

/* SMTP config */
.smtp-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.smtp-label { font-size: 11px; color: var(--text-muted); margin-bottom: 3px; }
.smtp-input {
  background: var(--bg-3); border: 1px solid var(--border); color: var(--text-primary);
  padding: 7px 10px; border-radius: 4px; font-size: 12px; font-family: var(--font-mono); width: 100%;
}
.smtp-input:focus { border-color: var(--accent-dim); outline: none; }

/* Add rule form */
.add-rule-form {
  background: var(--bg-2); border: 1px solid var(--border); border-radius: 6px; padding: 14px;
}
.form-row { display: flex; gap: 8px; margin-bottom: 8px; flex-wrap: wrap; }
.form-select {
  background: var(--bg-3); border: 1px solid var(--border); color: var(--text-primary);
  padding: 6px 8px; border-radius: 4px; font-size: 12px; font-family: var(--font-mono);
}
.form-input {
  background: var(--bg-3); border: 1px solid var(--border); color: var(--text-primary);
  padding: 6px 10px; border-radius: 4px; font-size: 12px; font-family: var(--font-mono); flex: 1;
}
.form-input:focus { border-color: var(--accent-dim); outline: none; }
.toggle { position: relative; width: 36px; height: 20px; flex-shrink: 0; }
.toggle input { opacity: 0; width: 0; height: 0; }
.toggle-slider { position: absolute; inset: 0; background: var(--bg-4); border-radius: 20px; cursor: pointer; transition: background 0.2s; border: 1px solid var(--border); }
.toggle-slider::before { content: ''; position: absolute; width: 14px; height: 14px; left: 2px; top: 2px; background: var(--text-muted); border-radius: 50%; transition: transform 0.2s, background 0.2s; }
.toggle input:checked + .toggle-slider { background: rgba(0,212,255,0.2); border-color: var(--accent-dim); }
.toggle input:checked + .toggle-slider::before { transform: translateX(16px); background: var(--accent); }
.sv-btn { display: flex; align-items: center; gap: 5px; padding: 6px 14px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; cursor: pointer; border: none; transition: all 0.12s; }
.sv-btn.primary { background: var(--accent); color: var(--bg-0); }
.sv-btn.primary:hover { background: #33ddff; }
.sv-btn.danger { background: rgba(255,61,61,0.1); color: var(--red); border: 1px solid rgba(255,61,61,0.3); }
.sv-btn.secondary { background: var(--bg-3); border: 1px solid var(--border); color: var(--text-secondary); }
.sv-btn.secondary:hover { color: var(--text-primary); }
`

const RULE_TYPES = [
  { value: 'host_down',   label: 'Host Down' },
  { value: 'new_device',  label: 'New Device' },
  { value: 'port_change', label: 'Port Change' },
  { value: 'cert_expiry', label: 'Cert Expiry' },
]

export default function AlertsView() {
  const [tab, setTab]         = useState('rules')
  const [rules, setRules]     = useState([])
  const [history, setHistory] = useState([])
  const [smtp, setSmtp]       = useState({})
  const [smtpDirty, setSmtpDirty] = useState(false)
  const [testSent, setTestSent]   = useState(false)
  const [newRule, setNewRule] = useState({ name:'', rule_type:'host_down', target:'any', threshold:60, notify_macos:true, notify_email:false })

  const load = async () => {
    const [r, h, s] = await Promise.all([
      fetch('/api/alerts/rules').then(x=>x.json()).catch(()=>[]),
      fetch('/api/alerts/history').then(x=>x.json()).catch(()=>[]),
      fetch('/api/alerts/smtp').then(x=>x.json()).catch(()=>({})),
    ])
    setRules(r); setHistory(h); setSmtp(s)
  }

  useEffect(() => { load() }, [])

  const addRule = async () => {
    if (!newRule.name) return
    await fetch('/api/alerts/rules', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(newRule) })
    load()
    setNewRule({ name:'', rule_type:'host_down', target:'any', threshold:60, notify_macos:true, notify_email:false })
  }

  const toggleRule = async (id, enabled) => {
    await fetch(`/api/alerts/rules/${id}`, { method:'PATCH', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ enabled: enabled ? 0 : 1 }) })
    load()
  }

  const deleteRule = async (id) => {
    await fetch(`/api/alerts/rules/${id}`, { method:'DELETE' })
    load()
  }

  const saveSmtp = async () => {
    await fetch('/api/alerts/smtp', { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify(smtp) })
    setSmtpDirty(false)
  }

  const testAlert = async () => {
    await fetch('/api/alerts/test', { method:'POST' })
    setTestSent(true)
    setTimeout(() => setTestSent(false), 3000)
  }

  return (
    <>
      <style>{css}</style>
      <div className="alerts-view">
        <div className="alerts-header">
          <Bell size={14} color="var(--accent)" />
          <span className="alerts-title">Alerts & Notifications</span>
        </div>

        <div className="alerts-tabs">
          {[['rules','Rules'],['history','History'],['smtp','Email Config']].map(([v,l]) => (
            <button key={v} className={`at-tab${tab===v?' active':''}`} onClick={() => setTab(v)}>{l}</button>
          ))}
        </div>

        <div className="alerts-body">

          {/* ── Rules ── */}
          {tab === 'rules' && (
            <>
              {rules.length === 0 && (
                <div style={{ color:'var(--text-muted)', fontSize:12, padding:8 }}>No rules configured.</div>
              )}
              {rules.map(r => (
                <div key={r.id} className={`rule-card${!r.enabled?' disabled':''}`}>
                  <label className="toggle">
                    <input type="checkbox" checked={!!r.enabled} onChange={() => toggleRule(r.id, r.enabled)} />
                    <span className="toggle-slider" />
                  </label>
                  <div className="rule-info">
                    <div className="rule-name">{r.name}</div>
                    <div className="rule-meta">
                      <span>{RULE_TYPES.find(t=>t.value===r.rule_type)?.label || r.rule_type}</span>
                      <span>Target: {r.target}</span>
                      <span>Cooldown: {r.threshold}s</span>
                    </div>
                  </div>
                  <div style={{ display:'flex', gap:8, alignItems:'center' }}>
                    <span className={`rule-channel${r.notify_macos?' active':' inactive'}`}><Monitor size={11} /></span>
                    <span className={`rule-channel${r.notify_email?' active':' inactive'}`}><Mail size={11} /></span>
                  </div>
                  <button className="sv-btn danger" onClick={() => deleteRule(r.id)}><Trash2 size={11} /></button>
                </div>
              ))}

              {/* Add rule */}
              <div className="add-rule-form">
                <div style={{ fontSize:10, fontWeight:700, letterSpacing:'0.1em', textTransform:'uppercase', color:'var(--text-muted)', marginBottom:10 }}>Add Rule</div>
                <div className="form-row">
                  <input className="form-input" value={newRule.name} onChange={e=>setNewRule(p=>({...p,name:e.target.value}))} placeholder="Rule name" />
                  <select className="form-select" value={newRule.rule_type} onChange={e=>setNewRule(p=>({...p,rule_type:e.target.value}))}>
                    {RULE_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                  </select>
                </div>
                <div className="form-row">
                  <input className="form-input" value={newRule.target} onChange={e=>setNewRule(p=>({...p,target:e.target.value}))} placeholder="Target IP or 'any'" style={{maxWidth:180}} />
                  <input className="form-input" type="number" value={newRule.threshold} onChange={e=>setNewRule(p=>({...p,threshold:parseInt(e.target.value)}))} placeholder="Cooldown (s)" style={{maxWidth:100}} />
                  <label style={{ display:'flex', alignItems:'center', gap:5, fontSize:11, color:'var(--text-muted)' }}>
                    <label className="toggle"><input type="checkbox" checked={newRule.notify_macos} onChange={e=>setNewRule(p=>({...p,notify_macos:e.target.checked}))}/><span className="toggle-slider"/></label>
                    macOS
                  </label>
                  <label style={{ display:'flex', alignItems:'center', gap:5, fontSize:11, color:'var(--text-muted)' }}>
                    <label className="toggle"><input type="checkbox" checked={newRule.notify_email} onChange={e=>setNewRule(p=>({...p,notify_email:e.target.checked}))}/><span className="toggle-slider"/></label>
                    Email
                  </label>
                  <button className="sv-btn primary" onClick={addRule}><Plus size={12}/> Add</button>
                </div>
              </div>

              {/* Test */}
              <div style={{ display:'flex', gap:8 }}>
                <button className="sv-btn secondary" onClick={testAlert}>
                  {testSent ? <><CheckCircle size={12}/> Sent!</> : <><Bell size={12}/> Send Test Alert</>}
                </button>
              </div>
            </>
          )}

          {/* ── History ── */}
          {tab === 'history' && (
            <>
              {history.length === 0 && <div style={{ color:'var(--text-muted)', fontSize:12 }}>No alerts fired yet.</div>}
              {history.map((h,i) => (
                <div key={i} className="hist-row">
                  <span className="hist-time">{h.datetime}</span>
                  <span className={`hist-type ${h.rule_type}`}>{h.rule_type?.replace('_',' ')}</span>
                  <span style={{ fontSize:10, color:'var(--text-muted)', width:120, flexShrink:0, fontFamily:'var(--font-mono)' }}>{h.target}</span>
                  <span className="hist-msg">{h.message}</span>
                </div>
              ))}
            </>
          )}

          {/* ── SMTP Config ── */}
          {tab === 'smtp' && (
            <div style={{ background:'var(--bg-2)', border:'1px solid var(--border)', borderRadius:6, padding:16 }}>
              <div style={{ fontSize:10, fontWeight:700, letterSpacing:'0.1em', textTransform:'uppercase', color:'var(--text-muted)', marginBottom:12 }}>SMTP Email Configuration</div>
              <div className="smtp-grid">
                {[
                  ['host','SMTP Host','mail.example.com'],
                  ['port','Port','587'],
                  ['user','Username','alerts@example.com'],
                  ['password','Password',''],
                  ['from','From Address','pulsar@example.com'],
                  ['to','To Address','admin@example.com'],
                ].map(([k,l,p]) => (
                  <div key={k}>
                    <div className="smtp-label">{l}</div>
                    <input className="smtp-input"
                      type={k === 'password' ? 'password' : 'text'}
                      value={smtp[k] || ''} placeholder={p}
                      onChange={e => { setSmtp(s=>({...s,[k]:e.target.value})); setSmtpDirty(true) }} />
                  </div>
                ))}
              </div>
              <div style={{ marginTop:12, display:'flex', gap:8 }}>
                <button className="sv-btn primary" onClick={saveSmtp} disabled={!smtpDirty}>
                  Save SMTP Config
                </button>
                <button className="sv-btn secondary" onClick={testAlert}>
                  {testSent ? '✓ Test sent!' : 'Send Test Email'}
                </button>
              </div>
              <div style={{ marginTop:10, fontSize:10, color:'var(--text-muted)' }}>
                Password is stored encrypted (AES-128). Port 587 = STARTTLS, 465 = SSL.
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  )
}
