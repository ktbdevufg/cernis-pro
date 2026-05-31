import React, { useState } from 'react'
import { Settings, X } from 'lucide-react'

const css = `
.settings-overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,0.6);
  z-index: 500; display: flex; align-items: center; justify-content: center;
}
.settings-panel {
  background: var(--bg-2); border: 1px solid var(--border-bright);
  border-radius: 8px; width: 480px; max-height: 85vh; overflow-y: auto;
  box-shadow: 0 24px 64px rgba(0,0,0,0.8);
}
.sp-header {
  display: flex; align-items: center; gap: 8px;
  padding: 14px 20px; border-bottom: 1px solid var(--border);
  font-size: 13px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--accent);
}
.sp-close { margin-left: auto; background: none; color: var(--text-muted); padding: 4px; border-radius: 4px; display: flex; cursor: pointer; }
.sp-close:hover { color: var(--text-primary); background: var(--bg-4); }
.sp-section { padding: 14px 20px; border-bottom: 1px solid var(--border); }
.sp-section:last-of-type { border-bottom: none; }
.sp-section-title {
  font-size: 9px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--text-muted); margin-bottom: 12px;
}
.sp-row { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }
.sp-row:last-child { margin-bottom: 0; }
.sp-label { color: var(--text-secondary); font-size: 13px; flex: 1; }
.sp-label small { display: block; font-size: 10px; color: var(--text-muted); margin-top: 1px; font-family: var(--font-mono); }
.toggle { position: relative; width: 36px; height: 20px; flex-shrink: 0; }
.toggle input { opacity: 0; width: 0; height: 0; }
.toggle-slider {
  position: absolute; inset: 0; background: var(--bg-4); border-radius: 20px; cursor: pointer;
  transition: background 0.2s; border: 1px solid var(--border);
}
.toggle-slider::before {
  content: ''; position: absolute; width: 14px; height: 14px; left: 2px; top: 2px;
  background: var(--text-muted); border-radius: 50%; transition: transform 0.2s, background 0.2s;
}
.toggle input:checked + .toggle-slider { background: rgba(0,212,255,0.2); border-color: var(--accent-dim); }
.toggle input:checked + .toggle-slider::before { transform: translateX(16px); background: var(--accent); }
.num-input {
  background: var(--bg-3); border: 1px solid var(--border); color: var(--text-primary);
  padding: 4px 8px; border-radius: 4px; font-size: 12px; font-family: var(--font-mono);
  width: 80px; text-align: right;
}
.num-input:focus { border-color: var(--accent-dim); }
.radio-group { display: flex; gap: 6px; }
.radio-opt {
  display: flex; align-items: center; gap: 4px; padding: 4px 10px; border-radius: 4px;
  border: 1px solid var(--border); background: var(--bg-3); color: var(--text-secondary);
  font-size: 11px; cursor: pointer; transition: all 0.12s; font-family: var(--font-mono);
}
.radio-opt.active { border-color: var(--accent-dim); background: rgba(0,212,255,0.08); color: var(--accent); }
.sp-footer { display: flex; align-items: center; justify-content: flex-end; gap: 8px; padding: 12px 20px; border-top: 1px solid var(--border); }
.btn-cancel {
  background: var(--bg-3); border: 1px solid var(--border); color: var(--text-secondary);
  padding: 7px 16px; border-radius: 4px; font-size: 12px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.06em; cursor: pointer;
}
.btn-cancel:hover { background: var(--bg-4); }
.btn-apply {
  background: var(--accent); color: var(--bg-0); padding: 7px 18px; border-radius: 4px;
  font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; cursor: pointer;
}
.btn-apply:hover { background: #33ddff; }
.settings-btn {
  display: flex; align-items: center; gap: 5px;
  background: var(--bg-3); border: 1px solid var(--border); color: var(--text-secondary);
  padding: 6px 12px; border-radius: 4px; font-size: 12px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.06em; cursor: pointer; transition: all 0.12s;
}
.settings-btn:hover { border-color: var(--border-bright); color: var(--text-primary); }
`

export const DEFAULT_CONFIG = {
  ping_timeout: 1.0,
  port_scan: true,
  port_mode: 'socket',
  mdns_scan: true,
  mdns_duration: 5.0,
  ssdp_scan: true,
  resolve_hostnames: true,
  smb_scan: false,
  max_concurrent_ping: 64,
  max_concurrent_ports: 100,
}

export default function ScanSettings({ config, onChange }) {
  const [open, setOpen] = useState(false)
  const [local, setLocal] = useState({ ...DEFAULT_CONFIG, ...config })
  const set = (k, v) => setLocal(c => ({ ...c, [k]: v }))

  const apply = () => { onChange({ ...DEFAULT_CONFIG, ...local }); setOpen(false) }

  const Toggle = ({ k }) => (
    <label className="toggle">
      <input type="checkbox" checked={!!local[k]} onChange={e => set(k, e.target.checked)} />
      <span className="toggle-slider" />
    </label>
  )
  const Num = ({ k, min, max, step }) => (
    <input className="num-input" type="number" min={min} max={max} step={step}
      value={local[k]} onChange={e => set(k, parseFloat(e.target.value))} />
  )

  return (
    <>
      <style>{css}</style>
      <button className="settings-btn" onClick={() => { setLocal({ ...DEFAULT_CONFIG, ...config }); setOpen(true) }}>
        <Settings size={13} /> Settings
      </button>

      {open && (
        <div className="settings-overlay" onClick={e => e.target === e.currentTarget && setOpen(false)}>
          <div className="settings-panel">
            <div className="sp-header">
              <Settings size={15} /> Scan Settings
              <button className="sp-close" onClick={() => setOpen(false)}><X size={15} /></button>
            </div>

            {/* Discovery */}
            <div className="sp-section">
              <div className="sp-section-title">Host Discovery</div>
              <div className="sp-row">
                <div className="sp-label">Ping Timeout (s)<small>Lower = faster, less reliable</small></div>
                <Num k="ping_timeout" min={0.2} max={5} step={0.1} />
              </div>
              <div className="sp-row">
                <div className="sp-label">Concurrent Pings<small>Max parallel pings (default 64)</small></div>
                <Num k="max_concurrent_ping" min={8} max={254} step={8} />
              </div>
              <div className="sp-row">
                <div className="sp-label">Hostname Resolution<small>Reverse DNS per host</small></div>
                <Toggle k="resolve_hostnames" />
              </div>
              <div className="sp-row">
                <div className="sp-label">NetBIOS / SMB Names<small>Requires nmblookup — slower</small></div>
                <Toggle k="smb_scan" />
              </div>
            </div>

            {/* Port Scan */}
            <div className="sp-section">
              <div className="sp-section-title">Port Scanning</div>
              <div className="sp-row">
                <div className="sp-label">Enabled</div>
                <Toggle k="port_scan" />
              </div>
              <div className="sp-row">
                <div className="sp-label">Scan Mode<small>socket = fast async · nmap = deep + OS</small></div>
                <div className="radio-group">
                  {['socket','nmap'].map(m => (
                    <button key={m} className={`radio-opt${local.port_mode === m ? ' active' : ''}`}
                      onClick={() => set('port_mode', m)}>{m}</button>
                  ))}
                </div>
              </div>
              <div className="sp-row">
                <div className="sp-label">Concurrent Port Checks</div>
                <Num k="max_concurrent_ports" min={20} max={500} step={20} />
              </div>
            </div>

            {/* Service Discovery */}
            <div className="sp-section">
              <div className="sp-section-title">Service Discovery</div>
              <div className="sp-row">
                <div className="sp-label">mDNS / Bonjour / NDI<small>Discovers AirPlay, NDI, printers…</small></div>
                <Toggle k="mdns_scan" />
              </div>
              <div className="sp-row">
                <div className="sp-label">mDNS Duration (s)<small>Listen time for mDNS responses</small></div>
                <Num k="mdns_duration" min={2} max={30} step={1} />
              </div>
              <div className="sp-row">
                <div className="sp-label">UPnP / SSDP<small>Smart TVs, routers, NAS devices</small></div>
                <Toggle k="ssdp_scan" />
              </div>
            </div>

            <div className="sp-footer">
              <button className="btn-cancel" onClick={() => setOpen(false)}>Cancel</button>
              <button className="btn-apply" onClick={apply}>Apply</button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
