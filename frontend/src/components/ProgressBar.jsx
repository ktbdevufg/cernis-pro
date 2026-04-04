import React from 'react'

const css = `
.progress-bar-wrap {
  height: 3px;
  background: var(--bg-3);
  flex-shrink: 0;
  position: relative;
  overflow: hidden;
}
.progress-bar-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--accent-dim), var(--accent));
  transition: width 0.3s ease;
  position: relative;
}
.progress-bar-fill::after {
  content: '';
  position: absolute;
  right: 0; top: 0; bottom: 0;
  width: 40px;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4));
}
.progress-bar-indeterminate {
  height: 100%;
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
  animation: indeterminate 1.4s ease infinite;
  position: absolute;
  width: 40%;
}
@keyframes indeterminate {
  0% { left: -40%; }
  100% { left: 120%; }
}
.progress-status {
  height: 24px;
  background: var(--bg-2);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 0 16px;
  font-size: 11px;
  font-family: var(--font-mono);
  flex-shrink: 0;
}
.progress-phase {
  display: flex; align-items: center; gap: 5px;
  color: var(--text-muted);
}
.progress-phase.active { color: var(--accent); }
.progress-phase.done { color: var(--green); }
.phase-dot {
  width: 5px; height: 5px;
  border-radius: 50%;
  background: currentColor;
}
.phase-dot.active { animation: pulse-dot 0.8s infinite; }
.progress-nums { color: var(--text-muted); margin-left: auto; }
.progress-nums span { color: var(--text-secondary); }
`

export default function ProgressBar({ progress, scanning, done }) {
  const { phase, discovery_pct, discovery_done, discovery_total,
          enrich_pct, enrich_done, enrich_total } = progress

  const phases = [
    { id: 'discovery', label: 'DISCOVERY' },
    { id: 'mdns',      label: 'mDNS/NDI' },
    { id: 'enrich',    label: 'ENRICH' },
  ]

  const getPhaseStatus = (id) => {
    if (!scanning && !done) return 'idle'
    const order = ['discovery', 'mdns', 'enrich', 'done']
    const currentIdx = order.indexOf(phase)
    const phaseIdx = order.indexOf(id)
    if (phase === id) return 'active'
    if (currentIdx > phaseIdx) return 'done'
    return 'idle'
  }

  const barPct = phase === 'discovery' ? discovery_pct
    : phase === 'enrich' ? (50 + enrich_pct * 0.5)
    : done ? 100 : 0

  return (
    <>
      <style>{css}</style>
      {(scanning || done) && (
        <>
          <div className="progress-bar-wrap">
            {scanning && phase === 'mdns' ? (
              <div className="progress-bar-indeterminate" />
            ) : (
              <div className="progress-bar-fill" style={{ width: `${barPct}%` }} />
            )}
          </div>
          <div className="progress-status">
            {phases.map(p => {
              const status = getPhaseStatus(p.id)
              return (
                <div key={p.id} className={`progress-phase ${status}`}>
                  <div className={`phase-dot ${status}`} />
                  {p.label}
                </div>
              )
            })}
            <div className="progress-nums">
              {phase === 'discovery' && discovery_total > 0 && (
                <><span>{discovery_done}</span> / {discovery_total} hosts pinged</>
              )}
              {phase === 'enrich' && enrich_total > 0 && (
                <><span>{enrich_done}</span> / {enrich_total} enriched</>
              )}
              {done && <span style={{ color: 'var(--green)' }}>SCAN COMPLETE</span>}
            </div>
          </div>
        </>
      )}
    </>
  )
}
