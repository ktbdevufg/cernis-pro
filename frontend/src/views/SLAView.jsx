import React, { useState, useEffect } from 'react'
import { TrendingUp, RefreshCw, Clock } from 'lucide-react'

const css = `
.sla-view { position: absolute; inset: 0; display: flex; flex-direction: column; }
.sla-header {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 20px; border-bottom: 1px solid var(--border);
  background: var(--bg-1); flex-shrink: 0;
}
.sla-title { font-size: 13px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); }
.sla-body { flex: 1; overflow-y: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 14px; }

.sla-card {
  background: var(--bg-2); border: 1px solid var(--border); border-radius: 6px; overflow: hidden;
}
.sla-card-header {
  display: flex; align-items: center; gap: 10px; padding: 12px 16px;
  border-bottom: 1px solid var(--border); background: var(--bg-3);
}
.sla-label { font-size: 12px; font-weight: 700; color: var(--text-primary); flex: 1; }
.sla-host  { font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); }

.sla-metrics { display: flex; gap: 0; border-bottom: 1px solid var(--border); }
.sla-metric {
  flex: 1; padding: 12px 16px; border-right: 1px solid var(--border); text-align: center;
}
.sla-metric:last-child { border-right: none; }
.sla-metric-val { font-size: 22px; font-weight: 700; font-family: var(--font-mono); line-height: 1; margin-bottom: 4px; }
.sla-metric-val.excellent { color: var(--green); }
.sla-metric-val.good      { color: #88cc44; }
.sla-metric-val.fair      { color: var(--yellow); }
.sla-metric-val.poor      { color: var(--red); }
.sla-metric-label { font-size: 9px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-muted); }

/* Uptime chart */
.sla-chart { padding: 12px 16px; }
.sla-chart-title { font-size: 9px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-muted); margin-bottom: 8px; }
.sla-chart svg { width: 100%; height: 60px; }
.uptime-bar-row { display: flex; gap: 1px; height: 24px; align-items: flex-end; }
.uptime-bar {
  flex: 1; border-radius: 1px;
  transition: opacity 0.1s;
  cursor: pointer;
  min-width: 2px;
}
.uptime-bar:hover { opacity: 0.7; }

.sla-no-data { padding: 20px; text-align: center; color: var(--text-muted); font-size: 12px; }

/* Days selector */
.days-select {
  background: var(--bg-3); border: 1px solid var(--border);
  color: var(--text-secondary); padding: 4px 8px; border-radius: 4px;
  font-size: 11px; font-family: var(--font-mono); cursor: pointer;
}
`

function uptimeColor(pct) {
  if (pct >= 99.9) return 'var(--green)'
  if (pct >= 99)   return '#88cc44'
  if (pct >= 95)   return 'var(--yellow)'
  return 'var(--red)'
}

function uptimeClass(pct) {
  if (pct >= 99.9) return 'excellent'
  if (pct >= 99)   return 'good'
  if (pct >= 95)   return 'fair'
  return 'poor'
}

function UptimeBars({ chart }) {
  if (!chart || chart.length === 0) return null
  const [tooltip, setTooltip] = useState(null)

  return (
    <div style={{ position: 'relative' }}>
      <div className="uptime-bar-row">
        {chart.slice(-120).map((h, i) => (
          <div
            key={i}
            className="uptime-bar"
            style={{
              height: `${Math.max(10, h.uptime_pct)}%`,
              background: uptimeColor(h.uptime_pct),
              opacity: h.uptime_pct < 100 ? 0.9 : 0.6,
            }}
            onMouseEnter={() => setTooltip(h)}
            onMouseLeave={() => setTooltip(null)}
          />
        ))}
      </div>
      {tooltip && (
        <div style={{
          position: 'absolute', bottom: 'calc(100% + 6px)', left: '50%',
          transform: 'translateX(-50%)',
          background: 'var(--bg-4)', border: '1px solid var(--border-bright)',
          borderRadius: 4, padding: '4px 8px', fontSize: 10,
          fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap', zIndex: 10,
          color: 'var(--text-primary)',
        }}>
          {tooltip.datetime} · {tooltip.uptime_pct}% · {tooltip.avg_rtt_ms}ms
        </div>
      )}
    </div>
  )
}

export default function SLAView() {
  const [stats, setStats]   = useState([])
  const [days, setDays]     = useState(7)
  const [loading, setLoading] = useState(true)

  const load = async () => {
    setLoading(true)
    const data = await fetch(`/api/sla?days=${days}`).then(r => r.json()).catch(() => [])
    setStats(data)
    setLoading(false)
  }

  useEffect(() => { load() }, [days])

  return (
    <>
      <style>{css}</style>
      <div className="sla-view">
        <div className="sla-header">
          <TrendingUp size={14} color="var(--accent)" />
          <span className="sla-title">SLA / Uptime Tracking</span>
          <select className="days-select" value={days} onChange={e => setDays(Number(e.target.value))} style={{ marginLeft:'auto' }}>
            <option value={1}>Last 24h</option>
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
          </select>
          <button onClick={load} style={{ background:'none', border:'none', color:'var(--text-muted)', cursor:'pointer', marginLeft:4 }}>
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>

        <div className="sla-body">
          {stats.length === 0 && !loading && (
            <div style={{ textAlign:'center', color:'var(--text-muted)', padding:40, fontSize:13 }}>
              <Clock size={32} style={{ opacity:0.2, marginBottom:8 }} />
              <div>No SLA data yet</div>
              <div style={{ fontSize:11, marginTop:4 }}>Monitor targets are tracked automatically once the monitor is running</div>
            </div>
          )}

          {stats.filter(s => s.samples > 0).map(s => (
            <div key={s.target_id} className="sla-card">
              <div className="sla-card-header">
                <div>
                  <div className="sla-label">{s.target_id}</div>
                  <div className="sla-host">{s.samples} samples over {s.days} days</div>
                </div>
              </div>

              <div className="sla-metrics">
                <div className="sla-metric">
                  <div className={`sla-metric-val ${s.uptime_pct !== null ? uptimeClass(s.uptime_pct) : ''}`}>
                    {s.uptime_pct !== null ? `${s.uptime_pct.toFixed(2)}%` : '—'}
                  </div>
                  <div className="sla-metric-label">Uptime</div>
                </div>
                <div className="sla-metric">
                  <div className="sla-metric-val" style={{ color: s.downtime_mins > 60 ? 'var(--red)' : s.downtime_mins > 5 ? 'var(--yellow)' : 'var(--green)', fontSize: 18 }}>
                    {s.downtime_mins > 60
                      ? `${(s.downtime_mins/60).toFixed(1)}h`
                      : `${s.downtime_mins}m`}
                  </div>
                  <div className="sla-metric-label">Downtime</div>
                </div>
                <div className="sla-metric">
                  <div className="sla-metric-val" style={{ color: s.avg_rtt_ms < 5 ? 'var(--green)' : s.avg_rtt_ms < 50 ? 'var(--yellow)' : 'var(--red)', fontSize: 18 }}>
                    {s.avg_rtt_ms > 0 ? `${s.avg_rtt_ms}ms` : '—'}
                  </div>
                  <div className="sla-metric-label">Avg RTT</div>
                </div>
                <div className="sla-metric">
                  <div className="sla-metric-val" style={{ fontSize:18, color:'var(--text-secondary)' }}>
                    {s.samples.toLocaleString()}
                  </div>
                  <div className="sla-metric-label">Samples</div>
                </div>
              </div>

              {s.chart && s.chart.length > 0 && (
                <div className="sla-chart">
                  <div className="sla-chart-title">Hourly Uptime — last {s.days} days</div>
                  <UptimeBars chart={s.chart} />
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </>
  )
}
