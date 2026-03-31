import { useState, useRef, useCallback } from 'react'

export const SCAN_STATE = {
  IDLE: 'idle',
  RUNNING: 'running',
  DONE: 'done',
  ERROR: 'error',
}

const initialProgress = {
  phase: '',
  discovery_pct: 0,
  discovery_total: 0,
  discovery_done: 0,
  enrich_pct: 0,
  enrich_total: 0,
  enrich_done: 0,
}

export function useScan() {
  const [scanState, setScanState] = useState(SCAN_STATE.IDLE)
  const [hosts, setHosts] = useState([])          // discovered IPs (partial)
  const [hostDetails, setHostDetails] = useState({}) // ip -> full detail
  const [progress, setProgress] = useState(initialProgress)
  const [error, setError] = useState(null)
  const wsRef = useRef(null)

  const startScan = useCallback((config) => {
    if (wsRef.current) {
      wsRef.current.close()
    }

    setHosts([])
    setHostDetails({})
    setProgress(initialProgress)
    setError(null)
    setScanState(SCAN_STATE.RUNNING)

    // In app mode use injected WS base, otherwise use current host
    let wsUrl
    if (window.CERNIS_WS_BASE) {
      wsUrl = `${window.CERNIS_WS_BASE}/ws/scan`
    } else {
      const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
      wsUrl = `${protocol}://${window.location.host}/ws/scan`
    }
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onopen = () => {
      ws.send(JSON.stringify(config))
    }

    ws.onmessage = (evt) => {
      let msg
      try { msg = JSON.parse(evt.data) } catch { return }

      switch (msg.type) {
        case 'scan_started':
          setProgress(p => ({ ...p, discovery_total: msg.total_hosts }))
          break

        case 'host_found':
          setHosts(prev => {
            if (prev.find(h => h.ip === msg.ip)) return prev
            return [...prev, { ip: msg.ip, mac: msg.mac, vendor: msg.vendor, rtt_ms: msg.rtt_ms }]
          })
          break

        case 'host_detail':
          setHostDetails(prev => ({ ...prev, [msg.ip]: msg }))
          break

        case 'progress':
          if (msg.phase === 'discovery') {
            setProgress(p => ({
              ...p,
              phase: 'discovery',
              discovery_pct: msg.pct,
              discovery_done: msg.completed,
              discovery_total: msg.total,
            }))
          } else if (msg.phase === 'enrich') {
            setProgress(p => ({
              ...p,
              phase: 'enrich',
              enrich_pct: msg.pct,
              enrich_done: msg.completed,
              enrich_total: msg.total,
            }))
          }
          break

        case 'phase':
          setProgress(p => ({ ...p, phase: msg.phase }))
          break

        case 'scan_complete':
          setScanState(SCAN_STATE.DONE)
          setProgress(p => ({ ...p, phase: 'done' }))
          break

        case 'error':
          setError(msg.message)
          setScanState(SCAN_STATE.ERROR)
          break
      }
    }

    ws.onerror = (e) => {
      console.error('WebSocket error:', e)
      // Only show error if scan was still running (not completed)
      setScanState(prev => {
        if (prev === SCAN_STATE.RUNNING) {
          setError('WebSocket connection failed. Is the backend running?')
          return SCAN_STATE.ERROR
        }
        return prev
      })
    }

    ws.onclose = (evt) => {
      // Use functional update to avoid stale closure on scanState
      setScanState(prev => {
        if (prev === SCAN_STATE.RUNNING) return SCAN_STATE.DONE
        return prev
      })
    }
  }, [])

  const stopScan = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close(1000)
      wsRef.current = null
    }
    setScanState(SCAN_STATE.IDLE)
  }, [])

  // Merged host list: combine partial + detailed
  const mergedHosts = hosts.map(h => ({
    ...h,
    ...(hostDetails[h.ip] || {}),
  }))

  return {
    scanState,
    hosts: mergedHosts,
    progress,
    error,
    startScan,
    stopScan,
  }
}
