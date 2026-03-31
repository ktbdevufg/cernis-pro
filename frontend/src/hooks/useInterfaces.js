import { useState, useEffect } from 'react'

export function useInterfaces() {
  const [interfaces, setInterfaces] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const refresh = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/interfaces')
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setInterfaces(data)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { refresh() }, [])
  return { interfaces, loading, error, refresh }
}
