import { useState, useEffect, useCallback, useRef } from 'react'

let _cache = null
let _listeners = []

function notify() { _listeners.forEach(fn => fn(_cache)) }

export function useSettings(key, defaultValue) {
  const [value, setValue] = useState(() => {
    if (_cache && key in _cache) return _cache[key]
    return defaultValue
  })

  useEffect(() => {
    const listener = (cache) => {
      if (key in cache) setValue(cache[key])
    }
    _listeners.push(listener)
    // Initial load
    if (!_cache) {
      fetch('/api/settings')
        .then(r => r.json())
        .then(data => {
          _cache = data
          notify()
        })
        .catch(() => { _cache = {} })
    } else {
      if (key in _cache) setValue(_cache[key])
    }
    return () => { _listeners = _listeners.filter(l => l !== listener) }
  }, [key])

  const set = useCallback(async (newValue) => {
    setValue(newValue)
    if (!_cache) _cache = {}
    _cache[key] = newValue
    notify()
    try {
      await fetch(`/api/settings/${encodeURIComponent(key)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: newValue }),
      })
    } catch (e) {
      console.warn('Settings save failed:', e)
    }
  }, [key])

  return [value, set]
}

export async function saveSettingsBulk(obj) {
  if (!_cache) _cache = {}
  Object.assign(_cache, obj)
  notify()
  await fetch('/api/settings', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(obj),
  })
}
