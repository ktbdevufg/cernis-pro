import { useEffect } from 'react'

/**
 * CERNIS PRO Keyboard Shortcuts
 * Space     → Start/Stop scan
 * F         → Focus filter input
 * R         → Refresh current view
 * T         → Switch to Topology view
 * M         → Switch to Monitor view
 * Escape    → Close sidebars/modals
 * 1-9       → Switch views by index
 * ?         → Show shortcut help
 */

const SHORTCUTS = [
  { key: ' ',       description: 'Start / Stop scan',     action: 'scan_toggle' },
  { key: 'f',       description: 'Focus filter',          action: 'focus_filter' },
  { key: 'r',       description: 'Refresh',               action: 'refresh' },
  { key: 't',       description: 'Topology view',         action: 'view_topology' },
  { key: 'm',       description: 'Monitor view',          action: 'view_monitor' },
  { key: 'g',       description: 'FritzBox view',         action: 'view_fritz' },
  { key: 's',       description: 'Security view',         action: 'view_security' },
  { key: 'Escape',  description: 'Close panel',           action: 'close' },
  { key: '?',       description: 'Show shortcuts',        action: 'help' },
]

export function getShortcutsList() {
  return SHORTCUTS
}

export default function useKeyboardShortcuts({
  onScanToggle,
  onViewChange,
  onClose,
  scanning,
}) {
  useEffect(() => {
    const handler = (e) => {
      // Skip if typing in an input
      const tag = document.activeElement?.tagName?.toLowerCase()
      if (['input', 'textarea', 'select'].includes(tag)) return
      if (e.ctrlKey || e.metaKey || e.altKey) return

      switch (e.key) {
        case ' ':
          e.preventDefault()
          onScanToggle?.()
          break
        case 'f':
        case 'F':
          e.preventDefault()
          document.querySelector('input[placeholder*="Filter"], input[placeholder*="filter"]')?.focus()
          break
        case 't':
          onViewChange?.('topology')
          break
        case 'm':
          onViewChange?.('monitor')
          break
        case 'g':
          onViewChange?.('fritz')
          break
        case 's':
          onViewChange?.('security')
          break
        case 'd':
          onViewChange?.('devices')
          break
        case 'i':
          onViewChange?.('infra')
          break
        case 'Escape':
          onClose?.()
          break
        case '?':
          // Show shortcut overlay — dispatch custom event
          window.dispatchEvent(new CustomEvent('cernis:show-shortcuts'))
          break
        default:
          break
      }
    }

    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onScanToggle, onViewChange, onClose, scanning])
}
