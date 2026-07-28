import { useState, useCallback, useEffect } from 'react'
import type { UpdateModalState } from '../types'

/**
 * Update manager — registers auto-updater IPC listeners on mount,
 * tracks version and update availability, and exposes callbacks for
 * install / restart / dismiss.
 *
 * Extracted from App.tsx (~40 lines) to keep the App component lean.
 */
export function useUpdateManager() {
  const [version, setVersion] = useState('')
  const [updateAvailable, setUpdateAvailable] = useState(false)
  const [updateModal, setUpdateModal] = useState<UpdateModalState>({
    show: false,
    version: '',
    state: 'available',
    percent: 0,
    speed: '',
    size: '',
    errorMsg: '',
  })

  // ── Actions ──
  const hInstallUpdate = useCallback(() => {
    setUpdateModal(p => ({ ...p, state: 'downloading', percent: 0 }))
    window.electronAPI?.startDownload()
  }, [])

  const hRestart = useCallback(() => window.electronAPI?.restartApp(), [])

  const hCloseModal = useCallback(
    () => setUpdateModal(p => ({ ...p, show: false })),
    [],
  )

  // ── Register auto-updater listeners once on mount ──
  useEffect(() => {
    const api = window.electronAPI
    if (!api) return

    // Fetch app version (fast, local)
    try {
      api.getAppVersion().then(setVersion).catch(() => setVersion('unknown'))
    } catch {
      setVersion('unknown')
    }

    // Update available
    try {
      api.onUpdateAvailable(info => {
        setUpdateAvailable(true)
        setUpdateModal(p => ({
          ...p,
          show: true,
          version: info.version,
          state: 'available',
        }))
      })
    } catch {
      /* IPC not available */
    }

    // No update available (silent)
    try {
      api.onUpdateNotAvailable(() => {
        /* nothing to do */
      })
    } catch {
      /* IPC not available */
    }

    // Download progress
    try {
      api.onDownloadProgress(data => {
        setUpdateModal(p => ({
          ...p,
          show: true,
          state: 'downloading',
          percent: data.percent,
          speed:
            data.bytesPerSecond > 0
              ? `${(data.bytesPerSecond / 1024 / 1024).toFixed(1)} MB/s`
              : '',
          size: `${(data.transferred / 1024 / 1024).toFixed(1)} / ${(data.total / 1024 / 1024).toFixed(1)} MB`,
        }))
      })
    } catch {
      /* IPC not available */
    }

    // Download complete
    try {
      api.onUpdateDownloaded(() => {
        setUpdateModal(p => ({ ...p, show: true, state: 'done' }))
      })
    } catch {
      /* IPC not available */
    }

    // Download error
    try {
      api.onUpdateError(msg => {
        setUpdateModal(p => ({ ...p, state: 'error', errorMsg: msg }))
      })
    } catch {
      /* IPC not available */
    }
  }, [])

  return {
    version,
    updateAvailable,
    updateModal,
    hInstallUpdate,
    hRestart,
    hCloseModal,
  } as const
}
