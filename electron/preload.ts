import { contextBridge, ipcRenderer } from 'electron'

function makeListener<T>(channel: string, callback: (data: T) => void) {
  const listener = (_event: unknown, data: T) => callback(data)
  ipcRenderer.on(channel, listener)
  return () => ipcRenderer.removeListener(channel, listener)
}

contextBridge.exposeInMainWorld('electronAPI', {
  getAppVersion: () => ipcRenderer.invoke('get-app-version'),

  // Update events
  onCheckingForUpdate: (callback: () => void) => {
    const listener = () => callback()
    ipcRenderer.on('checking-for-update', listener)
    return () => ipcRenderer.removeListener('checking-for-update', listener)
  },
  onUpdateAvailable: (callback: (info: { version: string; url: string }) => void) => {
    return makeListener('update-available', callback)
  },
  onUpdateNotAvailable: (callback: () => void) => {
    const listener = () => callback()
    ipcRenderer.on('update-not-available', listener)
    return () => ipcRenderer.removeListener('update-not-available', listener)
  },
  onDownloadProgress: (callback: (data: { percent: number; bytesPerSecond: number; total: number; transferred: number }) => void) => {
    return makeListener('download-progress', callback)
  },
  onUpdateDownloaded: (callback: () => void) => {
    const listener = () => callback()
    ipcRenderer.on('update-downloaded', listener)
    return () => ipcRenderer.removeListener('update-downloaded', listener)
  },
  onUpdateError: (callback: (message: string) => void) => {
    return makeListener('update-error', callback)
  },

  // Actions
  startUpdateCheck: () => ipcRenderer.invoke('start-update-check'),
  startDownload: () => ipcRenderer.invoke('start-download'),
  restartApp: () => ipcRenderer.invoke('restart-app'),
  getPCName: () => ipcRenderer.invoke('get-pc-name'),

  // Config / API URL
  getConfig: () => ipcRenderer.invoke('get-config'),
  saveConfig: (partial: Record<string, unknown>) => ipcRenderer.invoke('save-config', partial),
  getApiBase: () => ipcRenderer.invoke('get-api-base'),
  setApiBase: (url: string) => ipcRenderer.invoke('set-api-base', url),

  // Tray
  minimizeToTray: () => ipcRenderer.invoke('minimize-to-tray'),
  getMinimizeToTray: () => ipcRenderer.invoke('get-minimize-to-tray'),
  setMinimizeToTray: (value: boolean) => ipcRenderer.invoke('set-minimize-to-tray', value),

  // Scanner
  startScan: (mode?: string, tokenId?: number) => ipcRenderer.invoke('start-scan', mode || 'quick', { token_id: tokenId }),
  onScanProgress: (callback: (data: import('./types').ScanProgress) => void) => {
    return makeListener('scan-progress', callback)
  },
  offScanProgress: (unsubscribe?: () => void) => {
    if (typeof unsubscribe === 'function') unsubscribe()
  },

  // System info dashboard
  getSystemSnapshot: () => ipcRenderer.invoke('get-system-snapshot'),

  // System info streaming (replaces polling)
  startSystemStream: (intervalMs: number) => {
    ipcRenderer.send('start-system-stream', intervalMs)
  },
  stopSystemStream: () => {
    ipcRenderer.send('stop-system-stream')
  },
  onSystemUpdate: (callback: (data: import('./system-info').SystemInfoSnapshot) => void) => {
    return makeListener('system-snapshot', callback)
  },
  offSystemUpdate: (unsubscribe?: () => void) => {
    if (typeof unsubscribe === 'function') unsubscribe()
  },
})
