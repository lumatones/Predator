import { contextBridge, ipcRenderer } from 'electron'

contextBridge.exposeInMainWorld('electronAPI', {
  getAppVersion: () => ipcRenderer.invoke('get-app-version'),

  // Update events
  onCheckingForUpdate: (callback: () => void) => {
    ipcRenderer.on('checking-for-update', () => callback())
  },
  onUpdateAvailable: (callback: (info: { version: string; url: string }) => void) => {
    ipcRenderer.on('update-available', (_event, info) => callback(info))
  },
  onUpdateNotAvailable: (callback: () => void) => {
    ipcRenderer.on('update-not-available', () => callback())
  },
  onDownloadProgress: (callback: (data: { percent: number; bytesPerSecond: number; total: number; transferred: number }) => void) => {
    ipcRenderer.on('download-progress', (_event, data) => callback(data))
  },
  onUpdateDownloaded: (callback: () => void) => {
    ipcRenderer.on('update-downloaded', () => callback())
  },
  onUpdateError: (callback: (message: string) => void) => {
    ipcRenderer.on('update-error', (_event, message) => callback(message))
  },

  // Actions
  startUpdateCheck: () => ipcRenderer.invoke('start-update-check'),
  startDownload: () => ipcRenderer.invoke('start-download'),
  restartApp: () => ipcRenderer.invoke('restart-app'),
  getPCName: () => ipcRenderer.invoke('get-pc-name'),

  // Scanner
  startScan: (mode?: string, tokenId?: number) => ipcRenderer.invoke('start-scan', mode || 'files', { tokenId }),
  onScanProgress: (callback: (data: import('./types').ScanProgress) => void) => {
    ipcRenderer.on('scan-progress', (_event, data) => callback(data))
  },
  offScanProgress: () => {
    ipcRenderer.removeAllListeners('scan-progress')
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
    ipcRenderer.on('system-snapshot', (_event, data) => callback(data))
  },
  offSystemUpdate: () => {
    ipcRenderer.removeAllListeners('system-snapshot')
  },
})
