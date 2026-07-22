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
  startScan: () => ipcRenderer.invoke('start-scan'),
  onScanProgress: (callback: (data: import('./scanner').ScanProgress) => void) => {
    ipcRenderer.on('scan-progress', (_event, data) => callback(data))
  },
})
