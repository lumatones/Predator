export interface ElectronAPI {
  getAppVersion: () => Promise<string>

  onCheckingForUpdate: (callback: () => void) => void
  onUpdateAvailable: (callback: (info: { version: string; url: string }) => void) => void
  onUpdateNotAvailable: (callback: () => void) => void
  onDownloadProgress: (callback: (data: { percent: number; bytesPerSecond: number; total: number; transferred: number }) => void) => void
  onUpdateDownloaded: (callback: () => void) => void
  onUpdateError: (callback: (message: string) => void) => void

  startUpdateCheck: () => Promise<{ updateAvailable: boolean; version?: string }>
  startDownload: () => Promise<{ success: boolean; error?: string }>
  restartApp: () => Promise<void>
}

declare global {
  interface Window {
    electronAPI: ElectronAPI
  }
}
