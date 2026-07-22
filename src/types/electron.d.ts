export type ScanMode = 'files' | 'processes' | 'cheats' | 'dma' | 'extended' | 'network'

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
  getPCName: () => Promise<string>

  // Scanner
  startScan: (mode?: ScanMode) => Promise<ScanResponse>
  onScanProgress: (callback: (data: ScanProgress) => void) => void

  // System info dashboard
  getSystemSnapshot: () => Promise<SystemInfoSnapshot>
}

export interface ScanResult {
  path: string
  fileName: string
  type: 'file' | 'browser' | 'process' | 'registry' | 'hardware' | 'software'
  risk: 'high' | 'medium' | 'low'
  matches: string[]
  size: number
  modifiedAt: string
}

export interface ScanProgress {
  phase: 'scanning' | 'analyzing' | 'done'
  currentDir: string
  filesFound: number
  filesScanned: number
  totalDirs: number
  dirsDone: number
}

export interface ScanResponse {
  results: ScanResult[]
  summary: {
    totalScanned: number
    suspiciousFiles: number
    highRiskCount: number
    scanTimeMs: number
  }
}

export interface SystemProcess {
  pid: number
  name: string
  memoryMB: number
  cpuPercent: number
}

export interface SystemInfoSnapshot {
  cpu: {
    usagePercent: number
    cores: number
    model: string
    loadAvg: number[]
  }
  memory: {
    totalGB: number
    usedGB: number
    freeGB: number
    usagePercent: number
  }
  temperature: number | null
  uptime: {
    days: number
    hours: number
    minutes: number
  }
  os: {
    platform: string
    release: string
    arch: string
    hostname: string
  }
  processes: SystemProcess[]
  timestamp: number
}

declare global {
  interface Window {
    electronAPI: ElectronAPI
  }
}
