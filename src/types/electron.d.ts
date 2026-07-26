export type ScanMode = 'full' | 'quick' | 'dma'

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

  getConfig: () => Promise<{
    apiUrl: string
    tokenId: number | null
    lang: 'ru' | 'en'
    theme: 'predator' | 'ocean' | 'stealth' | 'nebula'
    onboardingComplete: boolean
  }>
  saveConfig: (partial: Partial<{
    apiUrl: string
    tokenId: number | null
    lang: 'ru' | 'en'
    theme: 'predator' | 'ocean' | 'stealth' | 'nebula'
    onboardingComplete: boolean
  }>) => Promise<{
    apiUrl: string
    tokenId: number | null
    lang: 'ru' | 'en'
    theme: 'predator' | 'ocean' | 'stealth' | 'nebula'
    onboardingComplete: boolean
  }>
  getApiBase: () => Promise<string>
  setApiBase: (url: string) => Promise<string>

  // Scanner
  startScan: (mode?: ScanMode, tokenId?: number) => Promise<ScanResponse>
  onScanProgress: (callback: (data: ScanProgress) => void) => (() => void)
  offScanProgress?: (unsubscribe?: () => void) => void

  // System info dashboard
  getSystemSnapshot: () => Promise<SystemInfoSnapshot>

  // System info streaming (replaces polling)
  startSystemStream: (intervalMs?: number) => void
  stopSystemStream: () => void
  onSystemUpdate: (callback: (data: SystemInfoSnapshot) => void) => (() => void)
  offSystemUpdate?: (unsubscribe?: () => void) => void
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
