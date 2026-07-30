export type ScanMode = 'full' | 'quick' | 'dma' | 'cleaner'

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
    telegramBotToken?: string
    telegramChatId?: string
  }>
  saveConfig: (partial: Partial<{
    apiUrl: string
    tokenId: number | null
    lang: 'ru' | 'en'
    theme: 'predator' | 'ocean' | 'stealth' | 'nebula'
    onboardingComplete: boolean
    telegramBotToken?: string
    telegramChatId?: string
  }>) => Promise<{
    apiUrl: string
    tokenId: number | null
    lang: 'ru' | 'en'
    theme: 'predator' | 'ocean' | 'stealth' | 'nebula'
    onboardingComplete: boolean
    telegramBotToken?: string
    telegramChatId?: string
  }>
  getApiBase: () => Promise<string>
  setApiBase: (url: string) => Promise<string>

  // Tray
  minimizeToTray: () => Promise<void>
  getMinimizeToTray: () => Promise<boolean>
  setMinimizeToTray: (value: boolean) => Promise<boolean>

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
  type: 'file' | 'browser' | 'process' | 'registry' | 'hardware' | 'software' | 'system'
  risk: 'high' | 'medium' | 'low'
  matches: string[]
  size: number
  modifiedAt: string
  /** SHA256 hash of the file (only for HIGH-risk file results) */
  sha256?: string
  /**
   * Auto-tagged finding kind for server-side smart classification.
   * Set by Electron scan-pipeline.ts based on scan mode + result characteristics.
   * Values: 'dma' | 'process' | 'registry' | 'browser' | 'cleaner' | 'file' | 'software' | 'system' | 'memory' | 'network' | 'usb'
   */
  findingKind?: string
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
