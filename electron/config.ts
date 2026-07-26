import { app } from 'electron'
import fs from 'fs'
import os from 'os'
import path from 'path'

export type AppLang = 'ru' | 'en'
export type AppTheme = 'predator' | 'ocean' | 'stealth' | 'nebula'

export interface PredatorConfig {
  apiUrl: string
  tokenId: number | null
  lang: AppLang
  theme: AppTheme
  onboardingComplete: boolean
}

// ── System paths (single source of truth) ──

export const CFG = {
  PF: process.env.ProgramFiles || 'C:\\Program Files',
  PF86: process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)',
  WR: process.env.SystemRoot || 'C:\\Windows',
  HOME: os.homedir(),
  PD: process.env.ProgramData || 'C:\\ProgramData',
}

const DEFAULT_CONFIG: PredatorConfig = {
  apiUrl: 'http://localhost:3001',
  tokenId: null,
  lang: 'ru',
  theme: 'predator',
  onboardingComplete: false,
}

function configFilePath(): string {
  return path.join(app.getPath('userData'), 'predator-config.json')
}

export function loadConfig(): PredatorConfig {
  const envUrl = process.env.PREDATOR_API_URL
  let stored: Partial<PredatorConfig> = {}
  try {
    const raw = fs.readFileSync(configFilePath(), 'utf-8')
    stored = JSON.parse(raw) as Partial<PredatorConfig>
  } catch { /* no config yet */ }

  const cfg: PredatorConfig = { ...DEFAULT_CONFIG, ...stored }
  if (envUrl) cfg.apiUrl = envUrl
  return cfg
}

export function saveConfig(partial: Partial<PredatorConfig>): PredatorConfig {
  const next = { ...loadConfig(), ...partial }
  fs.mkdirSync(path.dirname(configFilePath()), { recursive: true })
  fs.writeFileSync(configFilePath(), JSON.stringify(next, null, 2))
  return next
}

export function getApiBase(): string {
  return loadConfig().apiUrl.replace(/\/$/, '')
}

/** Parsed host/port for Node http module */
export function getApiEndpoint(): { hostname: string; port: number; protocol: 'http:' | 'https:' } {
  const url = new URL(getApiBase())
  const port = url.port
    ? parseInt(url.port, 10)
    : url.protocol === 'https:' ? 443 : 80
  return {
    hostname: url.hostname,
    port,
    protocol: url.protocol as 'http:' | 'https:',
  }
}
