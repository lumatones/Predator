/**
 * Predator — IPC Handler Functions
 *
 * Pure handler logic extracted from main.ts's ipcMain.handle() wrappers.
 * These are testable without mocking the entire Electron runtime.
 *
 * main.ts just wires them: ipcMain.handle('get-config', async () => handleGetConfig())
 */

import os from 'os'
import { loadConfig, saveConfig, getApiBase } from './config'
import type { PredatorConfig } from './config'

// ═══════════════════════════════════════════════════
// Config handlers
// ═══════════════════════════════════════════════════

export async function handleGetConfig(): Promise<PredatorConfig> {
  return loadConfig()
}

export async function handleSaveConfig(partial: unknown): Promise<PredatorConfig> {
  if (!partial || typeof partial !== 'object') return loadConfig()
  return saveConfig(partial as Partial<PredatorConfig>)
}

export async function handleGetApiBase(): Promise<string> {
  return getApiBase()
}

export function handleSetApiBase(url: unknown): string {
  if (!url || typeof url !== 'string') return getApiBase()
  try {
    const parsed = new URL(url.trim().replace(/\/$/, ''))
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return getApiBase()
    const clean = parsed.toString().replace(/\/$/, '')
    saveConfig({ apiUrl: clean })
    return clean
  } catch {
    return getApiBase()
  }
}

// ═══════════════════════════════════════════════════
// System info handlers
// ═══════════════════════════════════════════════════

export function handleGetPcName(): string {
  try {
    return os.userInfo().username || process.env.USERNAME || 'unknown'
  } catch {
    return process.env.USERNAME || 'unknown'
  }
}

// ═══════════════════════════════════════════════════
// Tray handlers
// ═══════════════════════════════════════════════════

export function handleGetMinimizeToTray(currentValue: boolean): boolean {
  return currentValue
}

export function handleSetMinimizeToTray(value: unknown): boolean {
  return !!value
}
