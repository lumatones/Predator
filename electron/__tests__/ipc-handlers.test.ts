/**
 * Predator — IPC Handler Integration Tests
 *
 * Tests all extracted IPC handler functions:
 *   - Config handlers (get, save, API base)
 *   - System info handlers (PC name, app version)
 *   - Tray handlers (minimize-to-tray)
 *   - Scan handlers (cancel-scan)
 *
 * All Electron dependencies are mocked — no runtime required.
 * 20+ tests covering happy paths, edge cases, and error handling.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import path from 'path'
import fs from 'fs'
import os from 'os'

// ═══════════════════════════════════════════════════
// MOCKS (set up BEFORE importing modules under test)
// ═══════════════════════════════════════════════════

const MOCK_USER_DATA = '/tmp/predator-test-ipc'
const CONFIG_PATH = path.join(MOCK_USER_DATA, 'predator-config.json')

vi.mock('electron', () => ({
  app: {
    getPath: vi.fn((key: string) => {
      if (key === 'userData') return MOCK_USER_DATA
      return '/tmp/predator-test'
    }),
    getVersion: vi.fn(() => '0.3.3'),
    commandLine: { appendSwitch: vi.fn() },
    on: vi.fn(),
    whenReady: vi.fn(),
  },
  ipcMain: {
    handle: vi.fn(),
    on: vi.fn(),
  },
  BrowserWindow: {
    fromWebContents: vi.fn(() => null),
    getAllWindows: vi.fn(() => []),
  },
  Menu: { setApplicationMenu: vi.fn(), buildFromTemplate: vi.fn(() => []) },
  Tray: vi.fn(() => ({
    setToolTip: vi.fn(),
    setContextMenu: vi.fn(),
    on: vi.fn(),
  })),
  nativeImage: {
    createFromPath: vi.fn(() => ({
      resize: vi.fn().mockReturnThis(),
      setTemplateImage: vi.fn(),
    })),
    createEmpty: vi.fn(() => ({ resize: vi.fn().mockReturnThis() })),
  },
}))

vi.mock('electron-updater', () => ({
  autoUpdater: {
    autoDownload: false,
    autoInstallOnAppQuit: true,
    checkForUpdates: vi.fn(() => Promise.resolve({ updateInfo: { version: '0.3.3' } })),
    downloadUpdate: vi.fn(() => Promise.resolve()),
    quitAndInstall: vi.fn(),
    on: vi.fn(),
  },
}))

// ═══════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════

/** Write a test config file to the mock userData directory */
function writeTestConfig(config: Record<string, unknown>): void {
  fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true })
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2))
}

/** Remove the test config file */
function removeTestConfig(): void {
  try { fs.unlinkSync(CONFIG_PATH) } catch { /* ok */ }
}

// ═══════════════════════════════════════════════════
// SETUP / TEARDOWN
// ═══════════════════════════════════════════════════

beforeEach(() => {
  removeTestConfig()
  vi.clearAllMocks()
})

afterEach(() => {
  removeTestConfig()
})

// ═══════════════════════════════════════════════════
// IMPORTS (after mocks)
// ═══════════════════════════════════════════════════

import {
  handleGetConfig,
  handleSaveConfig,
  handleGetApiBase,
  handleSetApiBase,
  handleGetPcName,
  handleGetMinimizeToTray,
  handleSetMinimizeToTray,
} from '../ipc-handlers'

import { handleCancelScan } from '../ipc-handlers-scan'

// ═══════════════════════════════════════════════════
// CONFIG HANDLERS
// ═══════════════════════════════════════════════════

describe('handleGetConfig', () => {
  it('returns DEFAULT_CONFIG when no config file exists', async () => {
    const cfg = await handleGetConfig()
    expect(cfg.apiUrl).toBe('http://5.164.42.189:3001')
    expect(cfg.lang).toBe('ru')
    expect(cfg.theme).toBe('predator')
    expect(cfg.tokenId).toBeNull()
    expect(cfg.onboardingComplete).toBe(false)
  })

  it('returns stored config when config file exists', async () => {
    writeTestConfig({ lang: 'en', theme: 'ocean', onboardingComplete: true })
    const cfg = await handleGetConfig()
    expect(cfg.lang).toBe('en')
    expect(cfg.theme).toBe('ocean')
    expect(cfg.onboardingComplete).toBe(true)
    // apiUrl falls back to default (not in stored)
    expect(cfg.apiUrl).toBe('http://5.164.42.189:3001')
  })

  it('merges partial stored config with defaults', async () => {
    writeTestConfig({ lang: 'en' })
    const cfg = await handleGetConfig()
    expect(cfg.lang).toBe('en')
    expect(cfg.theme).toBe('predator') // from default
    expect(cfg.apiUrl).toBe('http://5.164.42.189:3001') // from default
  })

  it('returns same result on repeated calls (idempotent)', async () => {
    const cfg1 = await handleGetConfig()
    const cfg2 = await handleGetConfig()
    expect(cfg1).toEqual(cfg2)
  })
})

describe('handleSaveConfig', () => {
  it('returns merged config after saving a valid partial', async () => {
    const cfg = await handleSaveConfig({ lang: 'en' })
    expect(cfg.lang).toBe('en')
    // Should have been persisted
    const raw = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'))
    expect(raw.lang).toBe('en')
  })

  it('returns current config when passed null', async () => {
    writeTestConfig({ lang: 'ru' })
    const cfg = await handleSaveConfig(null)
    expect(cfg.lang).toBe('ru') // unchanged
  })

  it('returns current config when passed undefined', async () => {
    writeTestConfig({ lang: 'ru' })
    const cfg = await handleSaveConfig(undefined)
    expect(cfg.lang).toBe('ru')
  })

  it('returns current config when passed a string (non-object)', async () => {
    writeTestConfig({ lang: 'ru' })
    const cfg = await handleSaveConfig('invalid')
    expect(cfg.lang).toBe('ru')
  })

  it('saves multiple fields at once', async () => {
    const cfg = await handleSaveConfig({ lang: 'en', theme: 'stealth', onboardingComplete: true })
    expect(cfg.lang).toBe('en')
    expect(cfg.theme).toBe('stealth')
    expect(cfg.onboardingComplete).toBe(true)
  })
})

describe('handleGetApiBase', () => {
  it('returns default API base without config file', async () => {
    const base = await handleGetApiBase()
    expect(base).toBe('http://5.164.42.189:3001')
  })

  it('returns stored API base from config', async () => {
    writeTestConfig({ apiUrl: 'https://api.example.com:8080' })
    const base = await handleGetApiBase()
    expect(base).toBe('https://api.example.com:8080')
  })

  it('strips trailing slash from stored API base', async () => {
    writeTestConfig({ apiUrl: 'https://api.example.com/' })
    const base = await handleGetApiBase()
    expect(base).toBe('https://api.example.com')
  })
})

describe('handleSetApiBase', () => {
  it('accepts a valid http URL', () => {
    const result = handleSetApiBase('http://192.168.1.1:3001')
    expect(result).toBe('http://192.168.1.1:3001')
  })

  it('accepts a valid https URL', () => {
    const result = handleSetApiBase('https://api.predator.dev')
    expect(result).toBe('https://api.predator.dev')
  })

  it('strips trailing slash', () => {
    const result = handleSetApiBase('http://localhost:3001/')
    expect(result).toBe('http://localhost:3001')
  })

  it('rejects empty string — returns current API base', () => {
    writeTestConfig({ apiUrl: 'http://5.164.42.189:3001' })
    const result = handleSetApiBase('')
    expect(result).toBe('http://5.164.42.189:3001')
  })

  it('rejects null — returns current API base', () => {
    writeTestConfig({ apiUrl: 'http://5.164.42.189:3001' })
    const result = handleSetApiBase(null)
    expect(result).toBe('http://5.164.42.189:3001')
  })

  it('rejects ftp:// protocol — returns current API base', () => {
    writeTestConfig({ apiUrl: 'http://5.164.42.189:3001' })
    const result = handleSetApiBase('ftp://files.example.com')
    expect(result).toBe('http://5.164.42.189:3001')
  })

  it('rejects invalid URL string — returns current API base', () => {
    writeTestConfig({ apiUrl: 'http://5.164.42.189:3001' })
    const result = handleSetApiBase('not-a-valid-url!@#$')
    expect(result).toBe('http://5.164.42.189:3001')
  })

  it('persists the new URL to config file', () => {
    handleSetApiBase('https://new-api.example.com:9090')
    const raw = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'))
    expect(raw.apiUrl).toBe('https://new-api.example.com:9090')
  })
})

// ═══════════════════════════════════════════════════
// SYSTEM INFO HANDLERS
// ═══════════════════════════════════════════════════

describe('handleGetPcName', () => {
  const savedUsername = process.env.USERNAME

  afterEach(() => {
    if (savedUsername) process.env.USERNAME = savedUsername
    else delete process.env.USERNAME
  })

  it('returns username from os.userInfo()', () => {
    const name = handleGetPcName()
    // On the test runner, os.userInfo() returns the actual user
    expect(typeof name).toBe('string')
    expect(name.length).toBeGreaterThan(0)
  })

  it('falls back to USERNAME env when os.userInfo throws', () => {
    vi.spyOn(os, 'userInfo').mockImplementationOnce(() => {
      throw new Error('No user info')
    })
    process.env.USERNAME = 'TestFallbackUser'
    const name = handleGetPcName()
    expect(name).toBe('TestFallbackUser')
  })

  it('returns "unknown" as last resort', () => {
    vi.spyOn(os, 'userInfo').mockImplementationOnce(() => {
      throw new Error('No user info')
    })
    delete process.env.USERNAME
    const name = handleGetPcName()
    expect(name).toBe('unknown')
  })
})

// ═══════════════════════════════════════════════════
// TRAY HANDLERS
// ═══════════════════════════════════════════════════

describe('handleGetMinimizeToTray', () => {
  it('returns true when current value is true', () => {
    expect(handleGetMinimizeToTray(true)).toBe(true)
  })

  it('returns false when current value is false', () => {
    expect(handleGetMinimizeToTray(false)).toBe(false)
  })
})

describe('handleSetMinimizeToTray', () => {
  it('returns true for truthy values', () => {
    expect(handleSetMinimizeToTray(true)).toBe(true)
    expect(handleSetMinimizeToTray(1)).toBe(true)
    expect(handleSetMinimizeToTray('yes')).toBe(true)
  })

  it('returns false for falsy values', () => {
    expect(handleSetMinimizeToTray(false)).toBe(false)
    expect(handleSetMinimizeToTray(0)).toBe(false)
    expect(handleSetMinimizeToTray('')).toBe(false)
    expect(handleSetMinimizeToTray(null)).toBe(false)
  })
})

// ═══════════════════════════════════════════════════
// SCAN HANDLERS — CANCEL
// ═══════════════════════════════════════════════════

describe('handleCancelScan', () => {
  it('aborts the controller and returns success when active', () => {
    const controller = new AbortController()
    expect(controller.signal.aborted).toBe(false)

    const result = handleCancelScan(controller)
    expect(result.success).toBe(true)
    expect(controller.signal.aborted).toBe(true)
  })

  it('returns error when controller is null', () => {
    const result = handleCancelScan(null)
    expect(result.success).toBe(false)
    expect(result.error).toBe('No active scan')
  })

  it('returns error when controller is undefined', () => {
    const result = handleCancelScan(undefined)
    expect(result.success).toBe(false)
    expect(result.error).toBe('No active scan')
  })

  it('is idempotent — calling twice still succeeds', () => {
    const controller = new AbortController()
    handleCancelScan(controller)
    // Controller is already aborted — calling again should still return success
    const result = handleCancelScan(controller)
    expect(result.success).toBe(true)
  })
})
