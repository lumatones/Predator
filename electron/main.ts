import { app, BrowserWindow, ipcMain, Menu, Tray, nativeImage } from 'electron'
import path from 'path'
import fs from 'fs'
import os from 'os'
import { autoUpdater } from 'electron-updater'
import { registerScanHandlers, startCloudSync, initSafeFilesDb } from './scanner'
import { registerSystemInfoHandlers } from './system-info'
import { loadConfig, saveConfig, getApiBase } from './config'
import { startSignatureWatcher, stopSignatureWatcher } from './signature-watcher'

let mainWindow: BrowserWindow | null = null
let _updateCheckInterval: ReturnType<typeof setInterval> | null = null
let tray: Tray | null = null
let minimizeToTray = true
let isQuitting = false

const VITE_DEV_SERVER_URL = process.env.VITE_DEV_SERVER_URL

// ── Proxy bypass for local API ───────────────────────────────────────
// When the OS has a system-wide proxy enabled (e.g. Clash / V2RayN on
// 127.0.0.1:10809), Chromium routes fetch() calls — including those to
// http://localhost:3001 — through that proxy. The proxy doesn't know how
// to forward localhost and answers with a plain-text HTTP 400 "invalid
// request", which the renderer then fails to parse as JSON.
//
// Tell Chromium to bypass the proxy for local addresses BEFORE any
// request happens. Command-line switches must be applied before
// app.whenReady() fires.
app.commandLine.appendSwitch('proxy-bypass-list', '<local>,127.0.0.1,localhost,::1')

// ── Crash Log File ────────────────────────────────

const CRASH_LOG = path.join(app.getPath('userData'), 'crash.log')

function writeCrashLog(level: string, message: string, error?: Error) {
  try {
    const ts = new Date().toISOString()
    const line = `[${ts}] ${level}: ${message}${error ? '\n  ' + error.stack?.replace(/\n/g, '\n  ') || error.message : ''}\n`
    fs.appendFileSync(CRASH_LOG, line)
  } catch { /* crash logger must never throw */ }
}

// ── Global Error Handlers ─────────────────────────

process.on('uncaughtException', (error) => {
  writeCrashLog('UNCAUGHT_EXCEPTION', error.message, error)
  console.error('🛑 Uncaught Exception:', error)

  // Notify the renderer so it can show a recovery UI
  try {
    mainWindow?.webContents.send('crash-event', {
      type: 'uncaughtException',
      message: error.message.slice(0, 200),
    })
  } catch { /* window gone */ }
})

process.on('unhandledRejection', (reason) => {
  const error = reason instanceof Error ? reason : new Error(String(reason))
  writeCrashLog('UNHANDLED_REJECTION', error.message, error)
  console.error('🛑 Unhandled Rejection:', error)
})

// Also catch renderer crashes
app.on('render-process-gone', (_event, _webContents, details) => {
  writeCrashLog('RENDERER_CRASH', `Reason: ${details.reason} (exitCode: ${details.exitCode})`)
  console.error('🛑 Renderer process gone:', details)
})

// ── Auto Updater Config ───────────────────────────

autoUpdater.autoDownload = false
autoUpdater.autoInstallOnAppQuit = true

// ── Hide native menu (File, Edit, View, Window, Help) ──

Menu.setApplicationMenu(null)

// ── Create Window ─────────────────────────────────

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    fullscreen: true,
    frame: true,
    titleBarStyle: 'hiddenInset',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
    icon: path.join(__dirname, '../resources/icon.png'),
    show: false,
  })

  mainWindow.once('ready-to-show', () => {
    mainWindow?.show()
  })

  mainWindow.on('close', (event) => {
    if (!isQuitting && minimizeToTray && process.platform !== 'darwin') {
      event.preventDefault()
      mainWindow?.hide()
      return
    }
  })

  mainWindow.on('closed', () => {
    mainWindow = null
    if (_updateCheckInterval) {
      clearInterval(_updateCheckInterval)
      _updateCheckInterval = null
    }
  })

  try {
    if (VITE_DEV_SERVER_URL) {
      mainWindow.loadURL(VITE_DEV_SERVER_URL)
      mainWindow.webContents.openDevTools()
    } else {
      mainWindow.loadFile(path.join(__dirname, '../dist/index.html'))
    }
  } catch (err) {
    writeCrashLog('LOAD_ERROR', `Failed to load app: ${err}`)
    console.error('Failed to load app:', err)
  }
}

// ── App Ready ──────────────────────────────────────

app.whenReady().then(async () => {
  createWindow()

  // Log startup
  writeCrashLog('INFO', `App started v${app.getVersion()} on ${os.platform()} ${os.release()}`)

  // Initialize safe-files DB from community whitelist BEFORE scan handlers
  await initSafeFilesDb()

  // Setup system tray
  setupTray()

  registerScanHandlers()
  startCloudSync()
  registerSystemInfoHandlers()
  startSignatureWatcher(mainWindow!)

  // ── Update check helpers ──

  function checkForUpdates() {
    if (!mainWindow || mainWindow.isDestroyed()) return
    mainWindow.webContents.send('checking-for-update')
    autoUpdater.checkForUpdates().catch((err) => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('update-error', err instanceof Error ? err.message : String(err))
      }
    })
  }

  // Initial check after window loads
  mainWindow?.webContents.once('did-finish-load', () => {
    if (!VITE_DEV_SERVER_URL) {
      setTimeout(checkForUpdates, 1500)
    }
  })

  // Periodic background check every 5 minutes
  _updateCheckInterval = setInterval(() => {
    if (!VITE_DEV_SERVER_URL && mainWindow && !mainWindow.isDestroyed()) {
      checkForUpdates()
    }
  }, 300_000)

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow()
    }
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
  }
})

// ── Minimize to tray instead of closing ──

app.on('before-quit', () => {
  isQuitting = true
})

function setupTray() {
  if (tray) return

  const iconPath = path.join(__dirname, '../resources/icon.png')
  let icon: Electron.NativeImage
  try {
    icon = nativeImage.createFromPath(iconPath)
    // macOS tray icons should be 16x16 or 22x22 template images
    if (process.platform === 'darwin') {
      icon = icon.resize({ width: 16, height: 16 })
      icon.setTemplateImage(true)
    } else {
      icon = icon.resize({ width: 16, height: 16 })
    }
  } catch {
    // Fallback: create empty 16x16 icon
    icon = nativeImage.createEmpty()
  }

  tray = new Tray(icon)
  tray.setToolTip('Predator Anti-Cheat')

  const updateContextMenu = () => {
    const menu = Menu.buildFromTemplate([
      {
        label: 'Показать Predator',
        click: () => {
          if (mainWindow) {
            mainWindow.show()
            mainWindow.focus()
          } else {
            createWindow()
          }
        },
      },
      {
        label: 'Свернуть в трей',
        click: () => {
          mainWindow?.hide()
        },
      },
      { type: 'separator' },
      {
        label: minimizeToTray ? '✓ Сворачивать в трей при закрытии' : 'Сворачивать в трей при закрытии',
        click: () => {
          minimizeToTray = !minimizeToTray
          updateContextMenu()
        },
      },
      { type: 'separator' },
      {
        label: 'Выход',
        click: () => {
          isQuitting = true
          app.quit()
        },
      },
    ])
    tray!.setContextMenu(menu)
  }

  updateContextMenu()

  tray.on('double-click', () => {
    if (mainWindow) {
      mainWindow.show()
      mainWindow.focus()
    }
  })
}

app.on('will-quit', () => {
  writeCrashLog('INFO', 'App quitting')
  stopSignatureWatcher()
  if (_updateCheckInterval) {
    clearInterval(_updateCheckInterval)
    _updateCheckInterval = null
  }
})

// ── Auto-Updater Events ───────────────────────────

autoUpdater.on('update-available', (info) => {
  if (!mainWindow || mainWindow.isDestroyed()) return
  mainWindow.webContents.send('update-available', {
    version: info.version,
    url: info.files?.[0]?.url || '',
  })
})

autoUpdater.on('download-progress', (progress) => {
  if (!mainWindow || mainWindow.isDestroyed()) return
  mainWindow.webContents.send('download-progress', {
    percent: Math.round(progress.percent),
    bytesPerSecond: progress.bytesPerSecond,
    total: progress.total,
    transferred: progress.transferred,
  })
})

autoUpdater.on('update-downloaded', () => {
  if (!mainWindow || mainWindow.isDestroyed()) return
  mainWindow.webContents.send('update-downloaded')
})

autoUpdater.on('update-not-available', () => {
  if (!mainWindow || mainWindow.isDestroyed()) return
  mainWindow.webContents.send('update-not-available')
})

autoUpdater.on('error', (err) => {
  if (!mainWindow || mainWindow.isDestroyed()) return
  mainWindow.webContents.send('update-error', err.message)
})

// ── IPC Handlers ──────────────────────────────────

ipcMain.handle('get-app-version', async () => {
  try {
    return app.getVersion()
  } catch {
    return 'unknown'
  }
})

ipcMain.handle('start-update-check', async () => {
  try {
    const result = await autoUpdater.checkForUpdates()
    if (result && result.updateInfo.version !== app.getVersion()) {
      return { updateAvailable: true, version: result.updateInfo.version }
    }
    return { updateAvailable: false }
  } catch {
    return { updateAvailable: false }
  }
})

ipcMain.handle('start-download', async () => {
  try {
    await autoUpdater.downloadUpdate()
    return { success: true }
  } catch (err: any) {
    return { success: false, error: err.message }
  }
})

ipcMain.handle('restart-app', async () => {
  try {
    autoUpdater.quitAndInstall()
  } catch (err: any) {
    writeCrashLog('IPC_ERROR', 'Restart failed: ' + err.message)
    console.error('Restart failed:', err.message)
  }
})

ipcMain.handle('get-pc-name', async () => {
  try {
    return os.userInfo().username || process.env.USERNAME || 'unknown'
  } catch {
    return process.env.USERNAME || 'unknown'
  }
})

ipcMain.handle('get-config', async () => loadConfig())

ipcMain.handle('save-config', async (_event, partial) => {
  if (!partial || typeof partial !== 'object') return loadConfig()
  return saveConfig(partial)
})

ipcMain.handle('get-api-base', async () => getApiBase())

ipcMain.handle('set-api-base', async (_event, url: string) => {
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
})

// ── Tray IPC ──

ipcMain.handle('minimize-to-tray', async () => {
  mainWindow?.hide()
})

ipcMain.handle('get-minimize-to-tray', async () => minimizeToTray)

ipcMain.handle('set-minimize-to-tray', async (_event, value: boolean) => {
  minimizeToTray = !!value
  return minimizeToTray
})
