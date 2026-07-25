import { app, BrowserWindow, ipcMain, Menu } from 'electron'
import path from 'path'
import fs from 'fs'
import os from 'os'
import { autoUpdater } from 'electron-updater'
import { registerScanHandlers, startCloudSync } from './scanner'
import { registerSystemInfoHandlers } from './system-info'

let mainWindow: BrowserWindow | null = null
let _updateCheckInterval: ReturnType<typeof setInterval> | null = null

const VITE_DEV_SERVER_URL = process.env.VITE_DEV_SERVER_URL

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

  mainWindow.on('closed', () => {
    mainWindow = null
  })

  // Cleanup streaming intervals when window is destroyed
  mainWindow.on('closed', () => {
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

app.whenReady().then(() => {
  createWindow()

  // Log startup
  writeCrashLog('INFO', `App started v${app.getVersion()} on ${os.platform()} ${os.release()}`)

  // ── Update check helpers ──

  function checkForUpdates() {
    mainWindow?.webContents.send('checking-for-update')
    autoUpdater.checkForUpdates().catch(() => {
      mainWindow?.webContents.send('update-not-available')
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

app.on('will-quit', () => {
  writeCrashLog('INFO', 'App quitting')
  if (_updateCheckInterval) {
    clearInterval(_updateCheckInterval)
    _updateCheckInterval = null
  }
})

// ── Auto-Updater Events ───────────────────────────

autoUpdater.on('update-available', (info) => {
  mainWindow?.webContents.send('update-available', {
    version: info.version,
    url: info.files?.[0]?.url || '',
  })
})

autoUpdater.on('download-progress', (progress) => {
  mainWindow?.webContents.send('download-progress', {
    percent: Math.round(progress.percent),
    bytesPerSecond: progress.bytesPerSecond,
    total: progress.total,
    transferred: progress.transferred,
  })
})

autoUpdater.on('update-downloaded', () => {
  mainWindow?.webContents.send('update-downloaded')
})

autoUpdater.on('update-not-available', () => {
  mainWindow?.webContents.send('update-not-available')
})

autoUpdater.on('error', (err) => {
  mainWindow?.webContents.send('update-error', err.message)
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

// ── Scanner ──────────────────────────────────────

registerScanHandlers()
startCloudSync()

// ── System Info Dashboard ────────────────────────

registerSystemInfoHandlers()
