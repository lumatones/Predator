import { app, BrowserWindow, ipcMain } from 'electron'
import path from 'path'
import os from 'os'
import { autoUpdater } from 'electron-updater'
import { registerScanHandlers } from './scanner'

let mainWindow: BrowserWindow | null = null

const VITE_DEV_SERVER_URL = process.env.VITE_DEV_SERVER_URL

// ── Auto Updater Config ───────────────────────────

autoUpdater.autoDownload = false
autoUpdater.autoInstallOnAppQuit = true

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

  try {
    if (VITE_DEV_SERVER_URL) {
      mainWindow.loadURL(VITE_DEV_SERVER_URL)
      mainWindow.webContents.openDevTools()
    } else {
      mainWindow.loadFile(path.join(__dirname, '../dist/index.html'))
    }
  } catch (err) {
    console.error('Failed to load app:', err)
  }

  mainWindow.on('closed', () => {
    mainWindow = null
  })
}

// ── App Ready ──────────────────────────────────────

app.whenReady().then(() => {
  createWindow()

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

  // Periodic background check every 5 minutes (300 000 ms)
  setInterval(() => {
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

ipcMain.handle('get-app-version', () => {
  return app.getVersion()
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
    autoUpdater.downloadUpdate()
    return { success: true }
  } catch (err: any) {
    return { success: false, error: err.message }
  }
})

ipcMain.handle('restart-app', async () => {
  autoUpdater.quitAndInstall()
})

ipcMain.handle('get-pc-name', () => {
  return os.userInfo().username || process.env.USERNAME || 'unknown'
})

// ── Scanner ──────────────────────────────────────

registerScanHandlers()
