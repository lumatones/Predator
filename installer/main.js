const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron')
const path = require('path')
const fs = require('fs')
const https = require('https')
const { exec } = require('child_process')

let mainWindow = null

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 860,
    height: 560,
    minWidth: 860,
    minHeight: 560,
    maxWidth: 860,
    maxHeight: 560,
    frame: false,
    transparent: true,
    resizable: false,
    show: false,
    icon: path.join(__dirname, 'assets', 'icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  })

  mainWindow.once('ready-to-show', () => {
    mainWindow?.show()
  })

  mainWindow.loadFile(path.join(__dirname, 'src', 'index.html'))

  // DevTools only in dev mode
  if (process.env.NODE_ENV === 'development') {
    mainWindow.webContents.openDevTools()
  }

  mainWindow.on('closed', () => {
    mainWindow = null
  })
}

app.whenReady().then(createWindow)

app.on('window-all-closed', () => {
  app.quit()
})

app.on('activate', () => {
  if (mainWindow === null) createWindow()
})

// ── Window controls ──────────────────────────────

ipcMain.handle('window-minimize', () => mainWindow?.minimize())
ipcMain.handle('window-close', () => mainWindow?.close())

// ── Default install path (user local app data) ────

ipcMain.handle('get-default-path', () => {
  return path.join(process.env.LOCALAPPDATA || app.getPath('userData'), 'Predator')
})

// ── Select install directory ─────────────────────

ipcMain.handle('select-directory', async () => {
  const defaultPath = path.join(process.env.LOCALAPPDATA || app.getPath('userData'), 'Predator')
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
    defaultPath,
  })
  if (!result.canceled && result.filePaths.length > 0) {
    return result.filePaths[0]
  }
  return null
})

// ── Helper: https get with redirect follow ────────

function httpsGet(url, options = {}, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    if (redirectCount > 10) {
      reject(new Error('Too many redirects'))
      return
    }
    const req = https.get(url, options, (res) => {
      // Follow redirects manually for Electron's Node
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        const redirectUrl = new URL(res.headers.location, url).toString()
        httpsGet(redirectUrl, options, redirectCount + 1).then(resolve).catch(reject)
        return
      }
      resolve(res)
    })
    req.on('error', reject)
    req.end()
  })
}

function httpsGetJSON(url) {
  return new Promise((resolve, reject) => {
    httpsGet(url, { headers: { 'User-Agent': 'Predator-Installer' } }).then((res) => {
      let data = ''
      res.on('data', (chunk) => data += chunk)
      res.on('end', () => {
        try {
          resolve(JSON.parse(data))
        } catch (e) {
          reject(new Error('Failed to parse JSON: ' + e.message))
        }
      })
    }).catch(reject)
  })
}

// ── Download Predator from GitHub ─────────────────

ipcMain.handle('download-predator', async (event, { installPath, server }) => {
  const repoUrl = 'https://api.github.com/repos/lumatones/Predator/releases/latest'

  try {
    // Get latest release info
    const json = await httpsGetJSON(repoUrl)

    // Check if GitHub returned an error (no releases yet, rate limit, etc.)
    if (!json || json.message) {
      return {
        success: false,
        error: json?.message === 'Not Found'
          ? 'На GitHub ещё нет релизов. Сначала создайте релиз с portable .exe файлом.'
          : (json?.message || 'Не удалось получить информацию о релизе с GitHub')
      }
    }

    // Check if assets exist
    if (!Array.isArray(json.assets) || json.assets.length === 0) {
      return { success: false, error: 'В последнем релизе нет файлов для загрузки. Добавьте Predator portable .exe в релиз на GitHub.' }
    }

    // Find the portable asset
    const asset = json.assets.find(a => a.name.endsWith('.exe') && a.name.includes('Predator'))
    if (!asset) {
      return { success: false, error: 'Бинарный файл Predator не найден в последнем релизе. Убедитесь, что файл .exe загружен в релиз.' }
    }

    const releaseInfo = { url: asset.browser_download_url, name: asset.name, size: asset.size, version: json.tag_name }

    // Ensure install directory exists
    if (!fs.existsSync(installPath)) {
      fs.mkdirSync(installPath, { recursive: true })
    }

    const exePath = path.join(installPath, releaseInfo.name)

    // Download the file with progress (including speed tracking)
    await new Promise((resolve, reject) => {
      httpsGet(releaseInfo.url, { headers: { 'User-Agent': 'Predator-Installer' } }).then((res) => {
        const total = parseInt(res.headers['content-length'] || releaseInfo.size, 10)
        let downloaded = 0
        let lastTime = Date.now()
        let lastBytes = 0
        const file = fs.createWriteStream(exePath)

        res.on('data', (chunk) => {
          const now = Date.now()
          downloaded += chunk.length
          const percent = Math.round((downloaded / total) * 100)

          // Calculate speed every ~500ms
          const elapsed = now - lastTime
          let speed = 0
          if (elapsed >= 500) {
            speed = Math.round(((downloaded - lastBytes) / elapsed) * 1000)
            lastTime = now
            lastBytes = downloaded
          }

          mainWindow?.webContents.send('download-progress', { percent, downloaded, total, speed })
        })

        res.pipe(file)

        file.on('finish', () => {
          file.close()
          resolve()
        })

        file.on('error', (err) => {
          try { fs.unlinkSync(exePath) } catch {}
          reject(err)
        })
      }).catch(reject)
    })

    return {
      success: true,
      exePath,
      version: releaseInfo.version,
      name: releaseInfo.name,
    }
  } catch (err) {
    return { success: false, error: err.message }
  }
})

// ── Create shortcuts ─────────────────────────────

ipcMain.handle('create-shortcuts', async (event, { exePath, installPath }) => {
  try {
    const desktopPath = path.join(app.getPath('desktop'), 'Predator.lnk')
    const startMenuPath = path.join(
      app.getPath('appData'),
      'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Predator.lnk'
    )

    // Create shortcuts using PowerShell (works on Windows 10+)
    const psScript = `
      $WScriptShell = New-Object -ComObject WScript.Shell
      $Shortcut = $WScriptShell.CreateShortcut('${desktopPath.replace(/'/g, "''")}')
      $Shortcut.TargetPath = '${exePath.replace(/'/g, "''")}'
      $Shortcut.WorkingDirectory = '${installPath.replace(/'/g, "''")}'
      $Shortcut.Description = 'Predator — Система проверки безопасности'
      $Shortcut.Save()

      $Shortcut2 = $WScriptShell.CreateShortcut('${startMenuPath.replace(/'/g, "''")}')
      $Shortcut2.TargetPath = '${exePath.replace(/'/g, "''")}'
      $Shortcut2.WorkingDirectory = '${installPath.replace(/'/g, "''")}'
      $Shortcut2.Description = 'Predator — Система проверки безопасности'
      $Shortcut2.Save()
    `

    return new Promise((resolve) => {
      exec(`powershell -Command "${psScript.replace(/"/g, '\\"')}"`, (err) => {
        resolve({ success: !err, error: err?.message })
      })
    })
  } catch (err) {
    return { success: false, error: err.message }
  }
})

// ── Launch Predator ──────────────────────────────

ipcMain.handle('launch-predator', async (event, exePath) => {
  try {
    shell.openPath(exePath)
    return { success: true }
  } catch (err) {
    return { success: false, error: err.message }
  }
})
