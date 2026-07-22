/* ══════════════════════════════════════════════
   Predator Installer — Renderer Logic
   ══════════════════════════════════════════════ */

// ── DOM References ──────────────────────────────

const $ = (id) => document.getElementById(id)

const screens = {
  welcome: $('screen-welcome'),
  installing: $('screen-installing'),
  complete: $('screen-complete'),
  error: $('screen-error'),
}

const installPath = $('install-path')
const btnInstall = $('btn-install')
const btnBrowse = $('btn-browse')
const btnLaunch = $('btn-launch')
const btnCloseInstaller = $('btn-close-installer')
const btnRetry = $('btn-retry')
const btnMinimize = $('btn-minimize')
const btnClose = $('btn-close')
const progressFill = $('progress-fill')
const progressPercent = $('progress-percent')
const progressLabel = $('progress-label')
const progressSpeed = $('progress-speed')
const progressSize = $('progress-size')
const installStatus = $('install-status')
const installLog = $('install-log')
const errorMessage = $('error-message')
const completeVersion = $('complete-version')
const chkDesktop = $('chk-desktop')
const chkStartMenu = $('chk-startmenu')

let lastDownloadResult = null

// ── Screen Manager ──────────────────────────────

function showScreen(name) {
  Object.values(screens).forEach(s => s.classList.remove('active'))
  screens[name].classList.add('active')
}

// ── API Guard ────────────────────────────────────

const api = window.installerAPI
if (!api) {
  document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#EF4444;font-family:sans-serif;background:#0D0D12;">Ошибка: не удалось загрузить модули безопасности.</div>'
  throw new Error('installerAPI not available')
}

// ── Window Controls ─────────────────────────────

btnMinimize.addEventListener('click', () => api.minimize())
btnClose.addEventListener('click', () => api.close())

// ── Path Selector ───────────────────────────────

btnBrowse.addEventListener('click', async () => {
  const dir = await api.selectDirectory()
  if (dir) installPath.value = dir
})

// ── Log Helper ──────────────────────────────────

function addLog(text, type = 'pending') {
  const entry = document.createElement('div')
  entry.className = `log-entry ${type}`
  entry.textContent = text
  installLog.appendChild(entry)
  installLog.scrollTop = installLog.scrollHeight
  return entry
}

function updateLastLog(text, type) {
  const last = installLog.lastElementChild
  if (last) {
    last.textContent = text
    if (type) last.className = `log-entry ${type}`
  }
}

// ── Format bytes ────────────────────────────────

function formatBytes(bytes) {
  if (bytes === 0) return '0 MB'
  const mb = bytes / (1024 * 1024)
  return mb >= 1 ? `${mb.toFixed(1)} MB` : `${(bytes / 1024).toFixed(0)} KB`
}

// ── Main Install Flow ───────────────────────────

btnInstall.addEventListener('click', async () => {
  const path = installPath.value.trim()
  if (!path) {
    addLog('❌ Укажите путь установки', 'error')
    return
  }

  const server = document.querySelector('input[name="server"]:checked')?.value || 'github'
  const createDesktop = chkDesktop.checked
  const createStartMenu = chkStartMenu.checked

  // Reset UI
  showScreen('installing')
  installLog.innerHTML = ''
  progressFill.style.width = '0%'
  progressPercent.textContent = '0%'
  progressLabel.textContent = 'Подготовка...'
  installStatus.textContent = 'Загрузка компонентов...'

  addLog('🔄 Инициализация установки...', 'active')
  await delay(300)

  // Start download (progress listener is registered globally once)
  addLog(`📥 Загрузка с сервера: ${server}...`, 'active')
  await delay(500)

  const result = await api.downloadPredator({
    installPath: path,
    server: server,
  })

  if (!result.success) {
    showScreen('error')
    errorMessage.textContent = result.error || 'Неизвестная ошибка при загрузке.'
    addLog(`❌ ${result.error}`, 'error')
    lastDownloadResult = null
    return
  }

  updateLastLog(`✅ Загружено: ${result.name} (${result.version})`, 'success')
  lastDownloadResult = result

  // Create shortcuts
  if (createDesktop || createStartMenu) {
    addLog('📌 Создание ярлыков...', 'active')
    await delay(200)

    const shortcutResult = await window.installerAPI.createShortcuts({
      exePath: result.exePath,
      installPath: path,
    })

    if (shortcutResult.success) {
      updateLastLog('✅ Ярлыки созданы', 'success')
    } else {
      updateLastLog(`⚠️ Не удалось создать ярлыки: ${shortcutResult.error}`, 'error')
    }
  }

  // Complete
  progressFill.style.width = '100%'
  progressPercent.textContent = '100%'
  progressLabel.textContent = 'Установка завершена!'
  installStatus.textContent = 'Predator готов к работе.'

  addLog('✅ Установка успешно завершена!', 'success')
  await delay(600)

  completeVersion.textContent = `Predator ${result.version} успешно установлен в ${path}`
  showScreen('complete')
})

// ── Retry ───────────────────────────────────────

btnRetry.addEventListener('click', () => {
  showScreen('welcome')
  installLog.innerHTML = ''
  progressFill.style.width = '0%'
  progressPercent.textContent = '0%'
})

// ── Launch / Close ──────────────────────────────

btnLaunch.addEventListener('click', async () => {
  if (lastDownloadResult) {
    await api.launchPredator(lastDownloadResult.exePath)
  }
  api.close()
})

btnCloseInstaller.addEventListener('click', () => {
  api.close()
})

// ── Init: Register global listeners once ────────

api.onDownloadProgress((data) => {
  const pct = data.percent
  progressFill.style.width = `${pct}%`
  progressPercent.textContent = `${pct}%`
  progressLabel.textContent = pct < 100 ? 'Загрузка Predator...' : 'Установка...'
  progressSize.textContent = data.downloaded === 0 && data.total === 0 ? '— / —' : `${formatBytes(data.downloaded)} / ${formatBytes(data.total)}`
  if (data.speed > 0) {
    progressSpeed.textContent = `${(data.speed / (1024 * 1024)).toFixed(1)} MB/s`
  }
})

// ── Utility ─────────────────────────────────────

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

// ── Init ─────────────────────────────────────────

addLog('✅ Установщик готов к работе', 'done')
