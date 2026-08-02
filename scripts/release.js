/**
 * Predator — Unified Release Script
 * 
 * Run: npm run release
 * 
 * Does everything in one shot:
 *   1. Typecheck
 *   2. Clean old build
 *   3. Build .exe
 *   4. Generate latest.yml (SHA512 checksum for auto-updater)
 *   5. Upload to GitHub Releases
 * 
 * Token: reads GITHUB_TOKEN from .env file (gitignored).
 *        Or: GITHUB_TOKEN=ghp_xxx npm run release
 *        Or: npm run release -- --token=ghp_xxx
 */

const { execSync } = require('child_process')
const fs = require('fs')
const crypto = require('crypto')
const https = require('https')
const path = require('path')

// ── Config ─────────────────────────────────────
const ROOT = path.join(__dirname, '..')
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf-8'))
const VERSION = pkg.version
const OWNER = 'lumatones'
const REPO = 'Predator'
const TAG = `v${VERSION}`
const RELEASE_DIR = path.join(ROOT, 'release')
const EXE_NAME = `Predator-${VERSION}.exe`
const EXE_PATH = path.join(RELEASE_DIR, EXE_NAME)
const YML_PATH = path.join(RELEASE_DIR, 'latest.yml')

// ── Changelog parser ──────────────────────────
/**
 * Extract the release body for the current version from CHANGELOG.md.
 * Follows Keep a Changelog format: finds `## [VERSION] — DATE` and
 * returns everything up to the next `## [` header (or EOF).
 */
function getReleaseBody() {
  const changelogPath = path.join(ROOT, 'CHANGELOG.md')
  if (!fs.existsSync(changelogPath)) {
    console.warn('  ⚠️  CHANGELOG.md not found — using empty body')
    return ''
  }
  const text = fs.readFileSync(changelogPath, 'utf-8')
  const startRe = new RegExp(`^## \\[${VERSION.replace(/\./g, '\\.')}\\]`, 'm')
  const startMatch = text.match(startRe)
  if (!startMatch) {
    console.warn(`  ⚠️  Version [${VERSION}] not found in CHANGELOG.md`)
    return ''
  }
  const startIdx = startMatch.index
  // Search for the next version header after our section
  const searchStart = startIdx + startMatch[0].length
  const nextHeaderRe = /^## \[[\d.]+\]/m
  const nextMatch = text.slice(searchStart).match(nextHeaderRe)
  const endIdx = nextMatch ? searchStart + nextMatch.index : text.length
  // Slice from our header to next header, trim trailing whitespace
  return text.slice(startIdx, endIdx).trim()
}

// ── Token resolution ───────────────────────────
function getToken() {
  // 1. --token= arg
  const tokenArg = process.argv.find(a => a.startsWith('--token='))
  if (tokenArg) return tokenArg.split('=')[1]

  // 2. GITHUB_TOKEN env
  if (process.env.GITHUB_TOKEN) return process.env.GITHUB_TOKEN

  // 3. .env file
  const envPath = path.join(ROOT, '.env')
  if (fs.existsSync(envPath)) {
    const match = fs.readFileSync(envPath, 'utf-8').match(/^GITHUB_TOKEN=(.+)$/m)
    if (match) return match[1].trim()
  }

  console.error('\n❌ GITHUB_TOKEN не найден!')
  console.error('   Добавьте его в .env файл:')
  console.error('   echo GITHUB_TOKEN=ghp_xxxx >> .env\n')
  console.error('   Или:')
  console.error('   set GITHUB_TOKEN=ghp_xxxx && npm run release')
  console.error('   npm run release -- --token=ghp_xxxx')
  process.exit(1)
}

const TOKEN = getToken()

// ── Logging ────────────────────────────────────
const c = { green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m', cyan: '\x1b[36m', reset: '\x1b[0m', bold: '\x1b[1m' }
function log(msg) { console.log(`  ${msg}`) }
function ok(msg) { console.log(`  ${c.green}✓${c.reset} ${msg}`) }
function fail(msg) { console.log(`  ${c.red}✗${c.reset} ${msg}`) }

// ── HTTP helper ────────────────────────────────
function gh(method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(`https://api.github.com${urlPath}`)
    const opts = {
      hostname: u.hostname, port: 443, path: u.pathname + u.search, method,
      headers: {
        'Authorization': `token ${TOKEN}`,
        'User-Agent': 'Predator-Release',
        'Accept': 'application/vnd.github+json',
      },
    }
    if (body) {
      opts.headers['Content-Type'] = 'application/json'
      opts.headers['Content-Length'] = Buffer.byteLength(body)
    }
    const r = https.request(opts, (res) => {
      let data = ''
      res.on('data', c => data += c)
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }) }
        catch { resolve({ status: res.statusCode, data }) }
      })
    })
    r.on('error', reject)
    if (body) r.write(body)
    r.end()
  })
}

// ── Upload asset ───────────────────────────────
function uploadAsset(uploadUrl, filePath, fileName) {
  return new Promise((resolve, reject) => {
    const content = fs.readFileSync(filePath)
    const cleanUrl = uploadUrl.replace('{?name,label}', '') + '?name=' + encodeURIComponent(fileName)
    const u = new URL(cleanUrl)
    const opts = {
      hostname: u.hostname, port: 443, path: u.pathname + u.search, method: 'POST',
      headers: {
        'Authorization': `token ${TOKEN}`,
        'User-Agent': 'Predator-Release',
        'Content-Type': 'application/octet-stream',
        'Content-Length': content.length,
        'Accept': 'application/vnd.github+json',
      },
    }
    const r = https.request(opts, (res) => {
      let data = ''
      res.on('data', c => data += c)
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }) }
        catch { resolve({ status: res.statusCode, data }) }
      })
    })
    r.on('error', reject)
    r.write(content)
    r.end()
  })
}

// ── Main ──────────────────────────────────────
(async () => {
  console.log(`\n  ${c.bold}🦅  Predator Release — ${TAG}${c.reset}\n`)
  console.log(`  Репозиторий: ${OWNER}/${REPO}\n`)

  // Step 1: Typecheck
  console.log(`${c.cyan}[1/5]${c.reset} Typecheck...`)
  try {
    execSync('npx tsc --noEmit --project tsconfig.electron.json', { cwd: ROOT, stdio: 'pipe' })
    ok('electron typecheck passed')
  } catch (e) {
    fail(`typecheck failed:\n${e.stdout?.toString()}`)
    process.exit(1)
  }

  // Step 2: Build .exe
  console.log(`\n${c.cyan}[2/5]${c.reset} Build .exe (это займёт пару минут)...`)
  try {
    execSync('npm run electron:build:win', { cwd: ROOT, stdio: 'inherit' })
  } catch {
    fail('build failed')
    process.exit(1)
  }

  if (!fs.existsSync(EXE_PATH)) {
    fail(`${EXE_NAME} не найден после сборки`)
    process.exit(1)
  }
  const exeSize = (fs.statSync(EXE_PATH).size / 1024 / 1024).toFixed(1)
  ok(`${EXE_NAME} (${exeSize} MB)`)

  // Step 3: Generate latest.yml
  console.log(`\n${c.cyan}[3/5]${c.reset} Generate latest.yml...`)
  const fileBuffer = fs.readFileSync(EXE_PATH)
  const sha512 = crypto.createHash('sha512').update(fileBuffer).digest('base64')
  const yml = [
    `version: ${VERSION}`,
    'files:',
    `  - url: ${EXE_NAME}`,
    `    sha512: ${sha512}`,
    `    size: ${fileBuffer.length}`,
    `path: ${EXE_NAME}`,
    `sha512: ${sha512}`,
    `releaseDate: ${new Date().toISOString()}`,
    '',
  ].join('\n')
  fs.writeFileSync(YML_PATH, yml, 'utf-8')
  ok(`latest.yml (SHA512: ${sha512.slice(0, 16)}...)`)

  // Step 4: Check if release exists on GitHub
  console.log(`\n${c.cyan}[4/5]${c.reset} GitHub Release...`)
  let release = (await gh('GET', `/repos/${OWNER}/${REPO}/releases/tags/${TAG}`))

  if (release.status === 200) {
    log(`Найден существующий release: ${release.data.html_url}`)
    // Delete old assets
    if (release.data.assets?.length > 0) {
      log(`Удаление ${release.data.assets.length} старых asset-ов...`)
      for (const asset of release.data.assets) {
        const del = await gh('DELETE', `/repos/${OWNER}/${REPO}/releases/assets/${asset.id}`)
        log(`  ${del.status === 204 ? '✓' : '✗'} ${asset.name}`)
      }
    }
  } else if (release.status === 404) {
    // Create new release
    log('Создание нового release...')
    release = await gh('POST', `/repos/${OWNER}/${REPO}/releases`, JSON.stringify({
      tag_name: TAG,
      name: TAG,
      body: getReleaseBody(),
      draft: false,
      prerelease: false,
    }))
    if (release.status !== 201) {
      fail(`Не удалось создать release: ${release.data?.message || release.status}`)
      process.exit(1)
    }
    ok(`Release создан: ${release.data.html_url}`)
  } else {
    fail(`Ошибка GitHub API: ${release.status} — ${release.data?.message}`)
    process.exit(1)
  }

  // Step 5: Upload files
  console.log(`\n${c.cyan}[5/5]${c.reset} Upload assets...`)
  const BLOCKMAP_PATH = `${EXE_PATH}.blockmap`
  const files = [
    { path: EXE_PATH, name: EXE_NAME },
    { path: YML_PATH, name: 'latest.yml' },
    // Differential-update blockmap (NSIS) — electron-updater derives the
    // blockmap URL by appending ".blockmap" to the file URL, so the asset
    // must be named "<exe>.blockmap" and sit next to the exe.
    ...(fs.existsSync(BLOCKMAP_PATH) ? [{ path: BLOCKMAP_PATH, name: `${EXE_NAME}.blockmap` }] : []),
  ]
  const failedUploads = []
  for (const file of files) {
    const mb = (fs.statSync(file.path).size / 1024 / 1024).toFixed(1)
    log(`Uploading ${file.name} (${mb} MB)...`)
    const result = await uploadAsset(release.data.upload_url, file.path, file.name)
    if (result.status === 201) {
      ok(`${file.name}`)
    } else {
      fail(`${file.name}: ${result.data?.message || result.status}`)
      failedUploads.push(file.name)
    }
  }

  if (failedUploads.length > 0) {
    fail(`Релиз ${TAG} НЕ завершён — не удалось загрузить: ${failedUploads.join(', ')}`)
    process.exit(1)
  }

  console.log(`\n  ${c.green}${c.bold}✅ Релиз ${TAG} готов!${c.reset}`)
  console.log(`  ${release.data.html_url}\n`)

  // Optional: register the exe SHA256 on the server so desktop clients can
  // build a server-verified integrity baseline instead of trust-on-first-use.
  // Enabled when ADMIN_TOKEN or ADMIN_USER/ADMIN_PASS (+ SERVER_URL) are set.
  const canRegister = process.env.ADMIN_TOKEN || (process.env.ADMIN_USER && process.env.ADMIN_PASS)
  if (canRegister) {
    console.log(`${c.cyan}[6/6]${c.reset} Register client hash on server...`)
    try {
      execSync('node scripts/register-client-hash.js', { cwd: ROOT, stdio: 'inherit', env: { ...process.env, SERVER_URL: process.env.SERVER_URL || 'http://localhost:3001' } })
    } catch {
      fail('client-hash registration failed (release continues — hash can be registered later)')
    }
  } else {
    log('ℹ️  Skipping client-hash registration — set ADMIN_TOKEN or ADMIN_USER/ADMIN_PASS to enable')
  }
})().catch(err => {
  console.error(`\n  ${c.red}❌ ${err.message}${c.reset}\n`)
  process.exit(1)
})
