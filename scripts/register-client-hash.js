/**
 * Predator — Register exe SHA256 on the server
 *
 * Populates the `client_hashes` table so the desktop client can fetch the
 * expected SHA256 for its version via GET /api/v1/client-hash and build a
 * server-verified integrity baseline (instead of trust-on-first-use).
 *
 * Run AFTER building the release exe:
 *   node scripts/register-client-hash.js
 *
 * Env / args:
 *   SERVER_URL   (default http://localhost:3001)
 *   ADMIN_TOKEN  — JWT from POST /api/admin/login (or --admin-token=)
 *   ADMIN_USER / ADMIN_PASS — to log in and obtain a JWT
 *   --exe=path   — path to the built exe (default release/Predator-<ver>.exe)
 *   --version=x  — version to register (default from package.json)
 *
 * Requires superadmin role (client-hash endpoint is superadmin-only).
 */

const fs = require('fs')
const crypto = require('crypto')
const path = require('path')

const ROOT = path.join(__dirname, '..')
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf-8'))
const VERSION = (process.argv.find(a => a.startsWith('--version='))?.split('=')[1] || pkg.version).replace(/^v/, '')
const EXE_PATH = process.argv.find(a => a.startsWith('--exe='))?.split('=')[1]
  || path.join(ROOT, 'release', `Predator-${VERSION}.exe`)
const SERVER_URL = (process.env.SERVER_URL || 'http://localhost:3001').replace(/\/$/, '')

function arg(name) {
  return process.argv.find(a => a.startsWith(`--${name}=`))?.split('=')[1]
}

async function api(method, urlPath, body, token) {
  const headers = { 'Content-Type': 'application/json', 'User-Agent': 'Predator-Release' }
  if (token) headers['Authorization'] = `Bearer ${token}`
  const res = await fetch(`${SERVER_URL}${urlPath}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  })
  const data = await res.json().catch(() => ({}))
  return { status: res.status, data }
}

async function main() {
  if (!fs.existsSync(EXE_PATH)) {
    console.error(`❌ Exe not found: ${EXE_PATH}`)
    console.error('   Build the release first (npm run electron:build:win)')
    process.exit(1)
  }

  const sha256 = crypto.createHash('sha256').update(fs.readFileSync(EXE_PATH)).digest('hex')
  const sizeMb = (fs.statSync(EXE_PATH).size / 1024 / 1024).toFixed(1)
  console.log(`  Predator-${VERSION}.exe (${sizeMb} MB)`)
  console.log(`  SHA256: ${sha256}`)

  // ── Obtain admin JWT ──
  let token = process.env.ADMIN_TOKEN || arg('admin-token')
  if (!token) {
    const user = process.env.ADMIN_USER || arg('admin-user')
    const pass = process.env.ADMIN_PASS || arg('admin-pass')
    if (!user || !pass) {
      console.error('❌ No credentials. Set ADMIN_TOKEN or ADMIN_USER/ADMIN_PASS.')
      process.exit(1)
    }
    const login = await api('POST', '/api/admin/login', { username: user, password: pass })
    if (login.status !== 200 || !login.data.token) {
      console.error(`❌ Admin login failed (${login.status}): ${JSON.stringify(login.data).slice(0, 200)}`)
      process.exit(1)
    }
    token = login.data.token
    console.log('  ✅ Admin login OK')
  }

  // ── Register hash ──
  const res = await api('POST', '/api/admin/client-hash', { version: VERSION, sha256 }, token)
  if (res.status !== 200) {
    console.error(`❌ Register failed (${res.status}): ${JSON.stringify(res.data).slice(0, 300)}`)
    console.error('   Check: server reachable? token has superadmin role?')
    process.exit(1)
  }
  console.log(`  ✅ Registered v${res.data.version} SHA256 on ${SERVER_URL}`)
}

main().catch(err => {
  console.error('❌', err.message)
  process.exit(1)
})
