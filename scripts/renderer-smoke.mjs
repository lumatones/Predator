import { spawn } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'

const HOST = '127.0.0.1'
const START_TIMEOUT_MS = 30_000
const STEP_TIMEOUT_MS = 10_000
const smokeUrl = process.env.SMOKE_URL || ''
const requestedDebugPort = Number(process.env.CHROME_DEBUG_PORT || 0)

function chromeCandidates() {
  return [
    process.env.CHROME_PATH,
    process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, 'Google/Chrome/Application/chrome.exe'),
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  ].filter(Boolean)
}

function findChrome() {
  const executable = chromeCandidates().find(path => existsSync(path))
  if (!executable) throw new Error('Chrome executable not found. Set CHROME_PATH to chrome.exe.')
  return executable
}

async function waitFor(predicate, timeoutMs, description) {
  const started = Date.now()
  let lastError
  while (Date.now() - started < timeoutMs) {
    try {
      const value = await predicate()
      if (value) return value
    } catch (error) {
      lastError = error
    }
    await sleep(100)
  }
  const suffix = lastError instanceof Error ? `: ${lastError.message}` : ''
  throw new Error(`Timed out waiting for ${description}${suffix}`)
}

async function getFreePort() {
  return new Promise((resolve, reject) => {
    const listener = createServer()
    listener.once('error', reject)
    listener.listen(0, HOST, () => {
      const address = listener.address()
      listener.close(error => {
        if (error) reject(error)
        else resolve(typeof address === 'object' && address ? address.port : 0)
      })
    })
  })
}

async function waitForHttp(url) {
  return waitFor(async () => {
    const response = await fetch(url)
    return response.ok
  }, START_TIMEOUT_MS, `Vite HTTP server at ${url}`)
}

async function waitForProcessExit(process) {
  if (!process || process.exitCode !== null) return
  await Promise.race([
    new Promise(resolve => process.once('exit', resolve)),
    sleep(2_000),
  ])
}

async function openCdpSession(port) {
  if (typeof WebSocket !== 'function') {
    throw new Error('Node 22+ is required for renderer smoke (global WebSocket is unavailable).')
  }

  const target = await waitFor(async () => {
    const response = await fetch(`http://${HOST}:${port}/json/list`)
    if (!response.ok) return null
    const targets = await response.json()
    return targets.find(item => item.type === 'page' && item.webSocketDebuggerUrl) || null
  }, START_TIMEOUT_MS, 'Chrome page target')

  const socket = new WebSocket(target.webSocketDebuggerUrl)
  const pending = new Map()
  const consoleErrors = []
  let nextId = 0

  socket.addEventListener('message', event => {
    const message = JSON.parse(String(event.data))
    if (message.method === 'Runtime.exceptionThrown') {
      consoleErrors.push(message.params.exceptionDetails?.text || 'Runtime exception')
    }
    if (message.method === 'Runtime.consoleAPICalled' && message.params.type === 'error') {
      consoleErrors.push(message.params.args?.map(arg => arg.value || arg.description).join(' ') || 'Console error')
    }
    const resolver = pending.get(message.id)
    if (resolver) {
      pending.delete(message.id)
      resolver(message)
    }
  })

  await waitFor(() => socket.readyState === WebSocket.OPEN, STEP_TIMEOUT_MS, 'CDP WebSocket')

  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++nextId
    pending.set(id, message => {
      if (message.error) reject(new Error(message.error.message))
      else resolve(message.result)
    })
    socket.send(JSON.stringify({ id, method, params }))
  })

  await send('Runtime.enable')
  await send('Page.enable')
  return { socket, send, consoleErrors }
}

async function evaluate(send, expression) {
  const result = await send('Runtime.evaluate', {
    expression,
    awaitPromise: true,
    returnByValue: true,
  })
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.text || 'Browser evaluation failed')
  return result.result?.value
}

async function assertSelector(send, selector, description) {
  return waitFor(
    () => evaluate(send, `Boolean(document.querySelector(${JSON.stringify(selector)}))`),
    STEP_TIMEOUT_MS,
    description,
  )
}

async function assertMissing(send, selector, description) {
  return waitFor(
    () => evaluate(send, `!document.querySelector(${JSON.stringify(selector)})`),
    STEP_TIMEOUT_MS,
    description,
  )
}

async function assertText(send, selector, expected, description) {
  return waitFor(
    () => evaluate(send, `document.querySelector(${JSON.stringify(selector)})?.textContent === ${JSON.stringify(expected)}`),
    STEP_TIMEOUT_MS,
    description,
  )
}

async function click(send, selector) {
  await assertSelector(send, selector, selector)
  await evaluate(send, `document.querySelector(${JSON.stringify(selector)}).click()`)
}

async function runSmoke() {
  const chrome = findChrome()
  const profile = mkdtempSync(join(tmpdir(), 'predator-smoke-'))
  const debugPort = requestedDebugPort || await getFreePort()
  const serverPort = smokeUrl ? 0 : await getFreePort()
  const url = smokeUrl.replace(/\/$/, '') || `http://${HOST}:${serverPort}`
  let server
  let browser
  let session

  try {
    if (!smokeUrl) {
      server = spawn(process.execPath, [
        join(process.cwd(), 'node_modules/vite/bin/vite.js'),
        '--host', HOST,
        '--port', String(serverPort),
      ], {
        stdio: 'ignore',
        windowsHide: true,
      })
      await waitForHttp(url)
    }

    browser = spawn(chrome, [
      '--headless=new',
      '--disable-gpu',
      '--no-sandbox',
      '--remote-debugging-address=127.0.0.1',
      `--remote-debugging-port=${debugPort}`,
      `--user-data-dir=${profile}`,
      'about:blank',
    ], { stdio: 'ignore', windowsHide: true })

    session = await openCdpSession(debugPort)
    const { send, consoleErrors } = session
    await send('Page.navigate', { url: `${url}/?smoke=checker` })
    await assertSelector(send, '[data-testid="checker-start-scan"]', 'Checker start button')
    await click(send, '[data-testid="checker-start-scan"]')
    await assertSelector(send, '[data-testid="checker-result-row"]', 'mock scan result')
    await click(send, '[data-testid="checker-result-row"]')
    await assertSelector(send, '[data-testid="file-detail-modal"]', 'Finding modal')
    await click(send, '.filedetail-close')
    await assertMissing(send, '[data-testid="file-detail-modal"]', 'Finding modal close')
    await click(send, '[data-testid="checker-export-html"]')
    await assertText(send, '.checker-export-msg', '✓', 'HTML export feedback')

    if (consoleErrors.length > 0) throw new Error(`Browser console errors:\n${consoleErrors.join('\n')}`)
    console.log('Renderer smoke PASS: Checker → mock scan → result → Finding modal → HTML export')
  } finally {
    if (session?.socket.readyState === WebSocket.OPEN) session.socket.close()
    if (browser && browser.exitCode === null) browser.kill()
    if (server && server.exitCode === null) server.kill()
    await waitForProcessExit(browser)
    await waitForProcessExit(server)
    rmSync(profile, { recursive: true, force: true })
  }
}

runSmoke().catch(error => {
  console.error(`Renderer smoke FAIL: ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
})
