/**
 * Predator — Telemetry Queue
 *
 * Persistent, background queue for reliably sending scan results to the server.
 * Replaces fire-and-forget HTTP with a disk-backed queue and exponential backoff.
 *
 * Features:
 *   - Disk persistence (survives app restarts)
 *   - Exponential backoff (1s → 2s → 4s → ... → 60s max)
 *   - Background worker (doesn't block scans)
 *   - Max queue size to prevent unbounded growth
 *   - Batch sending for efficiency
 */

import fs from 'fs'
import path from 'path'
import http from 'http'
import https from 'https'
import { app } from 'electron'
import { getApiEndpoint } from './config'

// ═══════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════

export interface QueuedPayload {
  id: string
  endpoint: string
  payload: unknown
  retries: number
  maxRetries: number
  nextRetryAt: number
  createdAt: number
}

interface QueueData {
  version: number
  items: QueuedPayload[]
}

// ═══════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════

const CONFIG = {
  MAX_QUEUE_SIZE: 500,
  MAX_RETRIES: 10,
  BASE_DELAY_MS: 1000,
  MAX_DELAY_MS: 60_000,
  BATCH_SIZE: 20,
  WORKER_INTERVAL_MS: 5_000,
  REQUEST_TIMEOUT_MS: 10_000,
}

// ═══════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════

let _queue: QueueData = { version: 1, items: [] }
let _dirty = false
let _workerTimer: ReturnType<typeof setInterval> | null = null
let _sending = false
let _queuePath = ''

function getQueuePath(): string {
  if (_queuePath) return _queuePath
  try {
    _queuePath = path.join(app.getPath('userData'), 'telemetry-queue.json')
  } catch {
    _queuePath = path.join(process.cwd(), 'telemetry-queue.json')
  }
  return _queuePath
}

// ═══════════════════════════════════════════════════
// PERSISTENCE
// ═══════════════════════════════════════════════════

function loadQueue(): void {
  try {
    const p = getQueuePath()
    if (fs.existsSync(p)) {
      const raw = fs.readFileSync(p, 'utf-8')
      _queue = JSON.parse(raw) as QueueData
      if (!_queue.items) _queue.items = []
      // Prune expired items (retried too many times)
      _queue.items = _queue.items.filter(item => item.retries < item.maxRetries)
    }
  } catch {
    _queue = { version: 1, items: [] }
  }
}

function saveQueue(): void {
  if (!_dirty) return
  try {
    const p = getQueuePath()
    const dir = path.dirname(p)
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(p, JSON.stringify(_queue, null, 2), 'utf-8')
    _dirty = false
  } catch (err) { console.warn('[telemetry-queue] silently failed:', (err as Error).message) }
}

// ═══════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════

/**
 * Enqueue a payload for background sending.
 * Returns immediately — payload will be sent by background worker.
 */
export function enqueue(endpoint: string, payload: unknown): void {
  if (_queue.items.length >= CONFIG.MAX_QUEUE_SIZE) {
    // Drop oldest item to prevent unbounded growth
    _queue.items.shift()
  }

  const item: QueuedPayload = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
    endpoint,
    payload,
    retries: 0,
    maxRetries: CONFIG.MAX_RETRIES,
    nextRetryAt: Date.now(), // Send immediately
    createdAt: Date.now(),
  }

  _queue.items.push(item)
  _dirty = true

  // Trigger immediate send for new items
  if (!_sending) {
    processQueue().catch(() => {})
  }
}

/**
 * Get current queue size (for monitoring).
 */
export function getQueueSize(): number {
  return _queue.items.length
}

/**
 * Get pending item count (not yet succeeded).
 */
export function getPendingCount(): number {
  return _queue.items.filter(i => i.retries < i.maxRetries).length
}

// ═══════════════════════════════════════════════════
// BACKGROUND WORKER
// ═══════════════════════════════════════════════════

async function processQueue(): Promise<void> {
  if (_sending) return
  _sending = true

  try {
    const now = Date.now()
    const ready = _queue.items.filter(item =>
      item.retries < item.maxRetries && item.nextRetryAt <= now
    )

    if (ready.length === 0) {
      _sending = false
      return
    }

    // Process in batches
    const batch = ready.slice(0, CONFIG.BATCH_SIZE)

    for (const item of batch) {
      try {
        await sendPayload(item.endpoint, item.payload)
        // Success — remove from queue
        _queue.items = _queue.items.filter(i => i.id !== item.id)
        _dirty = true
      } catch {
        // Failure — schedule retry
        item.retries++
        const delay = Math.min(
          CONFIG.BASE_DELAY_MS * Math.pow(2, item.retries - 1),
          CONFIG.MAX_DELAY_MS,
        )
        item.nextRetryAt = Date.now() + delay
        _dirty = true

        if (item.retries >= item.maxRetries) {
          console.warn(`  ⚠️  Telemetry: ${item.endpoint} failed after ${item.maxRetries} retries — dropped`)
        }
      }
    }
  } catch { /* worker error — retry next cycle */ }
  finally {
    _sending = false
    if (_dirty) saveQueue()
  }
}

// ═══════════════════════════════════════════════════
// HTTP SENDER
// ═══════════════════════════════════════════════════

function sendPayload(endpoint: string, body: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    try {
      const payload = JSON.stringify(body)
      const { hostname, port, protocol } = getApiEndpoint()
      const transport = protocol === 'https:' ? https : http

      const req = transport.request({
        hostname,
        port,
        path: endpoint,
        method: 'POST',
        timeout: CONFIG.REQUEST_TIMEOUT_MS,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
      }, (res) => {
        // Any 2xx response = success
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          // Consume response data to free memory
          res.resume()
          resolve()
        } else {
          res.resume()
          reject(new Error(`HTTP ${res.statusCode}`))
        }
      })

      req.on('error', reject)
      req.on('timeout', () => {
        req.destroy()
        reject(new Error('Request timeout'))
      })

      req.write(payload)
      req.end()
    } catch (err) {
      reject(err)
    }
  })
}

// ═══════════════════════════════════════════════════
// LIFECYCLE
// ═══════════════════════════════════════════════════

export function startTelemetryQueue(): void {
  loadQueue()
  console.log(`  📤 Telemetry queue: ${_queue.items.length} pending items`)

  // Start background worker
  _workerTimer = setInterval(() => {
    processQueue().catch(() => {})
  }, CONFIG.WORKER_INTERVAL_MS)

  // Process immediately
  processQueue().catch(() => {})
}

export function stopTelemetryQueue(): void {
  if (_workerTimer) {
    clearInterval(_workerTimer)
    _workerTimer = null
  }
  saveQueue()
}

/**
 * Force-flush the queue (called before app quit).
 */
export async function flushTelemetryQueue(): Promise<void> {
  stopTelemetryQueue()

  // Try to send remaining items
  const remaining = _queue.items.filter(i => i.retries < i.maxRetries)
  if (remaining.length === 0) {
    saveQueue()
    return
  }

  console.log(`  📤 Flushing ${remaining.length} telemetry items...`)

  for (const item of remaining) {
    try {
      await sendPayload(item.endpoint, item.payload)
      _queue.items = _queue.items.filter(i => i.id !== item.id)
    } catch {
      // Will be retried on next app start
      item.nextRetryAt = Date.now() + CONFIG.BASE_DELAY_MS
      item.retries++
    }
  }

  _dirty = true
  saveQueue()
  console.log(`  📤 Flush complete: ${_queue.items.length} items remain for next start`)
}
