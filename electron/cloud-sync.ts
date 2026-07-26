/**
 * Predator — Cloud Hash Sync v2
 *
 * WebSocket-first real-time sync of cheat signatures (SHA256 + TLSH).
 * Falls back to HTTP polling if WebSocket is unavailable.
 *
 * Syncs:
 *   - SHA256 hashes (cheat file signatures)
 *   - TLSH hashes (fuzzy hashes for variant detection)
 *   - YARA rules (auto-generated shadow rules)
 */

import http from 'http'
import https from 'https'
import { getApiBase } from './config'
import { mergeCheatHashes } from './cheats-db'
import { setKnownTlshHashes, mergeTlshHashes } from './fuzzy-hash'

let _syncTimer: ReturnType<typeof setInterval> | null = null
let _wsConnection: ReturnType<typeof import('socket.io-client').io> | null = null
let _wsConnected = false

export function isCloudSyncActive(): boolean {
  return _wsConnected || _syncTimer !== null
}

// ── WebSocket connection (real-time) ──

export function connectCloudWebSocket(serverUrl: string): void {
  try {
    // Dynamic import to avoid requiring socket.io-client in all builds
     
    const io = require('socket.io-client') as { default?: { io?: (url: string, opts: Record<string, unknown>) => { on: (e: string, cb: (data: unknown) => void) => void; emit: (e: string) => void; disconnect: () => void } } }
    const ioFn = io?.default?.io ?? (io as { io?: (url: string, opts: Record<string, unknown>) => { on: (e: string, cb: (data: unknown) => void) => void; emit: (e: string) => void; disconnect: () => void } })?.io
    if (!ioFn) {
      console.log('  ⚠️  socket.io-client not available — falling back to HTTP polling')
      return
    }
    const socket = ioFn(serverUrl, {
      transports: ['websocket'],
      reconnection: true,
      reconnectionDelay: 2000,
      reconnectionAttempts: Infinity,
    })

    socket.on('connect', () => {
      _wsConnected = true
      console.log('  🔌 Cloud WebSocket connected')
      socket.emit('join-scanner')
    })

    socket.on('disconnect', () => {
      _wsConnected = false
      console.log('  🔌 Cloud WebSocket disconnected')
    })

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    socket.on('hash-update', (data: any) => {
      if (data?.hashes) {
        mergeCheatHashes(data.hashes)
        console.log(`  ☁️  WS: synced ${data.hashes.length} SHA256 hashes`)
      }
      if (data?.tlsh) {
        mergeTlshHashes(data.tlsh)
        console.log(`  ☁️  WS: synced ${data.tlsh.length} TLSH hashes`)
      }
    })

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    socket.on('rule-update', (data: any) => {
      if (data?.rules) {
        console.log(`  ☁️  WS: received ${data.rules.length} updated YARA rules`)
        // Rules will be picked up on next scan
      }
    })

    _wsConnection = socket
  } catch {
    console.log('  ⚠️  WebSocket unavailable — falling back to HTTP polling')
  }
}

// ── HTTP polling (fallback) ──

export async function fetchCheatHashes(): Promise<void> {
  try {
    const base = getApiBase()
    const url = new URL('/api/auth/fetch-hashes', base)
    url.searchParams.set('after', '2000-01-01')

    const data = await new Promise<string>((resolve, reject) => {
      const transport = url.protocol === 'https:' ? https : http
      const req = transport.get(url, (res) => {
        let body = ''
        res.on('data', (chunk: string) => body += chunk)
        res.on('end', () => resolve(body))
        res.on('error', reject)
      })
      req.on('error', reject)
      req.setTimeout(5000, () => { req.destroy(); reject(new Error('timeout')) })
    })
    const parsed = JSON.parse(data)
    if (parsed?.hashes && Array.isArray(parsed.hashes)) {
      mergeCheatHashes(parsed.hashes.map((h: { sha256: string }) => h.sha256).filter(Boolean))
      console.log(`  ☁️  Synced ${parsed.hashes.length} cheat hashes from cloud`)
    }
    // Also sync TLSH hashes if available
    if (parsed?.tlsh && Array.isArray(parsed.tlsh)) {
      mergeTlshHashes(parsed.tlsh.map((h: { hash: string }) => h.hash).filter(Boolean))
      console.log(`  ☁️  Synced ${parsed.tlsh.length} TLSH hashes from cloud`)
    }
  } catch (_e) { /* cloud sync optional */ }
}

// ── Lifecycle ──

export function startCloudSync(): void {
  // Try WebSocket first
  try {
    const base = getApiBase()
    connectCloudWebSocket(base)
  } catch {
    console.log('  ℹ️  WebSocket connect failed — using HTTP polling')
  }
  // HTTP polling as fallback (runs in parallel with WS or standalone)
  fetchCheatHashes()
  _syncTimer = setInterval(fetchCheatHashes, 5 * 60 * 1000)
}

export function stopCloudSync(): void {
  if (_syncTimer) {
    clearInterval(_syncTimer)
    _syncTimer = null
  }
  if (_wsConnection) {
    try {
      ( _wsConnection as { disconnect?: () => void } ).disconnect?.()
    } catch { /* ignore */ }
    _wsConnection = null
    _wsConnected = false
  }
}
