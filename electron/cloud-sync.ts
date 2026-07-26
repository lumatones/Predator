/**
 * Predator — Cloud Hash Sync
 * Extracted from scanner.ts (Priority 1 refactoring)
 *
 * Periodically fetches known cheat hashes from the backend API
 * and merges them into the local cheat database.
 */

import http from 'http'
import https from 'https'
import { getApiBase } from './config'
import { mergeCheatHashes } from './cheats-db'

let _syncTimer: ReturnType<typeof setInterval> | null = null

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
  } catch (_e) { /* cloud sync optional */ }
}

export function startCloudSync(): void {
  fetchCheatHashes()
  _syncTimer = setInterval(fetchCheatHashes, 5 * 60 * 1000)
}

export function stopCloudSync(): void {
  if (_syncTimer) {
    clearInterval(_syncTimer)
    _syncTimer = null
  }
}
