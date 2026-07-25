import { execSync } from 'child_process'
import * as path from 'path'
import * as fs from 'fs'
import { ScanResult, addFindingDedup, _WR } from '../types'
import { SUSPICIOUS_CATEGORIES, ALL_CHEAT_KEYWORDS } from '../heuristic'
import { REGISTRY_SCAN_KEYS } from '../cheats-db'

/**
 * Deep registry scan for suspicious entries (Run, RunOnce, Services, Winlogon)
 */
export function scanRegistryDeepV2(): ScanResult[] {
  const results: ScanResult[] = []

  const regPaths = [
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'HKCU\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run',
    'HKLM\\SYSTEM\\CurrentControlSet\\Services',
    'HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
    'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
  ]

  for (const keyPath of regPaths) {
    try {
      const output = execSync(`reg query "${keyPath}" /s 2>nul`, { encoding: 'utf-8' as const, timeout: 5000 })
      if (!output || output.trim().length === 0) continue

      const lower = output.toLowerCase()

      for (const [catName, cat] of Object.entries(SUSPICIOUS_CATEGORIES)) {
        for (const name of cat.names) {
          if (lower.includes(name)) {
            const dedupKey = `reg-deep:${catName}:${name}`
            if (addFindingDedup(dedupKey)) {
              results.push({
                path: keyPath,
                fileName: `Registry [${catName}]: ${name}`,
                type: 'registry',
                risk: cat.risk === 'CRITICAL' ? 'high' : cat.risk === 'HIGH' ? 'high' : 'medium',
                matches: [`registry-deep:${name} (${catName})`, `risk:${cat.risk}`],
                size: 0,
                modifiedAt: new Date().toISOString(),
              })
            }
          }
        }
      }
    } catch (_e) { /* skip inaccessible keys */ }
  }

  return results
}

/**
 * Scan Prefetch directory for suspicious file names
 */
export function scanPrefetchV2(): ScanResult[] {
  const results: ScanResult[] = []
  const prefetchDir = path.join(_WR, 'Prefetch')

  try {
    if (!fs.existsSync(prefetchDir)) return results
    for (const file of fs.readdirSync(prefetchDir)) {
      if (!file.toLowerCase().endsWith('.pf')) continue
      const fileLower = file.toLowerCase()

      for (const [catName, cat] of Object.entries(SUSPICIOUS_CATEGORIES)) {
        for (const name of cat.names) {
          if (fileLower.includes(name)) {
            const dedupKey = `pf:${catName}:${file}`
            if (addFindingDedup(dedupKey)) {
              const filePath = path.join(prefetchDir, file)
              let mtime = new Date().toISOString()
              try { mtime = fs.statSync(filePath).mtime.toISOString() } catch (_e) { /* skip */ }

              results.push({
                path: filePath,
                fileName: `Prefetch [${catName}]: ${file}`,
                type: 'file',
                risk: cat.risk === 'CRITICAL' || cat.risk === 'HIGH' ? 'high' : 'medium',
                matches: [`prefetch:${name} (${catName})`, `last-run:${mtime.slice(0, 10)}`],
                size: 0,
                modifiedAt: mtime,
              })
            }
          }
        }
      }
    }
  } catch (_e) { /* skip */ }

  return results
}

/**
 * Scan registry for cheat-related keys
 */
export function scanRegistryForCheats(): ScanResult[] {
  const results: ScanResult[] = []

  for (const keyPath of REGISTRY_SCAN_KEYS) {
    try {
      const output = execSync(`reg query "${keyPath}" /s 2>nul`, { encoding: 'utf-8' as const, timeout: 5000 })
      if (!output || output.trim().length === 0) continue

      const lower = output.toLowerCase()
      for (const keyword of ALL_CHEAT_KEYWORDS) {
        if (lower.includes(keyword.toLowerCase())) {
          const safeKey = keyword.slice(0, 40)
          results.push({
            path: keyPath, fileName: `Registry: ${safeKey}`, type: 'registry',
            risk: 'high', matches: [`registry:${safeKey} found`], size: 0, modifiedAt: new Date().toISOString(),
          })
          break
        }
      }
    } catch (_e) { /* skip */ }
  }

  return results
}
