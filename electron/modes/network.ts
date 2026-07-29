/**
 * Predator — Network Scan Mode
 *
 * Checks DNS cache, hosts file, active network connections,
 * and suspicious IP patterns.
 */

import { execSync } from 'child_process'
import fs from 'fs'
import path from 'path'
import type { BrowserWindow } from 'electron'

import { sendProgress, clearFindingDedup, addFindingDedup, _WR, type ScanResult } from '../types'
import { SUSPICIOUS_CATEGORIES, ALL_CHEAT_KEYWORDS, matchKnownCheat } from '../heuristic'

const SUSPICIOUS_DOMAINS = [
  'nightfall', 'unknowncheats', 'mpgh', 'cheater', 'hack', 'cheat',
  'dllinject', 'aimbot', 'wallhack', 'mod menu',
]

const SUSPICIOUS_IP_PATTERNS = [
  /^(185\.|5\.|91\.|46\.|31\.|176\.)/,
  /\b(\d{1,3}\.){3}\d{1,3}$/,
]

function scanDnsCache(): ScanResult[] {
  const results: ScanResult[] = []
  try {
    const out = execSync('ipconfig /displaydns', { encoding: 'utf-8', timeout: 5000 })
    if (!out.trim()) return results
    const lines = out.split('\n').map(l => l.trim())
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      if (!line.startsWith('    ') || line.includes('----')) continue
      const domain = line.replace(/^ +/, '').trim()
      if (!domain || domain.length < 3) continue
      const matches: string[] = []
      for (const susDomain of SUSPICIOUS_DOMAINS) {
        if (domain.toLowerCase().includes(susDomain)) {
          matches.push(`dns:${susDomain}`)
        }
      }
      if (matches.length > 0 && addFindingDedup(`dns:${domain}`)) {
        results.push({
          path: 'DNS Cache', fileName: `DNS: ${domain}`, type: 'software',
          risk: 'medium', matches, size: 0, modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch (err) { console.warn('[network] failed:', (err as Error).message) }
  return results
}

function scanHostsFile(): ScanResult[] {
  const results: ScanResult[] = []
  try {
    const hostsPath = path.join(_WR, 'System32', 'drivers', 'etc', 'hosts')
    const content = fs.readFileSync(hostsPath, 'utf-8')
    const lines = content.split('\n')
    let blockCount = 0
    let redirectCount = 0
    const blocked: string[] = []
    const redirected: string[] = []

    for (const line of lines) {
      const trimmed = line.trim()
      if (trimmed.startsWith('#') || trimmed.length === 0) continue
      const parts = trimmed.split(/\s+/)
      if (parts.length >= 2) {
        const ip = parts[0]
        const hostname = parts.slice(1).join(' ')
        if (ip === '127.0.0.1' || ip === '0.0.0.1' || ip === '0.0.0.0') {
          for (const susDomain of SUSPICIOUS_DOMAINS) {
            if (hostname.toLowerCase().includes(susDomain) && addFindingDedup(`hosts-block:${hostname}`)) {
              blockCount++
              blocked.push(hostname)
              break
            }
          }
        } else if (ip !== '127.0.0.1' && ip !== '::1') {
          for (const susDomain of SUSPICIOUS_DOMAINS) {
            if (hostname.toLowerCase().includes(susDomain) && addFindingDedup(`hosts-redirect:${hostname}`)) {
              redirectCount++
              redirected.push(`${hostname}→${ip}`)
              break
            }
          }
        }
      }
    }

    if (blockCount > 0) {
      results.push({
        path: hostsPath, fileName: `Hosts: Suspicious entries (${blockCount})`, type: 'file', risk: 'high',
        matches: blocked.slice(0, 5).map(h => `hosts-block:${h}`),
        size: content.length, modifiedAt: new Date().toISOString(),
      })
    }
    if (redirectCount > 0) {
      results.push({
        path: hostsPath, fileName: `Hosts: Redirects (${redirectCount})`, type: 'file', risk: 'high',
        matches: redirected.slice(0, 5).map(h => `hosts-redirect:${h}`),
        size: content.length, modifiedAt: new Date().toISOString(),
      })
    }
  } catch (err) { console.warn('[network] failed:', (err as Error).message) }
  return results
}

function scanNetstat(): ScanResult[] {
  const results: ScanResult[] = []
  try {
    const out = execSync('netstat -ano', { encoding: 'utf-8', timeout: 5000 })
    if (!out.trim()) return results
    const lines = out.split('\n')
    let estCount = 0, lstnCount = 0, foreignCount = 0
    const foreignIPs: string[] = []

    for (const line of lines) {
      const trimmed = line.trim()
      if (trimmed.includes('ESTABLISHED')) estCount++
      else if (trimmed.includes('LISTENING')) lstnCount++
      const foreignMatch = trimmed.match(/(\d+\.\d+\.\d+\.\d+):(\d+)\s+(ESTABLISHED|TIME_WAIT)/)
      if (foreignMatch) {
        const ip = foreignMatch[1]
        if (SUSPICIOUS_IP_PATTERNS.some(p => p.test(ip)) && addFindingDedup(`net-foreign:${ip}`)) {
          foreignCount++
          foreignIPs.push(ip)
        }
      }
    }

    if (foreignCount > 0) {
      results.push({
        path: 'Active Connections', fileName: `Suspicious external IPs: ${foreignCount}`, type: 'software', risk: 'medium',
        matches: foreignIPs.slice(0, 5).map(ip => `foreign-ip:${ip}`),
        size: 0, modifiedAt: new Date().toISOString(),
      })
    }
    if (estCount > 0) {
      results.push({
        path: 'Network Summary', fileName: `Connections: ${estCount}`, type: 'process', risk: 'low',
        matches: [`est:${estCount} active`, `lstn:${lstnCount} listening`, `foreign:${foreignCount} unusual IPs`],
        size: 0, modifiedAt: new Date().toISOString(),
      })
    }
  } catch (err) { console.warn('[network] failed:', (err as Error).message) }
  return results
}

export function scanNetstatV2(): ScanResult[] {
  const results: ScanResult[] = []
  try {
    const out = execSync('netstat -ano', { encoding: 'utf-8', timeout: 5000 })
    if (!out.trim()) return results
    const lines = out.split('\n')
    for (const line of lines) {
      const trimmed = line.trim()
      const parts = trimmed.split(/\s+/)
      if (parts.length >= 5) {
        const proto = parts[0]
        const localAddr = parts[1]
        const foreignAddr = parts[2]
        const state = parts[3]
        const pid = parseInt(parts[parts.length - 1], 10)

        const knownCheatPorts = [1080, 1337, 4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321, 27015, 27016]
        const foreignPort = parseInt(foreignAddr.split(':').pop() || '0', 10)
        const lower = trimmed.toLowerCase()

        if (knownCheatPorts.includes(foreignPort) && addFindingDedup(`netstat-port:${pid}:${foreignPort}`)) {
          results.push({
            path: `process:${proto} (PID: ${pid})`, fileName: `Suspicious port: ${foreignPort}`, type: 'process', risk: 'high',
            matches: [`netstat:${foreignPort} (PID: ${pid})`, `netstat:remote:${foreignAddr} (PID: ${pid})`],
            size: 0, modifiedAt: new Date().toISOString(),
          })
        }

        for (const keyword of ALL_CHEAT_KEYWORDS) {
          if (lower.includes(keyword.toLowerCase()) && addFindingDedup(`netstat-str:${pid}:${keyword}`)) {
            results.push({
              path: `process:${proto} (PID: ${pid})`, fileName: `Connection: ${keyword}`, type: 'process', risk: 'medium',
              matches: [`netstat:${keyword} (PID: ${pid})`],
              size: 0, modifiedAt: new Date().toISOString(),
            })
          }
        }
      }
    }
  } catch (err) { console.warn('[network] failed:', (err as Error).message) }
  return results
}

export async function runNetworkScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  clearFindingDedup()
  const results: ScanResult[] = []

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking DNS cache...', filesFound: 0, filesScanned: 0, totalDirs: 4, dirsDone: 0 })

  const dns = scanDnsCache()
  for (const r of dns) results.push(r)

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking hosts file...', filesFound: results.length, filesScanned: 0, totalDirs: 4, dirsDone: 1 })

  const hosts = scanHostsFile()
  for (const r of hosts) results.push(r)

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking connections...', filesFound: results.length, filesScanned: 0, totalDirs: 4, dirsDone: 2 })

  const netstat = scanNetstat()
  for (const r of netstat) results.push(r)

  await sendProgress(win, { phase: 'scanning', currentDir: 'Deep netstat analysis...', filesFound: results.length, filesScanned: 0, totalDirs: 4, dirsDone: 3 })

  const netV2 = scanNetstatV2()
  for (const r of netV2) results.push(r)

  await sendProgress(win, { phase: 'done', currentDir: '', filesFound: results.length, filesScanned: 0, totalDirs: 4, dirsDone: 4 })

  return { results, filesScanned: results.length }
}
