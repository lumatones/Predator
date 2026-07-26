/**
 * Predator — Game Integrity Scan
 *
 * Checks game directories (FiveM, RAGE MP, ALT:V, GTA 5) for
 * unauthorized files, masquerading processes, and open handles.
 */

import { execSync } from 'child_process'
import fs from 'fs'
import path from 'path'
import type { BrowserWindow } from 'electron'

import { sendProgress, clearFindingDedup, addFindingDedup, parsePsJson, _PF, _PF86, _HOME, _WR, type ScanResult, type GamePid } from '../types'
import { SUSPICIOUS_CATEGORIES, SYSTEM_PROC_NAMES, matchKnownCheat, checkDigitalSignature, heuristicFileScan } from '../heuristic'
import { isTrustedPath } from '../cheat-rules'
import { isPlatformWhitelisted } from '../cheats-db'

// ═══════════════════════════════════════════════════
// GAME PROCESS IDs
// ═══════════════════════════════════════════════════

function getGamePids(): GamePid[] {
  const targets = [
    { name: 'GTA5.exe', platform: 'gta5' as const },
    { name: 'FiveM_GTAProcess.exe', platform: 'fivem' as const },
    { name: 'FiveM.exe', platform: 'fivem' as const },
    { name: 'ragemp_v.exe', platform: 'rage' as const },
    { name: 'altv.exe', platform: 'altv' as const },
  ]
  const results: GamePid[] = []
  try {
    const names = targets.map(t => `name='${t.name}'`).join(' or ')
    const out = execSync(`wmic process where "${names}" get ProcessId,Name /format:csv 2>nul`, { encoding: 'utf-8', timeout: 5000 })
    if (!out.trim()) return results
    for (const line of out.trim().split('\n').slice(1)) {
      const parts = line.split(',').map(s => s.trim())
      const name = parts[parts.length - 2]?.toLowerCase()
      const pid = parseInt(parts[parts.length - 1], 10)
      if (isNaN(pid) || !name) continue
      const target = targets.find(t => t.name.toLowerCase() === name)
      if (target) results.push({ pid, platform: target.platform })
    }
  } catch (_e) { /* skip */ }
  return results
}

// ═══════════════════════════════════════════════════
// GAME MODULE SCAN
// ═══════════════════════════════════════════════════

export function scanGameModules(): ScanResult[] {
  const results: ScanResult[] = []
  const gameProcs = getGamePids()
  if (gameProcs.length === 0) return results

  for (const { pid, platform } of gameProcs) {
    try {
      const ps = `Get-Process -Id ${pid} | Select-Object -ExpandProperty Modules | Select-Object ModuleName,FileName | ConvertTo-Json -Compress`
      const out = execSync(`powershell -Command "${ps}"`, { encoding: 'utf-8', timeout: 8000 })
      if (!out.trim()) continue
      const modules = parsePsJson<{ ModuleName?: string; FileName?: string }>(out)

      for (const mod of modules) {
        if (!mod.ModuleName) continue
        const modName = mod.ModuleName
        const modPath = mod.FileName || ''
        const name = modName.toLowerCase()
        const filePathLower = modPath.toLowerCase()
        const isSystem32 = filePathLower.includes('\\windows\\system32') || filePathLower.includes('\\windows\\syswow64')
        const isProgramFiles = filePathLower.includes('\\program files\\') || filePathLower.includes('\\program files (x86)\\')
        const isTrusted = isSystem32 || isProgramFiles || isTrustedPath(modPath)

        if (isPlatformWhitelisted(name, platform) && !isTrusted) {
          if (addFindingDedup(`mod-whitelist:${pid}:${name}`)) {
            results.push({
              path: modPath,
              fileName: `${modName} (unusual location)`,
              type: 'process',
              risk: 'high',
              matches: [`Whitelisted module in ${platform} (PID: ${pid})`, `Expected in System32/Program Files, found elsewhere`, `Platform: ${platform}`],
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
          continue
        }

        if (!isPlatformWhitelisted(name, platform) && !isTrusted) {
          const isSigned = isSystem32 ? true : checkDigitalSignature(modPath)
          if (!isSigned && addFindingDedup(`mod-unsigned:${pid}:${name}`)) {
            results.push({
              path: modPath,
              fileName: `${modName} (unsigned)`,
              type: 'process',
              risk: 'high',
              matches: [`Unsigned module loaded in ${platform} (PID: ${pid})`, `Possibly injected cheat`],
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
        }

        const cheatMatches = matchKnownCheat(name)
        if (cheatMatches.length > 0 && addFindingDedup(`mod-cheat:${pid}:${name}`)) {
          results.push({
            path: modPath,
            fileName: `${modName} (cheat)`,
            type: 'process',
            risk: 'high',
            matches: [...cheatMatches, `Loaded in ${platform} (PID: ${pid})`],
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
        }
      }
    } catch (_e) { /* skip */ }
  }
  return results
}

// ═══════════════════════════════════════════════════
// GAME INTEGRITY CHECK
// ═══════════════════════════════════════════════════

export function scanGameIntegrity(): ScanResult[] {
  const results: ScanResult[] = []
  const CRITICAL_MOD_FILES = ['dinput8.dll', 'dsound.dll', 'winmm.dll', 'scripthookv.dll', 'scripthookvdotnet.dll']
  const GTA5_DIRS = [
    path.join(_PF, 'Rockstar Games', 'Grand Theft Auto V'),
    path.join(_PF86, 'Rockstar Games', 'Grand Theft Auto V'),
    path.join(_PF, 'Steam', 'steamapps', 'common', 'Grand Theft Auto V'),
    path.join(_PF86, 'Steam', 'steamapps', 'common', 'Grand Theft Auto V'),
  ]

  const FIVEM_DIRS = [
    path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'mods'),
    path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'plugins'),
  ]
  for (const dir of FIVEM_DIRS) {
    if (!fs.existsSync(dir)) continue
    for (const entry of fs.readdirSync(dir)) {
      const fullPath = path.join(dir, entry)
      const lower = entry.toLowerCase()
      if ((lower.endsWith('.dll') || lower.endsWith('.asi')) && addFindingDedup(`fivem:${fullPath}`)) {
        try {
          const stat = fs.statSync(fullPath)
          results.push({
            path: fullPath, fileName: entry, type: 'file', risk: 'high',
            matches: ['Unauthorized file in FiveM directory', `Location: ${path.basename(dir)}`, 'DLL/ASI in mods/plugins = cheat loader'],
            size: stat.size, modifiedAt: stat.mtime.toISOString(),
          })
        } catch (_e) { /* skip */ }
      }
    }
  }

  const RAGE_DIRS = [
    path.join(_PF, 'RAGEMP'),
    path.join(_PF86, 'RAGEMP'),
    path.join(_HOME, 'RAGEMP'),
  ]
  for (const rageDir of RAGE_DIRS) {
    if (!fs.existsSync(rageDir)) continue
    for (const entry of fs.readdirSync(rageDir)) {
      const fullPath = path.join(rageDir, entry)
      const lower = entry.toLowerCase()
      // dinput8.dll — ASI loader proxy
      if (lower === 'dinput8.dll' && addFindingDedup(`rage:${fullPath}`)) {
        try {
          const stat = fs.statSync(fullPath)
          results.push({
            path: fullPath, fileName: entry, type: 'file', risk: 'high',
            matches: ['dinput8.dll in RAGEMP directory — ASI loader/cheat', 'ScriptHookV injection method used for MP cheating'],
            size: stat.size, modifiedAt: stat.mtime.toISOString(),
          })
        } catch (_e) { /* skip */ }
      }
      // .asi files — single-player mods loaded in MP
      if (lower.endsWith('.asi') && addFindingDedup(`rage-asi:${fullPath}`)) {
        try {
          const stat = fs.statSync(fullPath)
          results.push({
            path: fullPath, fileName: entry, type: 'file', risk: 'high',
            matches: ['ASI file in RAGEMP directory', 'Single-player cheat loaded in multiplayer'],
            size: stat.size, modifiedAt: stat.mtime.toISOString(),
          })
        } catch (_e) { /* skip */ }
      }
    }
    // Check client_packages subdirectory for unauthorized JS/Lua resources
    const clientPkgDir = path.join(rageDir, 'client_packages')
    if (fs.existsSync(clientPkgDir)) {
      for (const entry of fs.readdirSync(clientPkgDir)) {
        const fullPath = path.join(clientPkgDir, entry)
        const lower = entry.toLowerCase()
        const susKeywords = ['cheat', 'hack', 'inject', 'bypass', 'esp', 'aimbot', 'menu', 'executor', 'spoofer']
        if (susKeywords.some(k => lower.includes(k)) && addFindingDedup(`rage-cpkg:${fullPath}`)) {
          try {
            const stat = fs.statSync(fullPath)
            results.push({
              path: fullPath, fileName: `RAGE client_packages: ${entry}`, type: 'file', risk: 'high',
              matches: ['Suspicious resource in RAGE MP client_packages', `Name match: ${entry}`],
              size: stat.size, modifiedAt: stat.mtime.toISOString(),
            })
          } catch (_e) { /* skip */ }
        }
      }
    }
  }

  const ALTV_DIRS = [
    path.join(_HOME, 'AppData', 'Local', 'altv', 'modules'),
    path.join(_HOME, 'AppData', 'Local', 'altv', 'resources'),
    path.join(_PF, 'altv', 'modules'),
  ]
  const SUS_MOD_NAMES = ['aim', 'esp', 'wall', 'money', 'recovery', 'god', 'teleport', 'inject', 'bypass', 'cheat']
  for (const altvDir of ALTV_DIRS) {
    if (!fs.existsSync(altvDir)) continue
    for (const entry of fs.readdirSync(altvDir)) {
      const fullPath = path.join(altvDir, entry)
      const lower = entry.toLowerCase()
      if (SUS_MOD_NAMES.some(k => lower.includes(k)) && addFindingDedup(`altv-name:${fullPath}`)) {
        try {
          const stat = fs.statSync(fullPath)
          results.push({
            path: fullPath, fileName: entry, type: 'file', risk: 'high',
            matches: [`Suspicious ALT:V module name`, `Keyword match in ${path.basename(altvDir)}`],
            size: stat.size, modifiedAt: stat.mtime.toISOString(),
          })
        } catch (_e) { /* skip */ }
      }
      // Detect obfuscated module names (random hash-like names — alt:V anti-debug technique)
      const OBFUSCATED_NAME_PATTERN = /^[a-f0-9]{20,64}\.(dll|js)$/i
      if (OBFUSCATED_NAME_PATTERN.test(entry) && addFindingDedup(`altv-obf:${fullPath}`)) {
        try {
          const stat = fs.statSync(fullPath)
          results.push({
            path: fullPath, fileName: `ALT:V obfuscated: ${entry}`, type: 'file', risk: 'medium',
            matches: ['Obfuscated/hash-named module (alt:V anti-debug pattern)', 'Possible renamed cheat DLL or JS payload'],
            size: stat.size, modifiedAt: stat.mtime.toISOString(),
          })
        } catch (_e) { /* skip */ }
      }
      if (lower.endsWith('.dll') && !isTrustedPath(fullPath) && addFindingDedup(`altv-unsign:${fullPath}`)) {
        const signed = checkDigitalSignature(fullPath)
        if (!signed) {
          try {
            const stat = fs.statSync(fullPath)
            results.push({
              path: fullPath, fileName: entry, type: 'file', risk: 'medium',
              matches: ['Unsigned DLL in ALT:V modules directory', 'Possible cheat module'],
              size: stat.size, modifiedAt: stat.mtime.toISOString(),
            })
          } catch (_e) { /* skip */ }
        }
      }
    }
  }
  // ALT:V compiled JS resources — check for obfuscated cheat code
  const altvCompiledDir = path.join(_HOME, 'AppData', 'Local', 'altv', 'resources', 'compiled')
  if (fs.existsSync(altvCompiledDir)) {
    try {
      for (const entry of fs.readdirSync(altvCompiledDir)) {
        const fullPath = path.join(altvCompiledDir, entry)
        const lower = entry.toLowerCase()
        if (!lower.endsWith('.js')) continue
        // Check for suspicious patterns in JS filenames
        if (SUS_MOD_NAMES.some(k => lower.includes(k)) && addFindingDedup(`altv-cjs:${fullPath}`)) {
          try {
            const stat = fs.statSync(fullPath)
            results.push({
              path: fullPath, fileName: `ALT:V compiled JS: ${entry}`, type: 'file', risk: 'high',
              matches: [`Suspicious compiled JS resource: ${entry}`, 'Possible obfuscated cheat code'],
              size: stat.size, modifiedAt: stat.mtime.toISOString(),
            })
          } catch (_e) { /* skip */ }
        }
      }
    } catch (_e) { /* skip */ }
  }

  for (const gtaPath of GTA5_DIRS) {
    if (!fs.existsSync(gtaPath)) continue
    for (const entry of fs.readdirSync(gtaPath)) {
      const fullPath = path.join(gtaPath, entry)
      const lower = entry.toLowerCase()
      if (CRITICAL_MOD_FILES.includes(lower) && addFindingDedup(`gta5-root:${fullPath}`)) {
        try {
          const stat = fs.statSync(fullPath)
          results.push({
            path: fullPath, fileName: entry, type: 'file', risk: 'high',
            matches: [`${entry} in GTA 5 root — cheat/mod loader`, 'Used by ScriptHookV/trainers for MP cheating'],
            size: stat.size, modifiedAt: stat.mtime.toISOString(),
          })
        } catch (_e) { /* skip */ }
      }
      if (lower.endsWith('.asi') && addFindingDedup(`gta5-asi:${fullPath}`)) {
        try {
          const stat = fs.statSync(fullPath)
          results.push({
            path: fullPath, fileName: entry, type: 'file', risk: 'high',
            matches: ['ASI mod in GTA 5 directory', 'Common cheat format (Menyoo, SimpleTrainer, etc.)'],
            size: stat.size, modifiedAt: stat.mtime.toISOString(),
          })
        } catch (_e) { /* skip */ }
      }
    }
  }
  return results
}

// ═══════════════════════════════════════════════════
// MASQUERADING DETECTION
// ═══════════════════════════════════════════════════

export function scanMasqueradingProcesses(): ScanResult[] {
  const results: ScanResult[] = []
  try {
    const psCmd = `powershell -Command "Get-Process | Where-Object { $_.MainModule.FileName -match '\\\\[^\\\\]+\\.exe$' } | Select-Object Name, Id, @{N='Path';E={$_.MainModule.FileName}} | ConvertTo-Json -Compress"`
    const out = execSync(psCmd, { encoding: 'utf-8', timeout: 10000 })
    if (!out || out.trim().length < 5) return results

    const processes = parsePsJson<{ Name?: string; Id?: number; Path?: string }>(out)
    const systemDir = _WR.toLowerCase()
    const system32 = path.join(systemDir, 'system32').toLowerCase()
    const syswow64 = path.join(systemDir, 'syswow64').toLowerCase()

    for (const proc of processes) {
      const procName = (proc.Name || '').toLowerCase() + '.exe'
      const procPath = (proc.Path || '').toLowerCase()
      if (!SYSTEM_PROC_NAMES.has(procName)) continue
      if (procPath.startsWith(system32) || procPath.startsWith(syswow64)) continue
      if (isTrustedPath(procPath)) continue

      if (addFindingDedup(`masquerade:${procName}:${proc.Id}`)) {
        results.push({
          path: `process:${proc.Name} (PID: ${proc.Id})`,
          fileName: `🎭 Masquerading: ${proc.Name}.exe`,
          type: 'process', risk: 'high',
          matches: [
            `Process named like system process: ${procName}`,
            `Running from unexpected path: ${procPath}`,
            `Expected in: ${system32}`,
            'Masquerading as system process = cheat loader hiding technique',
          ],
          size: 0, modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch (_e) { /* skip */ }
  return results
}

// ═══════════════════════════════════════════════════
// OPEN HANDLES SCAN
// ═══════════════════════════════════════════════════

export function scanOpenHandles(): ScanResult[] {
  const results: ScanResult[] = []
  const gameProcs = getGamePids()
  const gamePids = new Set(gameProcs.map(g => g.pid))
  if (gamePids.size === 0) return results

  const SYSTEM_PROCS = new Set([
    'explorer.exe', 'taskmgr.exe', 'svchost.exe', 'csrss.exe',
    'lsass.exe', 'services.exe', 'smss.exe', 'fontdrvhost.exe',
    'dwm.exe', 'searchindexer.exe', 'shellexperiencehost.exe',
    'discord.exe', 'steam.exe',
    'gtavlauncher.exe', 'playgtav.exe',
    'fivem.exe', 'fivem_gtaprocess.exe', 'ragemp_v.exe', 'altv.exe',
  ])

  try {
    const out = execSync('handle64.exe -a GTA5.exe -nobanner 2>nul', { encoding: 'utf-8', timeout: 10000 })
    if (!out.trim()) return results
    const lines = out.split('\n')
    for (const line of lines) {
      const m = line.match(/^(\S+)\s+pid:\s+(\d+)\s+type:\s+(\w+)\s+(\w+):\s+(.+)$/i)
      if (!m) continue
      const [, procName, pidStr, type, , target] = m
      const pid = parseInt(pidStr, 10)
      if (SYSTEM_PROCS.has(procName.toLowerCase())) continue
      if (gamePids.has(pid)) continue
      if (addFindingDedup(`handle:${procName}:${pid}`)) {
        results.push({
          path: `handle:${procName} (PID: ${pid})`,
          fileName: procName,
          type: 'process', risk: 'high',
          matches: [`Process opened GTA5.exe handle`, `Handle type: ${type}`, `PID: ${pid}`, 'Possible external cheat (memory read/write)'] as string[],
          size: 0, modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch (_e) { /* skip */ }
  return results
}

// ═══════════════════════════════════════════════════
// ORCHESTRATOR
// ═══════════════════════════════════════════════════

export async function runGameScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  clearFindingDedup()
  const results: ScanResult[] = []

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking game processes...', filesFound: 0, filesScanned: 0, totalDirs: 4, dirsDone: 0 })

  const masq = scanMasqueradingProcesses()
  for (const r of masq) results.push(r)

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking game directories...', filesFound: results.length, filesScanned: 0, totalDirs: 4, dirsDone: 1 })

  const integrity = scanGameIntegrity()
  for (const r of integrity) results.push(r)

  await sendProgress(win, { phase: 'scanning', currentDir: 'Scanning loaded modules...', filesFound: results.length, filesScanned: 0, totalDirs: 4, dirsDone: 2 })

  const modules = scanGameModules()
  for (const r of modules) results.push(r)

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking open handles...', filesFound: results.length, filesScanned: 0, totalDirs: 4, dirsDone: 3 })

  const handles = scanOpenHandles()
  for (const r of handles) results.push(r)

  await sendProgress(win, { phase: 'done', currentDir: '', filesFound: results.length, filesScanned: 0, totalDirs: 4, dirsDone: 4 })

  return { results, filesScanned: results.length }
}
