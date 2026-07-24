/**
 * Predator Behavior Profiler
 * Создаёт профиль процесса по хендлам, модулям, сети.
 * Ловит инжекторы по поведению, а не по имени.
 */

import { execSync } from 'child_process'
import fs from 'fs'

export interface BehaviorProfile {
  pid: number
  name: string
  hasGameHandle: boolean
  hasUnsignedDll: boolean
  networkPorts: string[]
  parentName: string
  riskScore: number
}

export interface ScanResult {
  path: string
  fileName: string
  type: 'file' | 'browser' | 'process' | 'registry' | 'hardware' | 'software'
  risk: 'high' | 'medium' | 'low'
  matches: string[]
  size: number
  modifiedAt: string
}

const GAME_NAMES = ['gta5.exe', 'fivem_gtaprocess.exe', 'ragemp_v.exe', 'altv.exe']
const MEME_PORTS = new Set(['1337', '1338', '4444', '5555', '6666', '7777', '8888', '9999'])
const LEGIT_PARENTS = new Set(['explorer.exe', 'services.exe', 'svchost.exe', 'winlogon.exe', 'lsass.exe', 'csrss.exe', 'smss.exe', 'system'])

function getParentProcess(pid: number): string {
  try {
    const out = execSync(`wmic process where "ProcessId=${pid}" get ParentProcessId /format:csv`, { encoding: 'utf-8', timeout: 3000 })
    const ppid = parseInt(out.split('\n').pop()?.trim() || '0', 10)
    if (!ppid) return ''
    const nameOut = execSync(`wmic process where "ProcessId=${ppid}" get Name /format:csv`, { encoding: 'utf-8', timeout: 3000 })
    return nameOut.split('\n').pop()?.trim() || ''
  } catch { return '' }
}

function getNetworkForPid(pid: number): string[] {
  const ports: string[] = []
  try {
    const out = execSync(`netstat -ano | findstr "${pid}"`, { encoding: 'utf-8', timeout: 5000 })
    for (const line of out.split('\n')) {
      const parts = line.trim().split(/\s+/)
      if (parts.length < 5) continue
      const local = parts[1] || ''
      const port = local.split(':').pop() || ''
      if (MEME_PORTS.has(port)) ports.push(port)
    }
  } catch { /* ignore */ }
  return ports
}

/** Проверка, находится ли модуль в доверенном системном пути */
function isInTrustedModulePath(modulePath: string): boolean {
  const lower = modulePath.toLowerCase()
  // Системные пути: Windows, Program Files, ProgramData
  if (lower.includes('\\windows\\')) return true
  if (lower.includes('\\program files\\') || lower.includes('\\program files (x86)\\')) return true
  if (lower.includes('\\programdata\\')) return true
  return false
}

/** Построить профиль процесса */
export function buildBehaviorProfile(pid: number, name: string, modules: string[]): BehaviorProfile {
  const profile: BehaviorProfile = {
    pid, name, hasGameHandle: false, hasUnsignedDll: false,
    networkPorts: [], parentName: '', riskScore: 0,
  }

  // 1. Проверяем хендлы к игре (через handle64, если доступен)
  try {
    const out = execSync(`handle64 -p ${name} -a 2>nul`, { encoding: 'utf-8', timeout: 5000 })
    const lower = out.toLowerCase()
    for (const game of GAME_NAMES) {
      if (lower.includes(game)) {
        profile.hasGameHandle = true
        profile.riskScore += 50
        break
      }
    }
  } catch { /* handle64 не обязателен */ }

  // 2. Неподписанные DLL (исключая системные пути, Program Files, ProgramData)
  for (const mod of modules) {
    const modLower = mod.toLowerCase()
    if (isInTrustedModulePath(modLower)) continue
    profile.hasUnsignedDll = true
    profile.riskScore += 15
    break
  }

  // 3. Сеть
  profile.networkPorts = getNetworkForPid(pid)
  profile.riskScore += profile.networkPorts.length * 10

  // 4. Родитель
  profile.parentName = getParentProcess(pid)
  const parentLower = profile.parentName.toLowerCase()

  // 4a. General check: parent should be a known system/launcher process
  if (!LEGIT_PARENTS.has(parentLower)) {
    profile.riskScore += 10
  }

  // 4b. PPID-specific rules: known system processes MUST have the correct parent
  //    If svchost.exe has parent = explorer.exe, that's PPID spoofing
  const ppidRules: Record<string, string> = {
    'svchost.exe': 'services.exe',
    'csrss.exe': 'smss.exe',
    'lsass.exe': 'winlogon.exe',
    'smss.exe': 'system',
    'winlogon.exe': 'smss.exe',
    'services.exe': 'winlogon.exe',
    'spoolsv.exe': 'services.exe',
    'dwm.exe': 'system',
  }

  const nameLower = profile.name.toLowerCase()
  const expectedParent = ppidRules[nameLower]
  if (expectedParent && parentLower !== expectedParent) {
    profile.riskScore += 30
    profile.hasUnsignedDll = true // Mark as extra-suspicious for the report
  }

  return profile
}

/** Конвертировать профиль в ScanResult */
export function profileToScanResult(profile: BehaviorProfile): ScanResult | null {
  if (profile.riskScore < 40) return null
  return {
    path: `behavior:${profile.name} (PID:${profile.pid})`,
    fileName: profile.name,
    type: 'process',
    risk: profile.riskScore > 70 ? 'high' : 'medium',
    matches: [
      ...(profile.hasGameHandle ? ['Opened handle to game process'] : []),
      ...(profile.hasUnsignedDll ? ['Loaded unsigned module'] : []),
      ...(profile.networkPorts.length ? [`Suspicious ports: ${profile.networkPorts.join(', ')}`] : []),
      ...(profile.parentName ? [`Parent: ${profile.parentName}`] : []),
      ...(profile.riskScore > 70 ? ['Behavioral risk: HIGH — possible injector'] : ['Behavioral risk: MEDIUM']),
    ],
    size: 0,
    modifiedAt: new Date().toISOString(),
  }
}
