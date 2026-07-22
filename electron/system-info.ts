/**
 * Predator — System Information handler
 * Gathers CPU, RAM, temperature, running processes,
 * and other system metrics for the live dashboard.
 */

import { ipcMain } from 'electron'
import os from 'os'
import { execSync } from 'child_process'

// ── Types ──────────────────────────────────────

export interface SystemProcess {
  pid: number
  name: string
  memoryMB: number
  cpuPercent: number
}

export interface SystemInfoSnapshot {
  cpu: {
    usagePercent: number
    cores: number
    model: string
    loadAvg: number[]
  }
  memory: {
    totalGB: number
    usedGB: number
    freeGB: number
    usagePercent: number
  }
  temperature: number | null
  uptime: {
    days: number
    hours: number
    minutes: number
  }
  os: {
    platform: string
    release: string
    arch: string
    hostname: string
  }
  processes: SystemProcess[]
  timestamp: number
}

// ── CPU measurement ──

let _prevCpuTimes: { idle: number; total: number } | null = null

function getCpuUsage(): number {
  const cpus = os.cpus()
  let idle = 0
  let total = 0

  for (const cpu of cpus) {
    for (const type in cpu.times) {
      total += (cpu.times as Record<string, number>)[type] || 0
    }
    idle += cpu.times.idle
  }

  const now = { idle, total }

  if (!_prevCpuTimes) {
    _prevCpuTimes = now
    return 0
  }

  const idleDiff = now.idle - _prevCpuTimes.idle
  const totalDiff = now.total - _prevCpuTimes.total
  _prevCpuTimes = now

  if (totalDiff === 0) return 0
  return Math.round((1 - idleDiff / totalDiff) * 100)
}

// ── Temperature (Windows WMI) ──

let _lastTemp: number | null = null
let _lastTempTime = 0

function getTemperature(): number | null {
  // Cache for 10 seconds to avoid hammering WMI
  const now = Date.now()
  if (now - _lastTempTime < 10_000 && _lastTemp !== null) {
    return _lastTemp
  }

  try {
    const out = execSync(
      'wmic /namespace:\\\\root\\wmi PATH MSAcpi_ThermalZoneTemperature get CurrentTemperature /format:csv 2>nul',
      { encoding: 'utf-8', timeout: 3000 }
    )
    const lines = out.trim().split('\n').filter(l => l.trim().length > 0)
    for (const line of lines) {
      const parts = line.split(',')
      if (parts.length >= 2) {
        const val = parseInt(parts[parts.length - 1].trim(), 10)
        if (!isNaN(val) && val > 0) {
          // WMI returns temperature in tenths of Kelvin
          const celsius = Math.round((val / 10) - 273.15)
          if (celsius > 0 && celsius < 120) {
            _lastTemp = celsius
            _lastTempTime = now
            return celsius
          }
        }
      }
    }
  } catch { /* WMI not available or no thermal zones */ }

  // Fallback: try Open Hardware Monitor / Libre Hardware Monitor
  try {
    const out = execSync(
      'wmic path Win32_PerfFormattedData_Counters_ThermalZoneInformation get Temperature /format:csv 2>nul',
      { encoding: 'utf-8', timeout: 3000 }
    )
    const lines = out.trim().split('\n').filter(l => l.trim().length > 0)
    for (const line of lines) {
      const parts = line.split(',')
      if (parts.length >= 2) {
        const val = parseInt(parts[parts.length - 1].trim(), 10)
        if (!isNaN(val) && val > 0 && val < 120) {
          _lastTemp = val
          _lastTempTime = now
          return val
        }
      }
    }
  } catch { /* skip */ }

  return null
}

// ── Running processes ──

function getRunningProcesses(): SystemProcess[] {
  const processes: SystemProcess[] = []

  try {
    const out = execSync('tasklist /FO CSV /NH', { encoding: 'utf-8', timeout: 5000 })
    for (const line of out.trim().split('\n')) {
      try {
        const parts = line.match(/"([^"]+)",(\d+),(\d+),"([^"]+)"/)
        if (!parts) continue
        const name = parts[1]
        const pid = parseInt(parts[2], 10)
        const memStr = parts[3].replace(/[^0-9]/g, '')
        const memKb = parseInt(memStr, 10) || 0

        processes.push({
          pid,
          name,
          memoryMB: Math.round(memKb / 1024),
          cpuPercent: 0, // tasklist doesn't provide CPU %
        })
      } catch { /* skip malformed line */ }
    }
  } catch { /* tasklist failed */ }

  // Sort by memory descending, top 30
  processes.sort((a, b) => b.memoryMB - a.memoryMB)
  return processes.slice(0, 30)
}

// ── Snapshot ──

export function getSystemSnapshot(): SystemInfoSnapshot {
  const totalMem = os.totalmem()
  const freeMem = os.freemem()
  const usedMem = totalMem - freeMem

  const uptimeSec = os.uptime()
  const uptimeDays = Math.floor(uptimeSec / 86400)
  const uptimeHours = Math.floor((uptimeSec % 86400) / 3600)
  const uptimeMinutes = Math.floor((uptimeSec % 3600) / 60)

  const cpus = os.cpus()
  const cpuModel = cpus.length > 0 ? cpus[0].model.trim() : 'Unknown'

  return {
    cpu: {
      usagePercent: getCpuUsage(),
      cores: cpus.length,
      model: cpuModel,
      loadAvg: [], // Windows doesn't have loadavg
    },
    memory: {
      totalGB: parseFloat((totalMem / 1024 / 1024 / 1024).toFixed(1)),
      usedGB: parseFloat((usedMem / 1024 / 1024 / 1024).toFixed(1)),
      freeGB: parseFloat((freeMem / 1024 / 1024 / 1024).toFixed(1)),
      usagePercent: Math.round((usedMem / totalMem) * 100),
    },
    temperature: getTemperature(),
    uptime: {
      days: uptimeDays,
      hours: uptimeHours,
      minutes: uptimeMinutes,
    },
    os: {
      platform: os.platform(),
      release: os.release(),
      arch: os.arch(),
      hostname: os.hostname(),
    },
    processes: getRunningProcesses(),
    timestamp: Date.now(),
  }
}

// ── Register IPC handlers ──

export function registerSystemInfoHandlers() {
  ipcMain.handle('get-system-snapshot', () => {
    return getSystemSnapshot()
  })
}
