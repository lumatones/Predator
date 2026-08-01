import crypto from 'crypto'
import os from 'os'
import path from 'path'
import { execPowerShellAsync } from '../../utils/exec'
import type { ScanContext } from '../../core/models'
import type {
  BehaviorEvent,
  BehaviorObservationPort,
  BehaviorSnapshot,
  ParentRelation,
  ProcessLocation,
  ProcessSnapshot,
  SignatureState,
} from './models'
import { processObservationCache } from './process-observation-cache'

interface RawProcessRecord {
  readonly ProcessId?: number
  readonly ParentProcessId?: number
  readonly CreationDate?: string
  readonly ExecutablePath?: string
  readonly SignatureStatus?: string
  readonly SignatureAvailable?: boolean
  readonly ModulesAvailable?: boolean
  readonly IsSystemProcess?: boolean
  readonly Name?: string
  readonly Modules?: string[]
}

interface TrackedProcess {
  readonly stableId: string
  readonly pid: number
  readonly startedAt: number
  readonly observedAt: number
}

function parseJsonRecords(output: string): readonly RawProcessRecord[] {
  if (!output.trim()) throw new Error('Windows process observation returned empty output')

  try {
    const parsed: unknown = JSON.parse(output)
    if (Array.isArray(parsed)) return parsed.filter(isRecord)
    return isRecord(parsed) ? [parsed] : []
  } catch {
    throw new Error('Windows process observation returned invalid JSON')
  }
}

function isRecord(value: unknown): value is RawProcessRecord {
  return typeof value === 'object' && value !== null
}

function parseTimestamp(value: string | undefined, fallback: number): number {
  if (!value) return fallback
  const parsed = Date.parse(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

function stableId(pid: number, startedAt: number): string {
  return `process:${crypto.createHash('sha256').update(`${pid}:${startedAt}`).digest('hex').slice(0, 24)}`
}

function normalizePath(value: string): string {
  return path.normalize(value).toLowerCase()
}

function isWithin(candidate: string, root: string): boolean {
  const normalizedCandidate = normalizePath(candidate)
  const normalizedRoot = normalizePath(root).replace(/[\\/]$/, '')
  return normalizedCandidate === normalizedRoot || normalizedCandidate.startsWith(`${normalizedRoot}${path.sep}`)
}

function classifyLocation(executablePath: string | undefined): ProcessLocation {
  if (!executablePath) return 'unknown'

  const home = os.homedir()
  const systemRoot = process.env.SystemRoot || 'C:\\Windows'
  const programFiles = process.env.ProgramFiles || 'C:\\Program Files'
  const programFilesX86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)'
  const programData = process.env.ProgramData || 'C:\\ProgramData'
  const localAppData = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local')
  const roamingAppData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming')
  const temp = process.env.TEMP || process.env.TMP || path.join(localAppData, 'Temp')

  if (isWithin(executablePath, systemRoot) || isWithin(executablePath, programFiles) || isWithin(executablePath, programFilesX86)) {
    return 'system'
  }
  if (isWithin(executablePath, programData)) return 'program-data'
  if (isWithin(executablePath, temp)) return 'temporary'
  if (isWithin(executablePath, localAppData) || isWithin(executablePath, roamingAppData) || isWithin(executablePath, home)) {
    return 'user-writable'
  }
  return 'unknown'
}

function normalizeSignature(status: string | undefined): SignatureState {
  switch ((status || '').toLowerCase()) {
    case 'valid': return 'valid'
    case 'notsigned': return 'absent'
    case 'unknownerror':
    case 'nottrusted':
    case 'hashmismatch': return 'invalid'
    default: return 'unknown'
  }
}

function parentRelation(
  parentPid: number | undefined,
  currentByPid: ReadonlyMap<number, TrackedProcess>,
): ParentRelation {
  if (!parentPid || parentPid <= 0) return 'orphaned'
  return currentByPid.has(parentPid) ? 'normal' : 'unknown'
}

function processQuery(): string {
  // No user-controlled values are interpolated into this script.
  return `
    $moduleMap = @{}
    $moduleAvailability = @{}
    Get-Process | ForEach-Object {
      try {
        $moduleMap[[int]$_.Id] = @($_.Modules | ForEach-Object { $_.ModuleName })
        $moduleAvailability[[int]$_.Id] = $true
      } catch {
        $moduleAvailability[[int]$_.Id] = $false
      }
    }
    $records = @(
      Get-CimInstance Win32_Process | ForEach-Object {
        $signatureStatus = 'Unknown'
        $signatureAvailable = $true
        if ($_.ExecutablePath) {
          try { $signatureStatus = (Get-AuthenticodeSignature -FilePath $_.ExecutablePath -ErrorAction Stop).Status.ToString() } catch { $signatureAvailable = $false }
        }
        [PSCustomObject]@{
          ProcessId = [int]$_.ProcessId
          ParentProcessId = [int]$_.ParentProcessId
          CreationDate = if ($_.CreationDate) { $_.CreationDate.ToString('o') } else { $null }
          ExecutablePath = $_.ExecutablePath
          SignatureStatus = $signatureStatus
          SignatureAvailable = $signatureAvailable
          ModulesAvailable = if ($moduleAvailability.ContainsKey([int]$_.ProcessId)) { [bool]$moduleAvailability[[int]$_.ProcessId] } else { $false }
          IsSystemProcess = ([int]$_.ProcessId -le 4)
          Name = [string]$_.Name
          Modules = @($moduleMap[[int]$_.ProcessId])
        }
      }
    )
    $records | ConvertTo-Json -Depth 4 -Compress
  `.trim()
}

/**
 * Windows adapter for the behavioral detector.
 *
 * It keeps executable paths inside the adapter only for local classification;
 * paths are never included in BehaviorSnapshot or sent to the UI/transport.
 */
export class WindowsProcessObservationPort implements BehaviorObservationPort {
  private readonly previous = new Map<number, TrackedProcess>()

  async collect(context: ScanContext): Promise<BehaviorSnapshot> {
    const observedAt = Date.now()
    const output = await execPowerShellAsync(processQuery(), {
      timeout: Math.max(1, Math.min(10_000, context.deadlineAt - observedAt)),
      signal: context.signal,
    })

    if (output === null) throw new Error('Windows process observation failed')

    const records = parseJsonRecords(output)
    const current = new Map<number, TrackedProcess>()
    const rawByPid = new Map<number, RawProcessRecord>()

    for (const record of records) {
      const pid = typeof record.ProcessId === 'number' ? record.ProcessId : 0
      if (pid <= 0) continue

      const startedAt = parseTimestamp(record.CreationDate, observedAt)
      current.set(pid, { stableId: stableId(pid, startedAt), pid, startedAt, observedAt })
      rawByPid.set(pid, record)
    }

    const childCounts = new Map<number, number>()
    for (const record of rawByPid.values()) {
      const parentPid = record.ParentProcessId
      if (typeof parentPid !== 'number') continue
      childCounts.set(parentPid, (childCounts.get(parentPid) ?? 0) + 1)
    }

    const snapshots: ProcessSnapshot[] = []
    for (const [pid, process] of current) {
      const record = rawByPid.get(pid)
      snapshots.push({
        stableId: process.stableId,
        parentRelation: parentRelation(record?.ParentProcessId, current),
        location: classifyLocation(record?.ExecutablePath),
        signature: normalizeSignature(record?.SignatureStatus),
        startedAt: process.startedAt,
        observedAt,
        childCount: childCounts.get(pid) ?? 0,
        isSystemProcess: record?.IsSystemProcess === true,
      })
    }

    const events: BehaviorEvent[] = []
    for (const previous of this.previous.values()) {
      if (current.has(previous.pid)) continue

      const lifetimeMs = Math.max(0, observedAt - previous.startedAt)
      snapshots.push({
        stableId: previous.stableId,
        parentRelation: 'unknown',
        location: 'unknown',
        signature: 'unknown',
        startedAt: previous.startedAt,
        observedAt,
        lifetimeMs,
        childCount: 0,
        isSystemProcess: false,
      })
      events.push({
        eventId: `${previous.stableId}:exit:${observedAt}`,
        observedAt,
        sourceId: previous.stableId,
        operation: 'process-exit',
        crossProcess: false,
        succeeded: true,
        sourceExitedWithinMs: lifetimeMs,
      })
    }

    const incompleteRecords = records.filter(record =>
      record.ModulesAvailable === false || record.SignatureAvailable === false,
    )
    if (incompleteRecords.length > 0) {
      return {
        processes: snapshots,
        events,
        observationStatus: 'partial',
        observationWarning: `Process metadata unavailable for ${incompleteRecords.length} process record(s)`,
      }
    }

    this.previous.clear()
    for (const [pid, process] of current) this.previous.set(pid, process)

    processObservationCache.replace(records
      .filter(record => typeof record.ProcessId === 'number' && record.ProcessId > 0)
      .map(record => ({
        id: record.ProcessId as number,
        name: record.Name ?? '',
        modules: Array.isArray(record.Modules)
          ? record.Modules.filter((module): module is string => typeof module === 'string')
          : [],
      })), observedAt, context.sessionId)

    return {
      processes: snapshots,
      events,
      observationStatus: 'complete',
    }
  }
}
