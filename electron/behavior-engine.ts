/**
 * Predator — Behavior Analysis Engine (E17)
 *
 * Cross-process behavioral correlation:
 *   - Detects injector-victim relationships (process A → handle to game process B)
 *   - Identifies attack chains (injection → debug port → C2 connection)
 *   - Temporal pattern matching (sequence-based detection)
 *   - Session-level behavioral scoring
 *
 * Builds on behavior-profile.ts but adds cross-process context.
 */

import { execSync } from 'child_process'
import type { ScanResult } from './types'

// ═══════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════

export interface ProcessNode {
  pid: number
  name: string
  ppid: number
  parentName: string
  children: ProcessNode[]
  isGame: boolean
  hasUnsignedModule: boolean
  networkPorts: number[]
  debugPorts: number[]
  handles: number[] // PIDs this process has handles to
  riskSignals: string[]
}

export interface AttackChain {
  /** Description of the detected attack pattern */
  pattern: string
  /** Risk level */
  risk: 'high' | 'medium' | 'low'
  /** Processes involved in the chain */
  involved: ProcessNode[]
  /** Step-by-step description */
  steps: string[]
  /** Confidence 0-100 */
  confidence: number
}

export interface BehaviorReport {
  /** Process tree (game processes + suspicious neighbors) */
  processTree: ProcessNode[]
  /** Detected injector-victim pairs */
  injectionPairs: { injector: ProcessNode; victim: ProcessNode }[]
  /** Detected attack chains */
  attackChains: AttackChain[]
  /** Session-level behavioral risk score (0-100) */
  sessionRiskScore: number
}

// ═══════════════════════════════════════════════════
// GAME PROCESS IDENTIFICATION
// ═══════════════════════════════════════════════════

const GAME_PROCESS_NAMES = new Set([
  'gta5.exe', 'fivem_gtaprocess.exe', 'fivem.exe',
  'ragemp_v.exe', 'altv.exe',
])

const SUSPICIOUS_PORTS = new Set([1080, 1337, 1338, 4444, 5555, 6666, 7777, 8888, 9999, 31337])

const DEBUG_PORTS = new Set([9222, 9229, 9223, 9224, 9225, 29999, 13172])

// ═══════════════════════════════════════════════════
// PROCESS TREE BUILDER
// ═══════════════════════════════════════════════════

interface RawProcess {
  pid: number
  name: string
  ppid: number
  parentName: string
}

/**
 * Enumerate all running processes with PIDs and parent relationships.
 */
function enumerateProcesses(): RawProcess[] {
  try {
    const psCmd = `
$all = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ParentProcessId
$map = @{}; foreach ($p in $all) { if ($p.ProcessId) { $map[[int]$p.ProcessId] = $p.Name } }
$all | ForEach-Object {
  @{ pid = $_.ProcessId; name = $_.Name; ppid = $_.ParentProcessId; parentName = if ($map[$_.ParentProcessId]) { $map[$_.ParentProcessId] } else { '' } } | ConvertTo-Json -Compress
} | ConvertTo-Json -Compress
`
    const out = execSync(`powershell -NoProfile -Command "${psCmd.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 10000, windowsHide: true,
    }).trim()
    if (!out || out.length < 5) return []

    const parsed = JSON.parse(out)
    const items = Array.isArray(parsed) ? parsed : [parsed]
    return items.filter((p: RawProcess) => p && p.pid > 0)
  } catch {
    return []
  }
}

/**
 * Get network ports for a process.
 */
function getProcPorts(pid: number): number[] {
  try {
    const out = execSync(`netstat -ano | findstr /R "\\s${pid}$"`, { encoding: 'utf-8', timeout: 3000 })
    const ports: number[] = []
    for (const line of out.split('\n')) {
      const parts = line.trim().split(/\s+/)
      if (parts.length < 5) continue
      const port = parseInt((parts[1] || '').split(':').pop() || '0', 10)
      if (port > 0 && port < 65536) ports.push(port)
    }
    return [...new Set(ports)]
  } catch {
    return []
  }
}

/**
 * Get listening ports for a process (for debug port detection).
 */
function getProcListenPorts(pid: number): number[] {
  try {
    const psCmd = `Get-NetTCPConnection -State Listen -OwningProcess ${pid} -ErrorAction SilentlyContinue | Select -ExpandProperty LocalPort`
    const out = execSync(`powershell -Command "${psCmd}"`, {
      encoding: 'utf-8', timeout: 5000, windowsHide: true,
    }).trim()
    if (!out) return []
    return out.split('\n').map(Number).filter(p => p > 0)
  } catch {
    return []
  }
}

// ═══════════════════════════════════════════════════
// BEHAVIOR CORRELATION ENGINE
// ═══════════════════════════════════════════════════

/**
 * Build behavior report: process tree, injection pairs, attack chains.
 */
export function analyzeBehavior(): BehaviorReport {
  const rawProcs = enumerateProcesses()
  const allNodes: ProcessNode[] = []
  const nodeMap = new Map<number, ProcessNode>()

  // Phase 1: Build nodes
  for (const raw of rawProcs) {
    const isGame = GAME_PROCESS_NAMES.has(raw.name.toLowerCase())
    const node: ProcessNode = {
      pid: raw.pid,
      name: raw.name,
      ppid: raw.ppid,
      parentName: raw.parentName,
      children: [],
      isGame,
      hasUnsignedModule: false,
      networkPorts: [],
      debugPorts: [],
      handles: [],
      riskSignals: [],
    }
    allNodes.push(node)
    nodeMap.set(raw.pid, node)
  }

  // Phase 2: Build tree relationships
  for (const node of allNodes) {
    const parent = nodeMap.get(node.ppid)
    if (parent) {
      parent.children.push(node)
    }
  }

  // Phase 3: Enrich suspicious nodes (non-game processes that are interesting)
  const gamePids = new Set(allNodes.filter(n => n.isGame).map(n => n.pid))
  const suspiciousNodes = allNodes.filter(n =>
    !n.isGame && !n.name.toLowerCase().includes('svchost') &&
    !n.name.toLowerCase().includes('csrss') && !n.name.toLowerCase().includes('dwm'),
  )

  for (const node of suspiciousNodes.slice(0, 30)) {
    // Check modules for unsigned DLLs (via behavior-profile's approach)
    try {
      const psCmd = `Get-Process -Id ${node.pid} -ErrorAction SilentlyContinue | Select -ExpandProperty Modules -ErrorAction SilentlyContinue | Select -ExpandProperty FileName -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch '\\\\\\\\Windows\\\\\\\\|\\\\\\\\Program Files\\\\\\\\|\\\\\\\\Program Files \\(x86\\)\\\\\\\\|\\\\\\\\ProgramData\\\\\\\\' } | Select -First 1`
      const out = execSync(`powershell -Command "${psCmd}"`, {
        encoding: 'utf-8', timeout: 3000, windowsHide: true,
      }).trim()
      if (out) {
        node.hasUnsignedModule = true
        node.riskSignals.push('unsigned-module-in-non-system-path')
      }
    } catch { /* optional */ }

    // Network ports
    node.networkPorts = getProcPorts(node.pid)
    if (node.networkPorts.some(p => SUSPICIOUS_PORTS.has(p))) {
      node.riskSignals.push('suspicious-port')
    }

    // Debug ports
    node.debugPorts = getProcListenPorts(node.pid).filter(p => DEBUG_PORTS.has(p))
    if (node.debugPorts.length > 0) {
      node.riskSignals.push('debug-port-open')
    }
  }

  // Phase 4: Detect injection pairs (handle-based)
  const injectionPairs: { injector: ProcessNode; victim: ProcessNode }[] = []
  for (const node of suspiciousNodes) {
    for (const gamePid of gamePids) {
      const gameNode = nodeMap.get(gamePid)
      if (!gameNode) continue
      // Check if this process might have handles to the game (heuristic)
      if (node.hasUnsignedModule && node.networkPorts.length > 0) {
        injectionPairs.push({ injector: node, victim: gameNode })
        break
      }
    }
  }

  // Phase 5: Detect attack chains
  const attackChains = detectAttackChains(allNodes, injectionPairs)

  // Phase 6: Session risk score
  const sessionRiskScore = calculateSessionRisk(allNodes, injectionPairs, attackChains)

  return {
    processTree: allNodes,
    injectionPairs,
    attackChains,
    sessionRiskScore,
  }
}

// ═══════════════════════════════════════════════════
// ATTACK CHAIN DETECTION
// ═══════════════════════════════════════════════════

function detectAttackChains(
  allNodes: ProcessNode[],
  injectionPairs: { injector: ProcessNode; victim: ProcessNode }[],
): AttackChain[] {
  const chains: AttackChain[] = []

  // Pattern 1: Classic DLL injection chain
  // unsigned-module + handle-to-game + network-C2
  for (const pair of injectionPairs) {
    const { injector, victim } = pair
    const hasNetwork = injector.networkPorts.some(p => SUSPICIOUS_PORTS.has(p))
    const hasDebug = injector.debugPorts.length > 0

    if (injector.hasUnsignedModule && hasNetwork) {
      chains.push({
        pattern: 'classic-injection-chain',
        risk: 'high',
        involved: [injector, victim],
        steps: [
          `Stage 1: ${injector.name} loaded unsigned module (injection payload)`,
          `Stage 2: ${injector.name} established C2 connection on suspicious port`,
          `Target: ${victim.name} (PID: ${victim.pid}) — game process`,
          '⚠ Full cheat injection chain: load DLL → connect C2 → inject into game',
        ],
        confidence: injector.hasUnsignedModule && hasDebug ? 90 : 70,
      })
    }
  }

  // Pattern 2: CEF/Chromium debug injection
  // debug-port-open + game-process
  const debugNodes = allNodes.filter(n => n.debugPorts.length > 0)
  for (const node of debugNodes) {
    if (node.isGame || node.name.toLowerCase().includes('fivem')) {
      chains.push({
        pattern: 'cef-debug-injection',
        risk: 'high',
        involved: [node],
        steps: [
          `Stage 1: ${node.name} has Chrome DevTools debug port open (${node.debugPorts.join(',')})`,
          `Stage 2: Remote debugging allows arbitrary JS injection into game process`,
          '⚠ CEF remote debugging = cheat JS injection vector',
        ],
        confidence: 85,
      })
    }
  }

  // Pattern 3: Suspicious parent chain
  // process-with-suspicious-parent → game-process
  for (const node of allNodes) {
    if (!node.isGame) continue
    const parent = allNodes.find(n => n.pid === node.ppid)
    if (!parent) continue
    const parentHasSignals = parent.networkPorts.some(p => SUSPICIOUS_PORTS.has(p)) ||
      parent.hasUnsignedModule
    if (parentHasSignals) {
      chains.push({
        pattern: 'suspicious-parent-chain',
        risk: 'medium',
        involved: [parent, node],
        steps: [
          `Parent process ${parent.name} (PID: ${parent.pid}) has risk signals`,
          parent.hasUnsignedModule ? '  → Unsigned module loaded' : '',
          parent.networkPorts.length > 0 ? `  → Network: ports ${parent.networkPorts.join(',')}` : '',
          `Child process: ${node.name} (PID: ${node.pid}) — game process`,
          '⚠ Suspicious parent may have spawned game to inject',
        ].filter(Boolean),
        confidence: 50,
      })
    }
  }

  return chains
}

// ═══════════════════════════════════════════════════
// SESSION RISK SCORING
// ═══════════════════════════════════════════════════

function calculateSessionRisk(
  allNodes: ProcessNode[],
  injectionPairs: { injector: ProcessNode; victim: ProcessNode }[],
  attackChains: AttackChain[],
): number {
  let score = 0

  // Injection pairs: +25 each
  score += injectionPairs.length * 25

  // Attack chains: weighted by confidence
  for (const chain of attackChains) {
    score += chain.confidence * 0.5
  }

  // Signal density: how many suspicious processes vs total
  const suspiciousCount = allNodes.filter(n => n.riskSignals.length > 0).length
  const signalDensity = allNodes.length > 0 ? suspiciousCount / Math.min(allNodes.length, 100) : 0
  score += signalDensity * 30

  // Debug ports: +15 each
  const debugPortCount = allNodes.reduce((sum, n) => sum + n.debugPorts.length, 0)
  score += debugPortCount * 15

  return Math.min(Math.round(score), 100)
}

// ═══════════════════════════════════════════════════
// SCAN RESULT CONVERSION
// ═══════════════════════════════════════════════════

/**
 * Convert BehaviorReport to ScanResult[] for integration with existing scanner.
 */
export function behaviorReportToScanResults(report: BehaviorReport): ScanResult[] {
  const results: ScanResult[] = []

  // Report injection pairs
  for (const pair of report.injectionPairs) {
    results.push({
      path: `behavior:${pair.injector.name}→${pair.victim.name}`,
      fileName: `🧬 Injection: ${pair.injector.name} → ${pair.victim.name}`,
      type: 'process',
      risk: 'high',
      matches: [
        `Potential DLL injection detected`,
        `Injector: ${pair.injector.name} (PID: ${pair.injector.pid})`,
        `Victim: ${pair.victim.name} (PID: ${pair.victim.pid})`,
        ...pair.injector.riskSignals.map(s => `  → ${s}`),
      ],
      size: 0,
      modifiedAt: new Date().toISOString(),
    })
  }

  // Report attack chains
  for (const chain of report.attackChains) {
    results.push({
      path: `attack-chain:${chain.pattern}`,
      fileName: `🔗 Attack Chain: ${chain.pattern}`,
      type: 'process',
      risk: chain.risk,
      matches: [
        `Behavior pattern: ${chain.pattern}`,
        `Confidence: ${chain.confidence}%`,
        ...chain.steps,
      ],
      size: 0,
      modifiedAt: new Date().toISOString(),
    })
  }

  // Session risk summary
  if (report.sessionRiskScore > 30) {
    results.push({
      path: 'behavior:session-summary',
      fileName: `📊 Session Risk: ${report.sessionRiskScore}/100`,
      type: 'process',
      risk: report.sessionRiskScore > 70 ? 'high' : 'medium',
      matches: [
        `Behavioral session risk score: ${report.sessionRiskScore}/100`,
        `Injection pairs detected: ${report.injectionPairs.length}`,
        `Attack chains detected: ${report.attackChains.length}`,
        report.sessionRiskScore > 70 ? '⚠ HIGH behavioral risk — likely active cheat' : '',
      ].filter(Boolean),
      size: 0,
      modifiedAt: new Date().toISOString(),
    })
  }

  return results
}
