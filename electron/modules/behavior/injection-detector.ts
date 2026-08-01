import type {
  BehaviorEvent,
  BehaviorSignal,
  BehaviorSignalType,
  BehaviorSnapshot,
  ProcessSnapshot,
} from './models'

const RAPID_EXIT_THRESHOLD_MS = 10_000
const SHORT_LIFETIME_THRESHOLD_MS = 15_000
const MULTI_TARGET_THRESHOLD = 2

function signal(
  subjectId: string,
  type: BehaviorSignalType,
  confidence: number,
  explanation: string,
  observedAt: number,
): BehaviorSignal {
  return {
    id: `${subjectId}:${type}`,
    subjectId,
    type,
    confidence: Math.max(0, Math.min(1, confidence)),
    explanation,
    observedAt,
  }
}

function processSignals(process: ProcessSnapshot): readonly BehaviorSignal[] {
  const signals: BehaviorSignal[] = []

  if (process.location === 'user-writable') {
    signals.push(signal(
      process.stableId,
      'user-writable-launch',
      0.55,
      'Executable activity originated from a user-writable location',
      process.observedAt,
    ))
  }

  if (process.signature === 'absent' || process.signature === 'invalid') {
    signals.push(signal(
      process.stableId,
      'unsigned-recent-execution',
      process.signature === 'invalid' ? 0.7 : 0.5,
      'Executable activity has no valid publisher signature',
      process.observedAt,
    ))
  }

  if (process.parentRelation === 'orphaned') {
    signals.push(signal(
      process.stableId,
      'orphaned-parent',
      0.6,
      'Process has no consistent observable parent relation',
      process.observedAt,
    ))
  }

  if (process.parentRelation === 'unexpected' || process.parentRelation === 'cross-session') {
    signals.push(signal(
      process.stableId,
      'unexpected-parent',
      0.65,
      'Process parent relation is inconsistent with the observed session',
      process.observedAt,
    ))
  }

  if (process.lifetimeMs !== undefined && process.lifetimeMs <= SHORT_LIFETIME_THRESHOLD_MS) {
    signals.push(signal(
      process.stableId,
      'short-lived-execution',
      0.45,
      'Process terminated shortly after execution',
      process.observedAt,
    ))
  }

  return signals
}

function eventSignals(
  processById: ReadonlyMap<string, ProcessSnapshot>,
  events: readonly BehaviorEvent[],
): readonly BehaviorSignal[] {
  const signals: BehaviorSignal[] = []
  const targetsBySource = new Map<string, Set<string>>()

  for (const event of events) {
    if (!event.succeeded) continue

    if (
      event.operation === 'process-exit' &&
      event.sourceExitedWithinMs !== undefined &&
      event.sourceExitedWithinMs <= RAPID_EXIT_THRESHOLD_MS
    ) {
      signals.push(signal(
        event.sourceId,
        'rapid-source-exit',
        0.65,
        'The source process exited shortly after execution',
        event.observedAt,
      ))
      continue
    }

    if (!event.crossProcess) continue

    const source = processById.get(event.sourceId)
    if (!source) continue

    if (event.operation === 'memory-write') {
      signals.push(signal(
        event.sourceId,
        'cross-process-memory-write',
        event.protection === 'read-write-execute' ? 0.85 : 0.65,
        'A process wrote memory in another process',
        event.observedAt,
      ))
    }

    if (
      event.operation === 'memory-protect' &&
      event.protection === 'read-write-execute'
    ) {
      signals.push(signal(
        event.sourceId,
        'executable-memory-after-write',
        0.9,
        'Cross-process memory was made executable after modification',
        event.observedAt,
      ))
    }

    if (event.operation === 'remote-thread' || event.operation === 'apc-queue') {
      signals.push(signal(
        event.sourceId,
        'remote-execution',
        0.9,
        'Cross-process execution was requested through a thread or APC mechanism',
        event.observedAt,
      ))
    }

    if (event.targetId) {
      const targets = targetsBySource.get(event.sourceId) ?? new Set<string>()
      targets.add(event.targetId)
      targetsBySource.set(event.sourceId, targets)
    }

  }

  for (const [subjectId, targets] of targetsBySource) {
    if (targets.size < MULTI_TARGET_THRESHOLD) continue
    signals.push(signal(
      subjectId,
      'multi-target-access',
      0.75,
      'One process interacted with multiple target processes',
      Date.now(),
    ))
  }

  return signals
}

export class InjectionDetector {
  analyze(snapshot: BehaviorSnapshot): readonly BehaviorSignal[] {
    const processById = new Map(snapshot.processes.map(process => [process.stableId, process]))
    const signals: BehaviorSignal[] = []

    for (const process of snapshot.processes) {
      signals.push(...processSignals(process))
    }
    signals.push(...eventSignals(processById, snapshot.events))

    return this.deduplicate(signals)
  }

  private deduplicate(signals: readonly BehaviorSignal[]): readonly BehaviorSignal[] {
    const byId = new Map<string, BehaviorSignal>()
    for (const item of signals) {
      const existing = byId.get(item.id)
      if (!existing || item.confidence > existing.confidence) byId.set(item.id, item)
    }
    return [...byId.values()]
  }
}
