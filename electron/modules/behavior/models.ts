import type { DetectionKind, ScanContext } from '../../core/models'

export type ProcessLocation =
  | 'system'
  | 'program-data'
  | 'user-writable'
  | 'temporary'
  | 'unknown'

export type SignatureState = 'valid' | 'invalid' | 'absent' | 'unknown'

export type ParentRelation =
  | 'normal'
  | 'orphaned'
  | 'cross-session'
  | 'unexpected'
  | 'unknown'

export type MemoryOperationKind =
  | 'process-exit'
  | 'process-open'
  | 'memory-allocate'
  | 'memory-write'
  | 'memory-protect'
  | 'image-map'
  | 'remote-thread'
  | 'apc-queue'
  | 'handle-duplicate'

export type MemoryProtection =
  | 'read'
  | 'read-write'
  | 'read-execute'
  | 'read-write-execute'
  | 'unknown'

export interface ProcessSnapshot {
  readonly stableId: string
  readonly parentStableId?: string
  readonly parentRelation: ParentRelation
  readonly location: ProcessLocation
  readonly signature: SignatureState
  readonly startedAt: number
  readonly observedAt: number
  readonly lifetimeMs?: number
  readonly childCount: number
  readonly isSystemProcess: boolean
}

export interface BehaviorEvent {
  readonly eventId: string
  readonly observedAt: number
  readonly sourceId: string
  readonly targetId?: string
  readonly operation: MemoryOperationKind
  readonly protection?: MemoryProtection
  readonly bytes?: number
  readonly crossProcess: boolean
  readonly succeeded: boolean
  readonly sourceExitedWithinMs?: number
}

export type ObservationStatus = 'complete' | 'partial'

export interface BehaviorSnapshot {
  readonly processes: readonly ProcessSnapshot[]
  readonly events: readonly BehaviorEvent[]
  /** Partial observations must never be interpreted as a clean scan. */
  readonly observationStatus?: ObservationStatus
  readonly observationWarning?: string
}

export interface FileObservation {
  readonly stableId: string
  readonly location: ProcessLocation
  readonly signature: SignatureState
  readonly firstSeenAt: number
  readonly observedAt: number
  readonly executed: boolean
  readonly executionCount: number
  readonly transientLifetimeMs?: number
}

export type BehaviorSignalType =
  | 'cross-process-memory-write'
  | 'executable-memory-after-write'
  | 'remote-execution'
  | 'multi-target-access'
  | 'rapid-source-exit'
  | 'user-writable-launch'
  | 'unsigned-recent-execution'
  | 'orphaned-parent'
  | 'unexpected-parent'
  | 'short-lived-execution'

export interface BehaviorSignal {
  readonly id: string
  readonly subjectId: string
  readonly type: BehaviorSignalType
  readonly confidence: number
  readonly explanation: string
  readonly observedAt: number
}

export interface BehaviorObservationPort {
  collect(context: ScanContext): Promise<BehaviorSnapshot>
}

export interface FileObservationPort {
  collect(context: ScanContext): Promise<readonly FileObservation[]>
}

export interface BehaviorHistory {
  readonly subjectId: string
  readonly events: readonly BehaviorEvent[]
}

export type DetectorKind = Extract<DetectionKind, 'process' | 'memory' | 'file'>
