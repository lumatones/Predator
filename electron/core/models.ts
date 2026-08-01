/**
 * Core scan models.
 *
 * This module has no Electron, Node.js, filesystem or transport dependencies.
 * It is safe to reuse from the detection engine and platform adapters.
 */

export type DetectionKind =
  | 'process'
  | 'memory'
  | 'file'
  | 'registry'
  | 'driver'
  | 'browser'
  | 'network'
  | 'integrity'

export type RiskLevel = 'clean' | 'low' | 'medium' | 'high' | 'critical'

export type DetectorStatus =
  | 'completed'
  | 'failed'
  | 'timeout'
  | 'unsupported'

export interface ScanEvidence {
  readonly id: string
  readonly source: string
  readonly category: string
  readonly explanation: string
  readonly confidence: number
  readonly digest?: string
  readonly observedAt: string
}

export interface ScanSubject {
  readonly kind: DetectionKind
  /** A stable, privacy-preserving identifier for the observed subject. */
  readonly stableId: string
  readonly displayName?: string
}

export interface IScanResult {
  readonly findingId: string
  readonly detectorId: string
  readonly detectorVersion: string
  readonly kind: DetectionKind
  readonly subject: ScanSubject
  readonly risk: RiskLevel
  readonly score: number
  readonly confidence: number
  readonly categories: readonly string[]
  readonly evidence: readonly ScanEvidence[]
  readonly observedAt: string
}

export interface ScanContext {
  readonly sessionId: string
  readonly signal: AbortSignal
  readonly startedAt: number
  readonly deadlineAt: number
  readonly policyVersion: string
  readonly metadata: Readonly<Record<string, string>>
}

export interface DetectorReport {
  readonly detectorId: string
  readonly detectorVersion: string
  readonly status: DetectorStatus
  readonly results: readonly IScanResult[]
  readonly startedAt: string
  readonly completedAt: string
  readonly evidenceDigest?: string
  readonly errorCode?: string
  readonly errorMessage?: string
}

export interface DetectorFailure {
  readonly detectorId: string
  readonly status: Exclude<DetectorStatus, 'completed'>
  readonly errorCode?: string
  readonly errorMessage?: string
}

export interface EngineReport {
  readonly sessionId: string
  readonly results: readonly IScanResult[]
  readonly reports: readonly DetectorReport[]
  readonly failures: readonly DetectorFailure[]
  readonly startedAt: string
  readonly completedAt: string
}
