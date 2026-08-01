import type { DetectorReport, IScanResult, ScanContext } from '../../core/models'
import type { IDetector } from '../../core/ports'
import type {
  BehaviorSignal,
  FileObservation,
  FileObservationPort,
} from './models'
import { ScoringEngine } from './scoring-engine'

const DETECTOR_ID = 'behavioral-file-scanner'
const DETECTOR_VERSION = '1.0.0'

function timestamp(): string {
  return new Date().toISOString()
}

function toSignals(observation: FileObservation): readonly BehaviorSignal[] {
  const signals: BehaviorSignal[] = []

  if (observation.location === 'user-writable') {
    signals.push({
      id: `${observation.stableId}:user-writable-launch`,
      subjectId: observation.stableId,
      type: 'user-writable-launch',
      confidence: 0.55,
      explanation: 'Executable activity originated from a user-writable location',
      observedAt: observation.observedAt,
    })
  }

  if (observation.executed && (observation.signature === 'absent' || observation.signature === 'invalid')) {
    signals.push({
      id: `${observation.stableId}:unsigned-recent-execution`,
      subjectId: observation.stableId,
      type: 'unsigned-recent-execution',
      confidence: observation.signature === 'invalid' ? 0.7 : 0.5,
      explanation: 'Executed file has no valid publisher signature',
      observedAt: observation.observedAt,
    })
  }

  if (observation.transientLifetimeMs !== undefined && observation.transientLifetimeMs <= 15_000) {
    signals.push({
      id: `${observation.stableId}:short-lived-execution`,
      subjectId: observation.stableId,
      type: 'short-lived-execution',
      confidence: 0.45,
      explanation: 'Executed file terminated shortly after launch',
      observedAt: observation.observedAt,
    })
  }

  return signals
}

export interface FileScannerDependencies {
  readonly observationPort: FileObservationPort
  readonly scoringEngine?: ScoringEngine
}

/**
 * Detects suspicious execution origin and lifecycle without inspecting names,
 * hashes, paths or file contents.
 */
export class FileScanner implements IDetector {
  readonly id = DETECTOR_ID
  readonly version = DETECTOR_VERSION
  readonly kind = 'file' as const
  readonly required = false
  readonly capabilities = ['execution-origin', 'signature-state', 'lifecycle'] as const

  private readonly observationPort: FileObservationPort
  private readonly scoringEngine: ScoringEngine

  constructor(dependencies: FileScannerDependencies) {
    this.observationPort = dependencies.observationPort
    this.scoringEngine = dependencies.scoringEngine ?? new ScoringEngine()
  }

  supports(_context: ScanContext): boolean {
    return true
  }

  async scan(context: ScanContext): Promise<DetectorReport> {
    const startedAt = timestamp()
    const observations = await this.observationPort.collect(context)
    if (context.signal.aborted) {
      return {
        detectorId: this.id,
        detectorVersion: this.version,
        status: 'timeout',
        results: [],
        startedAt,
        completedAt: timestamp(),
        errorCode: 'SCAN_ABORTED',
        errorMessage: 'File observation was cancelled',
      }
    }

    const results: IScanResult[] = []
    for (const observation of observations) {
      const signals = toSignals(observation)
      const evaluation = this.scoringEngine.evaluate(signals)
      if (evaluation.score === 0) continue

      results.push({
        findingId: `${DETECTOR_ID}:${observation.stableId}`,
        detectorId: this.id,
        detectorVersion: this.version,
        kind: 'file',
        subject: {
          kind: 'file',
          stableId: observation.stableId,
        },
        risk: evaluation.risk,
        score: evaluation.score,
        confidence: evaluation.confidence,
        categories: evaluation.categories,
        evidence: signals.map(signal => ({
          id: signal.id,
          source: DETECTOR_ID,
          category: signal.type,
          explanation: signal.explanation,
          confidence: signal.confidence,
          observedAt: new Date(signal.observedAt).toISOString(),
        })),
        observedAt: new Date(observation.observedAt).toISOString(),
      })
    }

    return {
      detectorId: this.id,
      detectorVersion: this.version,
      status: 'completed',
      results,
      startedAt,
      completedAt: timestamp(),
    }
  }
}
