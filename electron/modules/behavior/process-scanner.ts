import type {
  DetectorReport,
  IScanResult,
  ScanContext,
} from '../../core/models'
import type { IDetector } from '../../core/ports'
import type {
  BehaviorObservationPort,
  BehaviorSignal,
  BehaviorSnapshot,
} from './models'
import { BehaviorTracker } from './behavior-tracker'
import { InjectionDetector } from './injection-detector'
import { ScoringEngine } from './scoring-engine'

const DETECTOR_ID = 'behavioral-process-scanner'
const DETECTOR_VERSION = '1.0.0'

function timestamp(): string {
  return new Date().toISOString()
}

function toResult(
  subjectId: string,
  signals: readonly BehaviorSignal[],
  score: ReturnType<ScoringEngine['evaluate']>,
): IScanResult {
  const observedAt = new Date(Math.max(...signals.map(signal => signal.observedAt))).toISOString()
  return {
    findingId: `${DETECTOR_ID}:${subjectId}`,
    detectorId: DETECTOR_ID,
    detectorVersion: DETECTOR_VERSION,
    kind: 'process',
    subject: {
      kind: 'process',
      stableId: subjectId,
    },
    risk: score.risk,
    score: score.score,
    confidence: score.confidence,
    categories: score.categories,
    evidence: signals.map(signal => ({
      id: signal.id,
      source: DETECTOR_ID,
      category: signal.type,
      explanation: signal.explanation,
      confidence: signal.confidence,
      observedAt: new Date(signal.observedAt).toISOString(),
    })),
    observedAt,
  }
}

export interface ProcessScannerDependencies {
  readonly observationPort: BehaviorObservationPort
  readonly tracker?: BehaviorTracker
  readonly injectionDetector?: InjectionDetector
  readonly scoringEngine?: ScoringEngine
}

/**
 * Detects loader-like behavior from normalized process and memory telemetry.
 * The scanner never receives paths, filenames, hashes or memory bytes.
 */
export class ProcessScanner implements IDetector {
  readonly id = DETECTOR_ID
  readonly version = DETECTOR_VERSION
  readonly kind = 'process' as const
  readonly required = false
  readonly capabilities = [
    'process-lifecycle',
    'parent-lineage',
    'cross-process-memory-metadata',
  ] as const

  private readonly observationPort: BehaviorObservationPort
  private readonly tracker: BehaviorTracker
  private readonly injectionDetector: InjectionDetector
  private readonly scoringEngine: ScoringEngine

  constructor(dependencies: ProcessScannerDependencies) {
    this.observationPort = dependencies.observationPort
    this.tracker = dependencies.tracker ?? new BehaviorTracker()
    this.injectionDetector = dependencies.injectionDetector ?? new InjectionDetector()
    this.scoringEngine = dependencies.scoringEngine ?? new ScoringEngine()
  }

  supports(_context: ScanContext): boolean {
    return true
  }

  async scan(context: ScanContext): Promise<DetectorReport> {
    const startedAt = timestamp()
    const snapshot: BehaviorSnapshot = await this.observationPort.collect(context)
    if (context.signal.aborted) {
      return {
        detectorId: this.id,
        detectorVersion: this.version,
        status: 'timeout',
        results: [],
        startedAt,
        completedAt: timestamp(),
        errorCode: 'SCAN_ABORTED',
        errorMessage: 'Process observation was cancelled',
      }
    }

    if (snapshot.observationStatus === 'partial') {
      return {
        detectorId: this.id,
        detectorVersion: this.version,
        status: 'failed',
        results: [],
        startedAt,
        completedAt: timestamp(),
        errorCode: 'PARTIAL_OBSERVATION',
        errorMessage: snapshot.observationWarning ?? 'Process observation was incomplete',
      }
    }

    this.tracker.record(snapshot)
    const signals = this.injectionDetector.analyze(snapshot)
    const bySubject = new Map<string, BehaviorSignal[]>()

    for (const item of signals) {
      const subjectSignals = bySubject.get(item.subjectId) ?? []
      subjectSignals.push(item)
      bySubject.set(item.subjectId, subjectSignals)
    }

    const results: IScanResult[] = []
    for (const [subjectId, subjectSignals] of bySubject) {
      const evaluation = this.scoringEngine.evaluate(subjectSignals)
      if (evaluation.score === 0) continue
      results.push(toResult(subjectId, subjectSignals, evaluation))
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
