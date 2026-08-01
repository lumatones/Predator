import type { IDetector, IEngine } from './ports'
import type {
  DetectorFailure,
  DetectorReport,
  EngineReport,
  IScanResult,
  ScanContext,
} from './models'

export interface DetectionEngineOptions {
  /** Maximum number of detectors running at the same time. */
  readonly concurrency?: number
  /** Default timeout for one detector, in milliseconds. */
  readonly detectorTimeoutMs?: number
}

const DEFAULT_CONCURRENCY = 2
const DEFAULT_DETECTOR_TIMEOUT_MS = 30_000

const RISK_WEIGHT: Record<IScanResult['risk'], number> = {
  clean: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Unknown detector error'
}

function nowIso(): string {
  return new Date().toISOString()
}

function createFailure(
  detector: IDetector,
  status: DetectorFailure['status'],
  errorCode: string,
  message: string,
): DetectorFailure {
  return {
    detectorId: detector.id,
    status,
    errorCode,
    errorMessage: message,
  }
}

function createFailureReport(
  detector: IDetector,
  startedAt: string,
  status: DetectorFailure['status'],
  errorCode: string,
  message: string,
): DetectorReport {
  return {
    detectorId: detector.id,
    detectorVersion: detector.version,
    status,
    results: [],
    startedAt,
    completedAt: nowIso(),
    errorCode,
    errorMessage: message,
  }
}

function mergeResults(left: IScanResult, right: IScanResult): IScanResult {
  const evidence = new Map<string, IScanResult['evidence'][number]>()
  for (const item of left.evidence) evidence.set(item.id, item)
  for (const item of right.evidence) evidence.set(item.id, item)

  const categories = new Set([...left.categories, ...right.categories])
  const preferred = RISK_WEIGHT[right.risk] > RISK_WEIGHT[left.risk] ? right : left

  return {
    ...preferred,
    score: Math.max(left.score, right.score),
    confidence: Math.max(left.confidence, right.confidence),
    categories: [...categories],
    evidence: [...evidence.values()],
    observedAt: left.observedAt <= right.observedAt ? left.observedAt : right.observedAt,
  }
}

function aggregateResults(reports: readonly DetectorReport[]): readonly IScanResult[] {
  const aggregated = new Map<string, IScanResult>()

  for (const report of reports) {
    for (const result of report.results) {
      const key = `${result.kind}:${result.subject.stableId}:${result.findingId}`
      const existing = aggregated.get(key)
      aggregated.set(key, existing ? mergeResults(existing, result) : result)
    }
  }

  return [...aggregated.values()]
}

interface DetectorRun {
  readonly report: DetectorReport
  readonly failure?: DetectorFailure
}

export class DetectionEngine implements IEngine {
  private readonly detectors = new Map<string, IDetector>()
  private readonly concurrency: number
  private readonly detectorTimeoutMs: number

  constructor(options: DetectionEngineOptions = {}) {
    this.concurrency = options.concurrency ?? DEFAULT_CONCURRENCY
    this.detectorTimeoutMs = options.detectorTimeoutMs ?? DEFAULT_DETECTOR_TIMEOUT_MS

    if (!Number.isInteger(this.concurrency) || this.concurrency < 1) {
      throw new RangeError('Detection engine concurrency must be a positive integer')
    }
    if (!Number.isFinite(this.detectorTimeoutMs) || this.detectorTimeoutMs <= 0) {
      throw new RangeError('Detector timeout must be a positive finite number')
    }
  }

  register(detector: IDetector): void {
    if (!detector.id.trim()) throw new Error('Detector id must not be empty')
    if (!detector.version.trim()) throw new Error(`Detector ${detector.id} must have a version`)
    if (this.detectors.has(detector.id)) {
      throw new Error(`Detector already registered: ${detector.id}`)
    }
    this.detectors.set(detector.id, detector)
  }

  unregister(detectorId: string): boolean {
    return this.detectors.delete(detectorId)
  }

  getDetectors(): readonly IDetector[] {
    return [...this.detectors.values()]
  }

  async scan(context: ScanContext): Promise<EngineReport> {
    const startedAt = nowIso()
    const detectors = this.getDetectors()
    const runs: DetectorRun[] = new Array(detectors.length)
    let nextIndex = 0

    const worker = async (): Promise<void> => {
      while (true) {
        const index = nextIndex++
        if (index >= detectors.length) return
        runs[index] = await this.runDetector(detectors[index], context)
      }
    }

    const workerCount = Math.min(this.concurrency, detectors.length)
    await Promise.all(Array.from({ length: workerCount }, () => worker()))

    const reports = runs.map(run => run.report)
    const failures = runs
      .map(run => run.failure)
      .filter((failure): failure is DetectorFailure => failure !== undefined)

    return {
      sessionId: context.sessionId,
      results: aggregateResults(reports),
      reports,
      failures,
      startedAt,
      completedAt: nowIso(),
    }
  }

  private async runDetector(detector: IDetector, context: ScanContext): Promise<DetectorRun> {
    const startedAt = nowIso()
    const remainingMs = context.deadlineAt - Date.now()
    const timeoutMs = Math.min(this.detectorTimeoutMs, remainingMs)

    if (context.signal.aborted || timeoutMs <= 0) {
      const message = context.signal.aborted ? 'Scan was cancelled' : 'Scan deadline exceeded'
      return {
        report: createFailureReport(detector, startedAt, 'timeout', 'SCAN_ABORTED_OR_EXPIRED', message),
        failure: createFailure(detector, 'timeout', 'SCAN_ABORTED_OR_EXPIRED', message),
      }
    }

    const controller = new AbortController()
    const abortFromParent = () => controller.abort()
    context.signal.addEventListener('abort', abortFromParent, { once: true })

    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      timer = setTimeout(() => controller.abort(), timeoutMs)
      const detectorContext: ScanContext = { ...context, signal: controller.signal }

      let supported: boolean
      try {
        supported = detector.supports(detectorContext)
      } catch (error: unknown) {
        const message = errorMessage(error)
        return {
          report: createFailureReport(detector, startedAt, 'failed', 'SUPPORT_CHECK_FAILED', message),
          failure: createFailure(detector, 'failed', 'SUPPORT_CHECK_FAILED', message),
        }
      }

      if (!supported) {
        return {
          report: createFailureReport(
            detector,
            startedAt,
            'unsupported',
            'DETECTOR_UNSUPPORTED',
            'Detector does not support the current scan context',
          ),
          failure: createFailure(
            detector,
            'unsupported',
            'DETECTOR_UNSUPPORTED',
            'Detector does not support the current scan context',
          ),
        }
      }

      const report = await this.runWithTimeout(detector.scan(detectorContext), controller.signal, timeoutMs)
      if (report.detectorId !== detector.id || report.detectorVersion !== detector.version) {
        const message = 'Detector returned a report with invalid identity'
        return {
          report: createFailureReport(detector, startedAt, 'failed', 'INVALID_REPORT', message),
          failure: createFailure(detector, 'failed', 'INVALID_REPORT', message),
        }
      }

      if (report.status !== 'completed') {
        const code = report.errorCode ?? `DETECTOR_${report.status.toUpperCase()}`
        const message = report.errorMessage ?? `Detector returned status: ${report.status}`
        return {
          report,
          failure: createFailure(detector, report.status, code, message),
        }
      }

      return { report }
    } catch (error: unknown) {
      const timedOut = controller.signal.aborted
      const status: DetectorFailure['status'] = timedOut ? 'timeout' : 'failed'
      const code = timedOut ? 'DETECTOR_TIMEOUT_OR_ABORTED' : 'DETECTOR_ERROR'
      const message = timedOut ? 'Detector timed out or was cancelled' : errorMessage(error)
      return {
        report: createFailureReport(detector, startedAt, status, code, message),
        failure: createFailure(detector, status, code, message),
      }
    } finally {
      if (timer !== undefined) clearTimeout(timer)
      context.signal.removeEventListener('abort', abortFromParent)
    }
  }

  private async runWithTimeout(
    task: Promise<DetectorReport>,
    signal: AbortSignal,
    timeoutMs: number,
  ): Promise<DetectorReport> {
    let timer: ReturnType<typeof setTimeout> | undefined
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('Detector timeout')), timeoutMs)
    })

    const aborted = new Promise<never>((_, reject) => {
      if (signal.aborted) {
        reject(new Error('Detector aborted'))
        return
      }
      signal.addEventListener('abort', () => reject(new Error('Detector aborted')), { once: true })
    })

    try {
      return await Promise.race([task, timeout, aborted])
    } finally {
      if (timer !== undefined) clearTimeout(timer)
    }
  }
}
