import { DetectionEngine } from '../../core/detection-engine'
import type {
  DetectorReport,
  EngineReport,
  IScanResult,
} from '../../core/models'
import type { ScanResult } from '../../types'
import { ProcessScanner } from './process-scanner'
import { WindowsProcessObservationPort } from './windows-process-observation'
import { processObservationCache } from './process-observation-cache'

export interface BehavioralProcessScanOptions {
  readonly signal?: AbortSignal
  readonly timeoutMs?: number
  readonly sessionId?: string
}

export interface BehavioralProcessScanReport {
  readonly results: readonly ScanResult[]
  readonly engineReport: EngineReport
}

const DETECTOR_ID = 'behavioral-process-scanner'
const DETECTOR_VERSION = '1.0.0'

// Reused for the lifetime of the Electron main process so short-lived
// processes can be observed across consecutive scans.
const processObservationPort = new WindowsProcessObservationPort()
const behavioralProcessScanner = new ProcessScanner({
  observationPort: processObservationPort,
})

function timestamp(): string {
  return new Date().toISOString()
}

function unsupportedReport(sessionId: string): EngineReport {
  const startedAt = timestamp()
  const report: DetectorReport = {
    detectorId: DETECTOR_ID,
    detectorVersion: DETECTOR_VERSION,
    status: 'unsupported',
    results: [],
    startedAt,
    completedAt: timestamp(),
    errorCode: 'PLATFORM_UNSUPPORTED',
    errorMessage: 'Behavioral process observation is available on Windows only',
  }

  return {
    sessionId,
    results: [],
    reports: [report],
    failures: [{
      detectorId: DETECTOR_ID,
      status: 'unsupported',
      errorCode: 'PLATFORM_UNSUPPORTED',
      errorMessage: report.errorMessage,
    }],
    startedAt,
    completedAt: timestamp(),
  }
}

function riskToLegacy(risk: IScanResult['risk']): ScanResult['risk'] {
  switch (risk) {
    case 'critical': return 'critical'
    case 'high': return 'high'
    case 'medium': return 'medium'
    case 'low': return 'low'
    case 'clean': return 'low'
  }
}

function toLegacyResult(result: IScanResult): ScanResult {
  const explanations = result.evidence
    .map(item => item.explanation)
    .filter((item, index, all) => all.indexOf(item) === index)

  return {
    path: `behavior:${result.subject.stableId}`,
    fileName: 'Behavioral process signal',
    type: 'process',
    risk: riskToLegacy(result.risk),
    matches: [...result.categories, ...explanations].slice(0, 12),
    size: 0,
    modifiedAt: result.observedAt,
    evidence: result.evidence.map(item => ({
      id: item.id,
      source: item.source,
      category: item.category,
      weight: Math.round(item.confidence * 100),
      confidence: item.confidence,
      explanation: item.explanation,
      raw: item.explanation,
      timestamp: item.observedAt,
    })),
    findingId: result.findingId,
    riskScore: result.score,
    riskExplanation: explanations.join('; '),
  }
}

export async function runBehavioralProcessScan(
  options: BehavioralProcessScanOptions = {},
): Promise<BehavioralProcessScanReport> {
  const sessionId = options.sessionId ?? `behavior-${Date.now()}`
  // Never let a failed refresh expose a previous scan's process inventory to
  // legacy detectors that run immediately after this detector.
  processObservationCache.begin(sessionId)
  if (process.platform !== 'win32') {
    return {
      results: [],
      engineReport: unsupportedReport(sessionId),
    }
  }

  const controller = new AbortController()
  const signal = options.signal ?? controller.signal
  const timeoutMs = options.timeoutMs ?? 10_000
  const engine = new DetectionEngine({
    concurrency: 1,
    detectorTimeoutMs: timeoutMs,
  })
  engine.register(behavioralProcessScanner)

  const engineReport = await engine.scan({
    sessionId,
    signal,
    startedAt: Date.now(),
    deadlineAt: Date.now() + timeoutMs,
    policyVersion: 'local-behavior-v1',
    metadata: { platform: process.platform },
  })

  return {
    results: engineReport.results.map(toLegacyResult),
    engineReport,
  }
}
