import { describe, expect, it } from 'vitest'
import { DetectionEngine } from '../core/detection-engine'
import type { IDetector } from '../core/ports'
import type { DetectorReport, IScanResult, ScanContext } from '../core/models'

function createContext(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    sessionId: 'test-session',
    signal: new AbortController().signal,
    startedAt: Date.now(),
    deadlineAt: Date.now() + 5_000,
    policyVersion: 'test-policy',
    metadata: {},
    ...overrides,
  }
}

function createResult(overrides: Partial<IScanResult> = {}): IScanResult {
  return {
    findingId: 'finding-1',
    detectorId: 'test-detector',
    detectorVersion: '1.0.0',
    kind: 'file',
    subject: {
      kind: 'file',
      stableId: 'sha256:sample',
      displayName: 'sample.exe',
    },
    risk: 'medium',
    score: 40,
    confidence: 0.7,
    categories: ['test'],
    evidence: [
      {
        id: 'evidence-1',
        source: 'test',
        category: 'sample',
        explanation: 'Test evidence',
        confidence: 0.7,
        observedAt: new Date().toISOString(),
      },
    ],
    observedAt: new Date().toISOString(),
    ...overrides,
  }
}

function createReport(detector: IDetector, results: readonly IScanResult[]): DetectorReport {
  const timestamp = new Date().toISOString()
  return {
    detectorId: detector.id,
    detectorVersion: detector.version,
    status: 'completed',
    results,
    startedAt: timestamp,
    completedAt: timestamp,
  }
}

function createDetector(
  id: string,
  scan: IDetector['scan'],
  supports: IDetector['supports'] = () => true,
): IDetector {
  const detector: IDetector = {
    id,
    version: '1.0.0',
    kind: 'file',
    required: true,
    capabilities: ['test'],
    supports,
    scan,
  }
  return detector
}

describe('DetectionEngine', () => {
  it('registers detectors and rejects duplicate ids', () => {
    const engine = new DetectionEngine()
    const detector = createDetector('files', async () => createReport(detector, []))

    engine.register(detector)

    expect(engine.getDetectors()).toEqual([detector])
    expect(() => engine.register(detector)).toThrow('Detector already registered: files')
    expect(engine.unregister('files')).toBe(true)
    expect(engine.unregister('files')).toBe(false)
  })

  it('aggregates duplicate findings and preserves the strongest evidence', async () => {
    const firstResult = createResult()
    const secondResult = createResult({
      detectorId: 'second-detector',
      detectorVersion: '2.0.0',
      risk: 'high',
      score: 80,
      confidence: 0.95,
      categories: ['behavior'],
      evidence: [
        {
          id: 'evidence-2',
          source: 'second',
          category: 'behavior',
          explanation: 'Correlated evidence',
          confidence: 0.95,
          observedAt: new Date().toISOString(),
        },
      ],
    })

    let firstDetector!: IDetector
    let secondDetector!: IDetector
    firstDetector = createDetector('first-detector', async () => createReport(firstDetector, [firstResult]))
    secondDetector = createDetector('second-detector', async () => createReport(secondDetector, [secondResult]))

    const engine = new DetectionEngine({ concurrency: 1 })
    engine.register(firstDetector)
    engine.register(secondDetector)

    const report = await engine.scan(createContext())

    expect(report.failures).toEqual([])
    expect(report.reports).toHaveLength(2)
    expect(report.results).toHaveLength(1)
    expect(report.results[0]).toMatchObject({
      risk: 'high',
      score: 80,
      confidence: 0.95,
    })
    expect(report.results[0]?.categories).toEqual(['test', 'behavior'])
    expect(report.results[0]?.evidence).toHaveLength(2)
  })

  it('reports unsupported detectors without treating them as clean', async () => {
    let detector!: IDetector
    detector = createDetector(
      'windows-only',
      async () => createReport(detector, []),
      () => false,
    )

    const report = await new DetectionEngine().scan(createContext())

    expect(report.results).toEqual([])
    expect(report.failures).toHaveLength(0)

    const engine = new DetectionEngine()
    engine.register(detector)
    const supportedReport = await engine.scan(createContext())

    expect(supportedReport.results).toEqual([])
    expect(supportedReport.failures).toEqual([
      expect.objectContaining({
        detectorId: 'windows-only',
        status: 'unsupported',
        errorCode: 'DETECTOR_UNSUPPORTED',
      }),
    ])
  })

  it('reports a detector timeout explicitly', async () => {
    let detector!: IDetector
    detector = createDetector(
      'slow-detector',
      async () => {
        await new Promise<void>(resolve => setTimeout(resolve, 50))
        return createReport(detector, [])
      },
    )

    const engine = new DetectionEngine({ detectorTimeoutMs: 5 })
    engine.register(detector)

    const report = await engine.scan(createContext())

    expect(report.results).toEqual([])
    expect(report.failures).toEqual([
      expect.objectContaining({
        detectorId: 'slow-detector',
        status: 'timeout',
        errorCode: 'DETECTOR_TIMEOUT_OR_ABORTED',
      }),
    ])
  })
})
