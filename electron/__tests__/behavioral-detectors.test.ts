import { describe, expect, it } from 'vitest'
import type { DetectorReport, ScanContext } from '../core/models'
import {
  BehaviorTracker,
  FileScanner,
  InjectionDetector,
  ProcessScanner,
  ScoringEngine,
  ProcessObservationCache,
  type BehaviorObservationPort,
  type BehaviorSnapshot,
  type FileObservation,
  type FileObservationPort,
} from '../modules/behavior'

function context(): ScanContext {
  return {
    sessionId: 'behavior-test',
    signal: new AbortController().signal,
    startedAt: Date.now(),
    deadlineAt: Date.now() + 10_000,
    policyVersion: 'test',
    metadata: {},
  }
}

function reportFor(report: DetectorReport): DetectorReport {
  return report
}

function snapshot(): BehaviorSnapshot {
  const observedAt = Date.now()
  return {
    processes: [
      {
        stableId: 'process:source',
        parentRelation: 'unexpected',
        location: 'user-writable',
        signature: 'absent',
        startedAt: observedAt - 2_000,
        observedAt,
        lifetimeMs: 2_000,
        childCount: 0,
        isSystemProcess: false,
      },
      {
        stableId: 'process:target-a',
        parentRelation: 'normal',
        location: 'system',
        signature: 'valid',
        startedAt: observedAt - 60_000,
        observedAt,
        childCount: 0,
        isSystemProcess: false,
      },
      {
        stableId: 'process:target-b',
        parentRelation: 'normal',
        location: 'system',
        signature: 'valid',
        startedAt: observedAt - 60_000,
        observedAt,
        childCount: 0,
        isSystemProcess: false,
      },
    ],
    events: [
      {
        eventId: 'event-write',
        observedAt,
        sourceId: 'process:source',
        targetId: 'process:target-a',
        operation: 'memory-write',
        protection: 'read-write',
        bytes: 4096,
        crossProcess: true,
        succeeded: true,
        sourceExitedWithinMs: 2_000,
      },
      {
        eventId: 'event-protect',
        observedAt: observedAt + 1,
        sourceId: 'process:source',
        targetId: 'process:target-a',
        operation: 'memory-protect',
        protection: 'read-write-execute',
        crossProcess: true,
        succeeded: true,
      },
      {
        eventId: 'event-execute',
        observedAt: observedAt + 2,
        sourceId: 'process:source',
        targetId: 'process:target-a',
        operation: 'remote-thread',
        crossProcess: true,
        succeeded: true,
      },
      {
        eventId: 'event-second-target',
        observedAt: observedAt + 3,
        sourceId: 'process:source',
        targetId: 'process:target-b',
        operation: 'process-open',
        crossProcess: true,
        succeeded: true,
      },
    ],
  }
}

describe('behavioral detection modules', () => {
  it('reuses fresh process inventory and expires stale observations', () => {
    const cache = new ProcessObservationCache({ maxAgeMs: 100 })
    cache.replace([{ id: 42, name: 'opaque-process', modules: ['opaque-module'] }], 1_000)

    expect(cache.get(1_099)).toEqual([
      { id: 42, name: 'opaque-process', modules: ['opaque-module'] },
    ])
    expect(cache.get(1_101)).toBeUndefined()

    cache.replace([{ id: 7, name: 'replacement', modules: [] }], 2_000)
    expect(cache.get(2_000)).toEqual([
      { id: 7, name: 'replacement', modules: [] },
    ])
    cache.clear()
    expect(cache.get(2_000)).toBeUndefined()
  })

  it('rejects late writes from an older scan session', () => {
    const cache = new ProcessObservationCache({ maxAgeMs: 1_000 })
    cache.begin('scan-a')
    cache.replace([{ id: 1, name: 'old', modules: [] }], 1_000, 'scan-a')
    cache.begin('scan-b')

    cache.replace([{ id: 2, name: 'late-old', modules: [] }], 1_100, 'scan-a')
    expect(cache.get(1_100, 'scan-b')).toBeUndefined()

    cache.replace([{ id: 3, name: 'current', modules: [] }], 1_200, 'scan-b')
    expect(cache.get(1_200, 'scan-a')).toBeUndefined()
    expect(cache.get(1_200, 'scan-b')).toEqual([
      { id: 3, name: 'current', modules: [] },
    ])
  })

  it('tracks bounded, normalized histories and deduplicates events', () => {
    const tracker = new BehaviorTracker({ maxSubjects: 1, maxEventsPerSubject: 2 })
    const current = snapshot()

    tracker.record(current)
    tracker.record({
      processes: [current.processes[0]!],
      events: [current.events[0]!, current.events[0]!, current.events[1]!, current.events[2]!],
    })

    expect(tracker.getSubjectIds()).toHaveLength(1)
    expect(tracker.getHistory('process:source')).toHaveLength(2)
    expect(tracker.getHistory('process:source').map(event => event.eventId)).toEqual([
      'event-protect',
      'event-execute',
    ])
  })

  it('detects short-lived source exit as a lifecycle signal', () => {
    const current = snapshot()
    const observedAt = Date.now()
    const signals = new InjectionDetector().analyze({
      processes: current.processes,
      events: [{
        eventId: 'exit-event',
        observedAt,
        sourceId: 'process:source',
        operation: 'process-exit',
        crossProcess: false,
        succeeded: true,
        sourceExitedWithinMs: 2_000,
      }],
    })

    expect(signals).toEqual(expect.arrayContaining([
      expect.objectContaining({
        subjectId: 'process:source',
        type: 'rapid-source-exit',
      }),
    ]))
  })

  it('detects behavior sequences without inspecting names, paths or hashes', () => {
    const signals = new InjectionDetector().analyze(snapshot())
    const types = new Set(signals.map(signal => signal.type))

    expect(types).toEqual(new Set([
      'user-writable-launch',
      'unsigned-recent-execution',
      'unexpected-parent',
      'short-lived-execution',
      'cross-process-memory-write',
      'executable-memory-after-write',
      'remote-execution',
      'multi-target-access',
    ]))
    expect(signals.every(signal => !signal.explanation.includes('source.exe'))).toBe(true)
  })

  it('raises score for correlated memory and lifecycle signals', () => {
    const signals = new InjectionDetector().analyze(snapshot())
    const evaluation = new ScoringEngine().evaluate(signals)

    expect(evaluation.score).toBeGreaterThanOrEqual(75)
    expect(evaluation.risk).toBe('critical')
    expect(evaluation.categories).toEqual(expect.arrayContaining([
      'memory-modification',
      'cross-process-execution',
      'lifecycle-anomaly',
    ]))
  })

  it('returns a process finding through the IDetector contract', async () => {
    const observationPort: BehaviorObservationPort = {
      collect: async () => snapshot(),
    }
    const scanner = new ProcessScanner({ observationPort })

    const report = await scanner.scan(context())

    expect(report).toMatchObject({
      detectorId: 'behavioral-process-scanner',
      status: 'completed',
    })
    expect(report.results).toHaveLength(1)
    expect(report.results[0]).toMatchObject({
      kind: 'process',
      risk: 'critical',
      subject: { stableId: 'process:source' },
    })
  })

  it('detects file execution-origin and short-lifetime behavior without static indicators', async () => {
    const observations: readonly FileObservation[] = [
      {
        stableId: 'file:opaque-1',
        location: 'user-writable',
        signature: 'absent',
        firstSeenAt: Date.now() - 5_000,
        observedAt: Date.now(),
        executed: true,
        executionCount: 1,
        transientLifetimeMs: 2_000,
      },
    ]
    const observationPort: FileObservationPort = {
      collect: async () => observations,
    }
    const scanner = new FileScanner({ observationPort })

    const report = await scanner.scan(context())

    expect(report.status).toBe('completed')
    expect(report.results).toHaveLength(1)
    expect(report.results[0]).toMatchObject({
      kind: 'file',
      subject: { stableId: 'file:opaque-1' },
    })
  })

  it('does not produce a finding for benign signed system-origin execution', async () => {
    const observationPort: FileObservationPort = {
      collect: async () => [{
        stableId: 'file:opaque-benign',
        location: 'system',
        signature: 'valid',
        firstSeenAt: Date.now() - 60_000,
        observedAt: Date.now(),
        executed: true,
        executionCount: 1,
      }],
    }
    const report = await new FileScanner({ observationPort }).scan(context())

    expect(report.status).toBe('completed')
    expect(report.results).toEqual([])
  })

  it('returns a failed report for partial observations', async () => {
    const observationPort: BehaviorObservationPort = {
      collect: async () => ({
        processes: [],
        events: [],
        observationStatus: 'partial',
        observationWarning: 'provider returned incomplete data',
      }),
    }
    const report = await new ProcessScanner({ observationPort }).scan(context())

    expect(report).toMatchObject({
      status: 'failed',
      errorCode: 'PARTIAL_OBSERVATION',
    })
  })

  it('returns an explicit timeout report when observation is cancelled', async () => {
    const controller = new AbortController()
    controller.abort()
    const cancelledContext = context()
    const observationPort: FileObservationPort = {
      collect: async () => [],
    }
    const report = await new FileScanner({ observationPort }).scan({
      ...cancelledContext,
      signal: controller.signal,
    })

    expect(reportFor(report)).toMatchObject({
      status: 'timeout',
      errorCode: 'SCAN_ABORTED',
    })
  })
})
