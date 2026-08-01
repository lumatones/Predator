import type { RiskLevel } from '../../core/models'
import type { BehaviorSignal, BehaviorSignalType } from './models'

export interface ScoreEvaluation {
  readonly score: number
  readonly risk: RiskLevel
  readonly confidence: number
  readonly categories: readonly string[]
}

export interface ScoringEngineOptions {
  readonly weights?: Partial<Record<BehaviorSignalType, number>>
}

const DEFAULT_WEIGHTS: Record<BehaviorSignalType, number> = {
  'cross-process-memory-write': 24,
  'executable-memory-after-write': 28,
  'remote-execution': 30,
  'multi-target-access': 16,
  'rapid-source-exit': 12,
  'user-writable-launch': 10,
  'unsigned-recent-execution': 12,
  'orphaned-parent': 8,
  'unexpected-parent': 10,
  'short-lived-execution': 8,
}

const CATEGORY_BY_SIGNAL: Record<BehaviorSignalType, string> = {
  'cross-process-memory-write': 'memory-modification',
  'executable-memory-after-write': 'memory-modification',
  'remote-execution': 'cross-process-execution',
  'multi-target-access': 'cross-process-execution',
  'rapid-source-exit': 'lifecycle-anomaly',
  'user-writable-launch': 'execution-origin',
  'unsigned-recent-execution': 'trust-metadata',
  'orphaned-parent': 'process-lineage',
  'unexpected-parent': 'process-lineage',
  'short-lived-execution': 'lifecycle-anomaly',
}

function riskForScore(score: number): RiskLevel {
  if (score >= 75) return 'critical'
  if (score >= 50) return 'high'
  if (score >= 25) return 'medium'
  if (score > 0) return 'low'
  return 'clean'
}

export class ScoringEngine {
  private readonly weights: Readonly<Record<BehaviorSignalType, number>>

  constructor(options: ScoringEngineOptions = {}) {
    this.weights = { ...DEFAULT_WEIGHTS, ...options.weights }

    for (const [type, weight] of Object.entries(this.weights)) {
      if (!Number.isFinite(weight) || weight < 0) {
        throw new RangeError(`Invalid behavior signal weight: ${type}`)
      }
    }
  }

  evaluate(signals: readonly BehaviorSignal[]): ScoreEvaluation {
    const unique = new Map<string, BehaviorSignal>()
    for (const item of signals) {
      const existing = unique.get(item.type)
      if (!existing || item.confidence > existing.confidence) unique.set(item.type, item)
    }

    const values = [...unique.values()]
    const rawScore = values.reduce(
      (total, item) => total + this.weights[item.type] * item.confidence,
      0,
    )

    const categories = [...new Set(values.map(item => CATEGORY_BY_SIGNAL[item.type]))]
    const correlationBonus = this.correlationBonus(values)
    const score = Math.min(100, Math.round(rawScore + correlationBonus))
    const confidence = this.confidence(values, categories.length)

    return {
      score,
      risk: riskForScore(score),
      confidence,
      categories,
    }
  }

  private correlationBonus(signals: readonly BehaviorSignal[]): number {
    const types = new Set(signals.map(signal => signal.type))
    const hasMemoryModification =
      types.has('cross-process-memory-write') ||
      types.has('executable-memory-after-write')
    const hasExecution =
      types.has('remote-execution') ||
      types.has('multi-target-access')
    const hasLifecycle =
      types.has('rapid-source-exit') ||
      types.has('short-lived-execution')

    let bonus = 0
    if (hasMemoryModification && hasExecution) bonus += 12
    if (hasExecution && hasLifecycle) bonus += 8
    if (hasMemoryModification && types.has('unsigned-recent-execution')) bonus += 6
    return bonus
  }

  private confidence(signals: readonly BehaviorSignal[], categoryCount: number): number {
    if (signals.length === 0) return 0
    const average = signals.reduce((total, item) => total + item.confidence, 0) / signals.length
    const diversity = Math.min(1, categoryCount / 3)
    return Math.round(Math.min(1, average * 0.7 + diversity * 0.3) * 100) / 100
  }
}
