export { BehaviorTracker } from './behavior-tracker'
export type { BehaviorTrackerOptions } from './behavior-tracker'
export { InjectionDetector } from './injection-detector'
export { ScoringEngine } from './scoring-engine'
export type { ScoreEvaluation, ScoringEngineOptions } from './scoring-engine'
export { ProcessScanner } from './process-scanner'
export type { ProcessScannerDependencies } from './process-scanner'
export { FileScanner } from './file-scanner'
export type { FileScannerDependencies } from './file-scanner'
export { runBehavioralProcessScan } from './run-process-scan'
export type { BehavioralProcessScanOptions, BehavioralProcessScanReport } from './run-process-scan'
export { WindowsProcessObservationPort } from './windows-process-observation'
export { ProcessObservationCache, processObservationCache, getCachedProcessInventory } from './process-observation-cache'
export type { CachedProcessInventory, ProcessObservationCacheOptions } from './process-observation-cache'
export type {
  BehaviorEvent,
  BehaviorObservationPort,
  BehaviorSignal,
  BehaviorSignalType,
  BehaviorSnapshot,
  FileObservation,
  FileObservationPort,
  MemoryOperationKind,
  MemoryProtection,
  ParentRelation,
  ProcessLocation,
  ProcessSnapshot,
  SignatureState,
} from './models'
