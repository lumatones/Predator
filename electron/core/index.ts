export type {
  DetectionKind,
  DetectorFailure,
  DetectorReport,
  DetectorStatus,
  EngineReport,
  IScanResult,
  RiskLevel,
  ScanContext,
  ScanEvidence,
  ScanSubject,
} from './models'

export type { IDetector, IEngine } from './ports'
export { DetectionEngine } from './detection-engine'
export type { DetectionEngineOptions } from './detection-engine'
