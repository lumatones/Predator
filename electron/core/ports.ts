import type {
  DetectionKind,
  DetectorReport,
  EngineReport,
  ScanContext,
} from './models'

/**
 * A detector is an isolated unit of observation.
 *
 * Detectors return data only. They do not write to the database, publish
 * telemetry, call IPC or mutate another detector's state.
 */
export interface IDetector {
  readonly id: string
  readonly version: string
  readonly kind: DetectionKind
  readonly required: boolean
  readonly capabilities: readonly string[]

  supports(context: ScanContext): boolean
  scan(context: ScanContext): Promise<DetectorReport>
}

/**
 * Detection engine boundary used by AntiCheatCore.
 *
 * The implementation owns detector registration, execution isolation and
 * aggregation. A detector failure must remain observable in EngineReport;
 * it must never be silently converted into a clean result.
 */
export interface IEngine {
  register(detector: IDetector): void
  unregister(detectorId: string): boolean
  getDetectors(): readonly IDetector[]
  scan(context: ScanContext): Promise<EngineReport>
}
