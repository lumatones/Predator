/**
 * Predator — Process Scanner (Orchestrator)
 *
 * Re-exports from modular process/ subdirectory.
 *
 * Modular structure:
 *   process/enumeration.ts  — process listing + module analysis
 *   process/pipes-wmi.ts    — named pipes + WMI persistence
 *   process/behavioral.ts   — behavioral masquerading detection
 */

export { scanRunningProcessesV2 } from './process/enumeration'
export { scanNamedPipes, scanWmiPersistence } from './process/pipes-wmi'
export { scanBehavioralMasquerading } from './process/behavioral'
