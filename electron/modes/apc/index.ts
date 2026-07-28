/**
 * Predator — APC Injection & Atom Bombing Detector (Barrel)
 *
 * Detects advanced process injection techniques used by modern cheats:
 *
 *   Tier 1: Thread state analysis (suspicious wait states, high thread counts)
 *   Tier 2: Atom table scan (shellcode patterns in global atoms)
 *   Tier 3: ETW Background Monitor — 5-min Kernel-Thread + Kernel-Process trace
 *   Tier 4: Thread Pool abuse detection (WrQueue saturation, Pool Party/WTH)
 *   Tier 5: Process Hollowing detection (module count, path mismatch, RunPE)
 *   Tier 6: Reflective DLL Injection (phantom modules, masquerading, manual-map)
 *   Tier 7: DLL Side-Loading (KnownDLLs cross-ref, shadow DLLs, WMI size mismatch)
 */

import { scanApcThreadStates } from './thread-states'
import { scanAtomTables } from './atom-scan'
import { scanEtwKernelThread } from './etw-trace'
import { scanThreadPoolAbuse } from './thread-pool'
import { scanProcessHollowing } from './process-hollowing'
import { scanReflectiveDll } from './reflective-dll'
import { scanDllSideLoading } from './dll-side-load'
import type { ScanResult } from '../../types'

export { scanApcThreadStates } from './thread-states'
export { scanAtomTables } from './atom-scan'
export { scanEtwKernelThread } from './etw-trace'
export { scanThreadPoolAbuse } from './thread-pool'
export { scanProcessHollowing } from './process-hollowing'
export { scanReflectiveDll } from './reflective-dll'
export { scanDllSideLoading } from './dll-side-load'

/**
 * Run full APC/Atom injection scan — all five tiers.
 */
export function runApcScan(): ScanResult[] {
  const results: ScanResult[] = []

  // Tier 1: Thread state analysis (fast, no admin required)
  results.push(...scanApcThreadStates())

  // Tier 2: Atom table scan (moderate, no admin required)
  results.push(...scanAtomTables())

  // Tier 3: ETW kernel-thread trace (needs admin, optional)
  results.push(...scanEtwKernelThread())

  // Tier 4: Thread Pool abuse detection (fast, no admin required)
  results.push(...scanThreadPoolAbuse())

  // Tier 5: Process Hollowing detection (module count, path mismatch, RunPE)
  results.push(...scanProcessHollowing())

  // Tier 6: Reflective DLL Injection (phantom modules, masquerading, manual-map)
  results.push(...scanReflectiveDll())

  // Tier 7: DLL Side-Loading (KnownDLLs cross-ref, shadow DLLs, WMI size mismatch)
  results.push(...scanDllSideLoading())

  return results
}
