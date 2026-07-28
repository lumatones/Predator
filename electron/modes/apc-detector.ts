/**
 * Predator — APC Injection & Atom Bombing Detector
 *
 * ⚠ DEPRECATED — This file now re-exports from the modular apc/ barrel.
 *    See electron/modes/apc/index.ts for the canonical entry point.
 *    Individual tiers live in electron/modes/apc/{thread-states,atom-scan,etw-trace,thread-pool,process-hollowing}.ts
 *
 * Kept for backwards compatibility — existing imports of `runApcScan` still resolve.
 */

export { runApcScan } from './apc/index'
