/**
 * Predator — IPC Scan Handler Functions
 *
 * Pure handler logic extracted from scanner.ts's registerScanHandlers().
 * Testable without mocking the entire scan pipeline.
 */

// ═══════════════════════════════════════════════════
// Cancel Scan handler
// ═══════════════════════════════════════════════════

export interface CancelScanResult {
  success: boolean
  error?: string
}

export function handleCancelScan(
  abortController: AbortController | null | undefined,
): CancelScanResult {
  if (abortController) {
    abortController.abort()
    return { success: true }
  }
  return { success: false, error: 'No active scan' }
}
