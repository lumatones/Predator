/**
 * Predator — Safe Spread Utility
 *
 * Prevents scan crashes from killing the entire scan.
 * `safeCall` catches exceptions from individual scan phases.
 * `safeSpread` guards against non-array returns.
 */

/** Wrap a scan phase function call in try/catch. If it throws, return [] and log. */
export function safeCall<T>(label: string, fn: () => T[]): T[] {
  try {
    const result = fn()
    if (!Array.isArray(result)) {
      console.error(`[safeCall] ${label} — expected array, got:`, typeof result)
      return []
    }
    return result
  } catch (err) {
    console.error(`[safeCall] ${label} — crashed:`, (err as Error).message || err)
    return []
  }
}

export function safeSpread<T>(label: string, value: T[] | null | undefined): T[] {
  if (!Array.isArray(value)) {
    console.error(`[safeSpread] ${label} — expected array, got:`, typeof value, value)
    return []
  }
  return value
}
