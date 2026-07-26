/**
 * Predator — Safe Spread Utility
 * Extracted from scanner.ts
 *
 * Prevents "a is not iterable" crashes when spreading potentially non-array values.
 */

export function safeSpread<T>(label: string, value: T[] | null | undefined): T[] {
  if (!Array.isArray(value)) {
    console.error(`[safeSpread] ${label} — expected array, got:`, typeof value, value)
    return []
  }
  return value
}
