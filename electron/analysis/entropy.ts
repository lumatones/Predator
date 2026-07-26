/**
 * Predator — Shannon Entropy Calculator
 * Extracted from heuristic.ts
 *
 * Shannon entropy (0–8). High = possibly packed / encrypted. O(n) single-pass.
 */

export function calculateEntropy(data: Buffer): number {
  if (!data || data.length === 0) return 0
  const freq = new Array(256).fill(0)
  for (const b of data) freq[b]++
  const len = data.length
  let entropy = 0
  for (const count of freq) {
    if (count > 0) {
      const p = count / len
      entropy -= p * Math.log2(p)
    }
  }
  return entropy
}
