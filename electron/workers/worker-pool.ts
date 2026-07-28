/**
 * Predator — Worker Pool
 *
 * Lightweight concurrency pool for parallel file scanning.
 * Uses Promise-based batching with a configurable concurrency limit.
 *
 * This is a software pool (not worker_threads) because:
 *   1. heuristicFileScan imports ~15 modules — worker serialization is complex
 *   2. The bottleneck is CPU (entropy calc, string scan, PE headers), not I/O
 *   3. A software pool with setImmediate() yields gives enough parallelism (4-8x)
 *
 * For true worker_threads, each worker would need its own TypeScript loader
 * and full dependency graph. This can be added later if profiling shows need.
 *
 * The pool supports AbortSignal for graceful cancellation.
 */

import { yieldToEventLoop } from '../types'

export interface PoolOptions {
  /** Maximum concurrent tasks */
  concurrency: number
  /** AbortSignal for cancellation */
  signal?: AbortSignal
}

/**
 * Run tasks in parallel with concurrency control and abort support.
 *
 * @param items — array of input items
 * @param fn — async function to process each item
 * @param options — concurrency limit + optional AbortSignal
 * @returns array of results (one per item, in order)
 */
export async function runParallel<T, R>(
  items: T[],
  fn: (item: T, index: number) => Promise<R>,
  options: PoolOptions,
): Promise<R[]> {
  const { concurrency, signal } = options
  const results: R[] = new Array(items.length)
  const executing = new Set<Promise<void>>()
  let nextIndex = 0
  let aborted = false

  if (signal) {
    signal.addEventListener('abort', () => { aborted = true }, { once: true })
  }

  async function executeNext(): Promise<void> {
    while (nextIndex < items.length && !aborted && !signal?.aborted) {
      const idx = nextIndex++
      // Double-check abort before spending CPU on the next file
      if (aborted || signal?.aborted) return

      try {
        results[idx] = await fn(items[idx], idx)
      } catch {
        // Individual task failure — leave undefined in result slot
      }
    }
  }

  // Start N workers
  const workers = Math.min(concurrency, items.length)
  for (let i = 0; i < workers; i++) {
    const worker = executeNext().then(() => {
      executing.delete(worker)
    }) as Promise<void>
    executing.add(worker)
  }

  // Yield to event loop periodically to avoid blocking the main thread
  while (executing.size > 0) {
    await Promise.race(executing)
    await yieldToEventLoop()
  }

  // Filter out undefined (failed) results
  return results.filter((r): r is R => r !== undefined)
}
