export interface CachedProcessInventory {
  readonly id: number
  readonly name: string
  readonly modules: readonly string[]
}

export interface ProcessObservationCacheOptions {
  readonly maxAgeMs?: number
}

/**
 * Main-process-only cache for one process inventory.
 *
 * The cache deliberately has no renderer/IPC surface. It exists to let
 * adjacent detectors reuse one privileged observation without executing a
 * second process enumeration immediately afterwards.
 */
export class ProcessObservationCache {
  private readonly maxAgeMs: number
  private records: readonly CachedProcessInventory[] | null = null
  private observedAt = 0
  private activeOwnerId: string | undefined

  constructor(options: ProcessObservationCacheOptions = {}) {
    this.maxAgeMs = options.maxAgeMs ?? 15_000
    if (!Number.isFinite(this.maxAgeMs) || this.maxAgeMs <= 0) {
      throw new RangeError('Process observation cache maxAgeMs must be positive')
    }
  }

  begin(ownerId: string): void {
    this.activeOwnerId = ownerId
    this.records = null
    this.observedAt = 0
  }

  replace(records: readonly CachedProcessInventory[], observedAt = Date.now(), ownerId?: string): void {
    if (this.activeOwnerId !== undefined && ownerId !== this.activeOwnerId) return

    this.records = records.map(record => ({
      id: record.id,
      name: record.name,
      modules: [...record.modules],
    }))
    this.observedAt = observedAt
  }

  get(now = Date.now(), ownerId?: string): readonly CachedProcessInventory[] | undefined {
    if (this.activeOwnerId !== undefined && ownerId !== undefined && ownerId !== this.activeOwnerId) return undefined
    if (!this.records || now - this.observedAt > this.maxAgeMs) return undefined
    return this.records
  }

  clear(): void {
    this.records = null
    this.observedAt = 0
    this.activeOwnerId = undefined
  }
}

export const processObservationCache = new ProcessObservationCache()

export function getCachedProcessInventory(now = Date.now(), ownerId?: string): readonly CachedProcessInventory[] | undefined {
  return processObservationCache.get(now, ownerId)
}
