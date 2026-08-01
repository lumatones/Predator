import fsp from 'fs/promises'

/**
 * Read at most maxBytes from the beginning of a file without blocking the
 * Electron main-process event loop.
 */
export function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new Error('File read aborted')
}

/**
 * Read at most maxBytes from an arbitrary file offset without blocking the
 * Electron main-process event loop. The returned buffer may be shorter when
 * the file ends before the requested range.
 */
export async function readFileRange(
  filepath: string,
  offset: number,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<Buffer> {
  if (!Number.isSafeInteger(offset) || offset < 0) return Buffer.alloc(0)
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) return Buffer.alloc(0)
  throwIfAborted(signal)

  const handle = await fsp.open(filepath, 'r')
  try {
    throwIfAborted(signal)
    const buffer = Buffer.alloc(maxBytes)
    const { bytesRead } = await handle.read(buffer, 0, maxBytes, offset)
    throwIfAborted(signal)
    return buffer.subarray(0, bytesRead)
  } finally {
    await handle.close()
  }
}

/**
 * Read at most maxBytes from the beginning of a file without blocking the
 * Electron main-process event loop.
 */
export async function readFilePrefix(
  filepath: string,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<Buffer> {
  return readFileRange(filepath, 0, maxBytes, signal)
}
