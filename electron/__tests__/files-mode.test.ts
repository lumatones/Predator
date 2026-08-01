import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { walkDirAsync } from '../modes/files'

const tempDir = path.join(os.tmpdir(), `predator-files-mode-${Date.now()}`)

async function collectWalker(dirPath: string, signal?: AbortSignal): Promise<string[]> {
  const result: string[] = []
  for await (const filePath of walkDirAsync(dirPath, signal)) {
    result.push(filePath)
  }
  return result
}

describe('async files mode walker', () => {
  beforeAll(async () => {
    await fs.mkdir(path.join(tempDir, 'nested'), { recursive: true })
    await fs.writeFile(path.join(tempDir, 'nested', 'payload.exe'), 'binary')
    await fs.writeFile(path.join(tempDir, 'nested', 'notes.txt'), 'text')
    await fs.writeFile(path.join(tempDir, 'image.png'), 'image')
  })

  afterAll(async () => {
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  it('walks nested directories and keeps only target extensions', async () => {
    const files = await collectWalker(tempDir)

    expect(files).toContain(path.join(tempDir, 'nested', 'payload.exe'))
    expect(files).not.toContain(path.join(tempDir, 'nested', 'notes.txt'))
    expect(files).not.toContain(path.join(tempDir, 'image.png'))
  })

  it('propagates cancellation before reading a directory', async () => {
    const controller = new AbortController()
    controller.abort()

    await expect(collectWalker(tempDir, controller.signal)).rejects.toThrow('aborted')
  })

  it('skips inaccessible or missing directories without returning fake files', async () => {
    await expect(collectWalker(path.join(tempDir, 'missing'))).resolves.toEqual([])
  })
})
