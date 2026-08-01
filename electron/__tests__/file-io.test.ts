import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { readFilePrefix } from '../utils/file-io'

const tempDir = path.join(os.tmpdir(), `predator-file-io-${Date.now()}`)
const fixturePath = path.join(tempDir, 'fixture.bin')

beforeAll(async () => {
  await fs.mkdir(tempDir, { recursive: true })
  await fs.writeFile(fixturePath, Buffer.from('0123456789abcdef'))
})

afterAll(async () => {
  await fs.rm(tempDir, { recursive: true, force: true })
})

describe('readFilePrefix', () => {
  it('reads no more than the requested prefix', async () => {
    const result = await readFilePrefix(fixturePath, 5)
    expect(result.toString()).toBe('01234')
  })

  it('returns the available bytes when the file is shorter than the limit', async () => {
    const result = await readFilePrefix(fixturePath, 100)
    expect(result.toString()).toBe('0123456789abcdef')
  })

  it('returns an empty buffer for a non-positive limit', async () => {
    await expect(readFilePrefix(fixturePath, 0)).resolves.toEqual(Buffer.alloc(0))
    await expect(readFilePrefix(fixturePath, -1)).resolves.toEqual(Buffer.alloc(0))
  })

  it('rejects missing files without leaving a caller-visible fake success', async () => {
    await expect(readFilePrefix(path.join(tempDir, 'missing.bin'), 8)).rejects.toBeTruthy()
  })

  it('rejects immediately when the read signal is already aborted', async () => {
    const controller = new AbortController()
    controller.abort()

    await expect(readFilePrefix(fixturePath, 8, controller.signal)).rejects.toThrow('File read aborted')
  })
})
