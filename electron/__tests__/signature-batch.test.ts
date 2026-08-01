import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../utils/exec', () => ({
  execPowerShellAsync: vi.fn(),
  execWithTimeout: vi.fn(),
}))

import { execPowerShellAsync } from '../utils/exec'
import { ctx } from '../types'
import { batchCheckSignatures, checkDigitalSignature } from '../heuristic/signature-batch'

const mockedExec = vi.mocked(execPowerShellAsync)

beforeEach(() => {
  mockedExec.mockReset()
  ctx.sigCache.clear()
})

describe('async digital signature checks', () => {
  it('parses a valid batch response and caches only boolean entries', async () => {
    const signedPath = `C:\\Program Files\\Tool's\\signed.exe`
    const unsignedPath = 'C:\\Temp\\unsigned.dll'
    mockedExec.mockResolvedValue(JSON.stringify({
      [signedPath]: true,
      [unsignedPath]: false,
    }))

    const result = await batchCheckSignatures([signedPath, unsignedPath, 'notes.txt'])

    expect(result).toEqual(new Map([
      [signedPath, true],
      [unsignedPath, false],
    ]))
    expect(ctx.sigCache.get(signedPath)).toBe(true)
    expect(ctx.sigCache.get(unsignedPath)).toBe(false)
    expect(mockedExec).toHaveBeenCalledTimes(1)
    const [script] = mockedExec.mock.calls[0]
    expect(script).toContain("Tool''s")
  })

  it('uses the cache without starting PowerShell again', async () => {
    const filepath = 'C:\\cached.exe'
    ctx.sigCache.set(filepath, true)

    await expect(checkDigitalSignature(filepath)).resolves.toBe(true)
    await expect(batchCheckSignatures([filepath])).resolves.toEqual(new Map([[filepath, true]]))
    expect(mockedExec).not.toHaveBeenCalled()
  })

  it('does not poison the cache when batch output is malformed or missing', async () => {
    const firstPath = 'C:\\first.exe'
    const secondPath = 'C:\\second.exe'
    mockedExec.mockResolvedValue('{not-json')

    await expect(batchCheckSignatures([firstPath, secondPath])).resolves.toEqual(new Map([
      [firstPath, false],
      [secondPath, false],
    ]))
    expect(ctx.sigCache.has(firstPath)).toBe(false)
    expect(ctx.sigCache.has(secondPath)).toBe(false)
  })

  it('does not cache a missing batch key as an unsigned verdict', async () => {
    const checkedPath = 'C:\\checked.exe'
    const missingPath = 'C:\\missing.exe'
    mockedExec.mockResolvedValue(JSON.stringify({ [checkedPath]: true }))

    await expect(batchCheckSignatures([checkedPath, missingPath])).resolves.toEqual(new Map([
      [checkedPath, true],
      [missingPath, false],
    ]))
    expect(ctx.sigCache.get(checkedPath)).toBe(true)
    expect(ctx.sigCache.has(missingPath)).toBe(false)
  })

  it('does not cache a timeout or an unexpected single-file status', async () => {
    const timeoutPath = 'C:\\timeout.exe'
    const unexpectedPath = 'C:\\unexpected.exe'
    mockedExec.mockResolvedValueOnce(null).mockResolvedValueOnce('UnexpectedStatus\n')

    await expect(checkDigitalSignature(timeoutPath)).resolves.toBe(false)
    await expect(checkDigitalSignature(unexpectedPath)).resolves.toBe(false)

    expect(ctx.sigCache.has(timeoutPath)).toBe(false)
    expect(ctx.sigCache.has(unexpectedPath)).toBe(false)
  })

  it('caches a recognized unsigned Authenticode status', async () => {
    const filepath = 'C:\\unsigned.exe'
    mockedExec.mockResolvedValue('NotSigned\n')

    await expect(checkDigitalSignature(filepath)).resolves.toBe(false)
    expect(ctx.sigCache.get(filepath)).toBe(false)
  })

  it('propagates cancellation without invoking PowerShell', async () => {
    const controller = new AbortController()
    controller.abort()

    await expect(batchCheckSignatures(['C:\\cancelled.exe'], 500, controller.signal))
      .rejects.toThrow('aborted')
    await expect(checkDigitalSignature('C:\\cancelled.dll', controller.signal))
      .rejects.toThrow('aborted')
    expect(mockedExec).not.toHaveBeenCalled()
  })

  it('splits batches and preserves cache results across batches', async () => {
    mockedExec
      .mockResolvedValueOnce(JSON.stringify({ 'C:\\one.exe': true }))
      .mockResolvedValueOnce(JSON.stringify({ 'C:\\two.exe': false }))

    const result = await batchCheckSignatures(['C:\\one.exe', 'C:\\two.exe'], 1)

    expect(result).toEqual(new Map([
      ['C:\\one.exe', true],
      ['C:\\two.exe', false],
    ]))
    expect(mockedExec).toHaveBeenCalledTimes(2)
  })
})
