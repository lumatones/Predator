import { EventEmitter } from 'events'
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { spawn } from 'child_process'

vi.mock('child_process', () => ({
  execSync: vi.fn(),
  execFileSync: vi.fn(),
  spawn: vi.fn(),
}))

import { execPowerShellAsync, spawnAsyncWithTimeout } from '../utils/exec'

type MockChild = EventEmitter & {
  pid: number
  stdout: EventEmitter & { setEncoding: ReturnType<typeof vi.fn> }
  kill: ReturnType<typeof vi.fn>
}

function makeChild(): MockChild {
  const child = new EventEmitter() as MockChild
  const stdout = new EventEmitter() as MockChild['stdout']
  stdout.setEncoding = vi.fn()
  child.pid = 1234
  child.stdout = stdout
  child.kill = vi.fn()
  return child
}

describe('spawnAsyncWithTimeout', () => {
  beforeEach(() => {
    vi.mocked(spawn).mockReset()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('resolves collected stdout when the process exits successfully', async () => {
    const child = makeChild()
    vi.mocked(spawn).mockReturnValue(child as never)

    const resultPromise = spawnAsyncWithTimeout('powershell', ['-NoProfile', '-Command', 'Write-Output ok'])
    child.stdout.emit('data', 'ok')
    child.emit('close', 0, null)

    await expect(resultPromise).resolves.toBe('ok')
    expect(spawn).toHaveBeenCalledWith('powershell', ['-NoProfile', '-Command', 'Write-Output ok'], expect.objectContaining({ shell: false }))
  })

  it('returns null for a non-zero exit', async () => {
    const child = makeChild()
    vi.mocked(spawn).mockReturnValue(child as never)

    const resultPromise = spawnAsyncWithTimeout('7z', ['l', 'broken.zip'])
    child.emit('close', 2, null)

    await expect(resultPromise).resolves.toBeNull()
  })

  it('terminates and resolves null on timeout', async () => {
    vi.useFakeTimers()
    const child = makeChild()
    vi.mocked(spawn).mockReturnValue(child as never)

    const resultPromise = spawnAsyncWithTimeout('powershell', [], { timeout: 25 })
    await vi.advanceTimersByTimeAsync(25)

    expect(child.kill).toHaveBeenCalledTimes(1)
    await expect(resultPromise).resolves.toBeNull()
  })

  it('terminates and resolves null when the signal is aborted', async () => {
    const child = makeChild()
    vi.mocked(spawn).mockReturnValue(child as never)
    const controller = new AbortController()

    const resultPromise = spawnAsyncWithTimeout('powershell', [], { signal: controller.signal })
    controller.abort()

    expect(child.kill).toHaveBeenCalledTimes(1)
    await expect(resultPromise).resolves.toBeNull()
  })

  it('does not spawn when the signal is already aborted', async () => {
    const controller = new AbortController()
    controller.abort()

    await expect(spawnAsyncWithTimeout('powershell', [], { signal: controller.signal })).resolves.toBeNull()
    expect(spawn).not.toHaveBeenCalled()
  })

  it('returns null when spawning throws synchronously', async () => {
    vi.mocked(spawn).mockImplementationOnce(() => {
      throw new Error('spawn unavailable')
    })

    await expect(spawnAsyncWithTimeout('powershell', [])).resolves.toBeNull()
  })

  it('terminates when stdout exceeds maxBuffer', async () => {
    const child = makeChild()
    vi.mocked(spawn).mockReturnValue(child as never)

    const resultPromise = spawnAsyncWithTimeout('powershell', [], { maxBuffer: 3 })
    child.stdout.emit('data', 'four')

    expect(child.kill).toHaveBeenCalledTimes(1)
    await expect(resultPromise).resolves.toBeNull()
  })
})

describe('execPowerShellAsync', () => {
  it('passes the script as a direct argument without shell quoting', async () => {
    const child = makeChild()
    vi.mocked(spawn).mockReturnValue(child as never)
    const script = 'Write-Output "safe"\nWrite-Output done'

    const resultPromise = execPowerShellAsync(script, { collapseLines: 'semicolons' })
    child.stdout.emit('data', 'safe\ndone')
    child.emit('close', 0, null)

    await expect(resultPromise).resolves.toBe('safe\ndone')
    expect(spawn).toHaveBeenCalledWith(
      'powershell',
      ['-NoProfile', '-Command', 'Write-Output "safe"; Write-Output done'],
      expect.objectContaining({ shell: false, windowsHide: true }),
    )
  })
})
