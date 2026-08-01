import { beforeEach, describe, expect, it, vi } from 'vitest'
import { scanArchiveContents } from '../heuristic/archive-scan'
import { spawnAsyncWithTimeout } from '../utils/exec'

vi.mock('../utils/exec', () => ({
  spawnAsyncWithTimeout: vi.fn(),
}))

describe('scanArchiveContents', () => {
  beforeEach(() => {
    vi.mocked(spawnAsyncWithTimeout).mockReset()
  })

  it('escapes apostrophes in ZIP paths and passes PowerShell as direct args', async () => {
    vi.mocked(spawnAsyncWithTimeout).mockResolvedValue('folder/eulen.exe\n')
    const filepath = "C:\\Users\\O'Brien\\Downloads\\archive.zip"

    const matches = await scanArchiveContents(filepath)

    expect(matches.some(match => match.includes('archive:eulen.exe'))).toBe(true)
    expect(spawnAsyncWithTimeout).toHaveBeenCalledWith(
      'powershell',
      [
        '-NoProfile',
        '-Command',
        expect.stringContaining("C:\\Users\\O''Brien\\Downloads\\archive.zip"),
      ],
      expect.objectContaining({ timeout: 10000 }),
    )
  })

  it('passes RAR/7z paths as an argument without shell interpolation', async () => {
    vi.mocked(spawnAsyncWithTimeout).mockResolvedValue('Path = folder/nightfall.exe\n')
    const filepath = 'C:\\Users\\Player\\Downloads\\archive with spaces.7z'

    const matches = await scanArchiveContents(filepath)

    expect(matches.some(match => match.includes('archive:nightfall.exe'))).toBe(true)
    expect(spawnAsyncWithTimeout).toHaveBeenCalledWith(
      '7z',
      ['l', '-slt', filepath],
      expect.objectContaining({ timeout: 10000 }),
    )
  })

  it('does not start archive inspection when already aborted', async () => {
    const controller = new AbortController()
    controller.abort()

    await expect(scanArchiveContents('archive.zip', controller.signal)).resolves.toEqual([])
    expect(spawnAsyncWithTimeout).not.toHaveBeenCalled()
  })

  it('treats process failure as an optional archive-scan miss', async () => {
    vi.mocked(spawnAsyncWithTimeout).mockResolvedValue(null)

    await expect(scanArchiveContents('archive.7z')).resolves.toEqual([])
  })
})
