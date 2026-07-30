/**
 * Predator Memory Dumper
 * Дампит память подозрительного процесса через MiniDumpWriteDump,
 * затем извлекает из дампа строки (чит уже распакован в памяти).
 */

import fs from 'fs'
import path from 'path'
import os from 'os'
import { execPowerShell, execWithTimeout } from './utils/exec'
import { checkAutoRulesOnStrings } from './auto-yara'

export interface DumpResult {
  success: boolean
  dumpPath: string
  extractedStrings: string[]
  cheatMatches: string[]
  riskScore: number
}

const TEMP_DIR = path.join(os.tmpdir(), 'predator_dumps')

function ensureTemp() {
  if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true })
}

function cleanupTemp() {
  try {
    for (const f of fs.readdirSync(TEMP_DIR)) {
      const p = path.join(TEMP_DIR, f)
      const stat = fs.statSync(p)
      if (Date.now() - stat.mtimeMs > 3600000) fs.unlinkSync(p)
    }
  } catch (err) { console.warn('[memory-dump] failed:', (err as Error).message) }
}

/** Дамп процесса через PowerShell + MiniDumpWriteDump */
export function dumpProcessMemory(pid: number, tag = 'suspicious'): string | null {
  ensureTemp()
  cleanupTemp()

  const outPath = path.join(TEMP_DIR, `dump_${tag}_${pid}_${Date.now()}.dmp`)
  const psScript = `
Add-Type @"
using System;
using System.IO;
using System.Runtime.InteropServices;
public class Mdmp {
  [DllImport("dbghelp.dll", SetLastError=true)] public static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId, IntPtr hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);
  [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);
}
"@
$proc = ${pid}
$h = [Mdmp]::OpenProcess(0x1F0FFF, $false, $proc)
if ($h -eq 0) { throw "OpenProcess failed" }
$fs = [IO.File]::Create("${outPath.replace(/\\/g, '\\\\')}")
$ok = [Mdmp]::MiniDumpWriteDump($h, $proc, $fs.SafeFileHandle.DangerousGetHandle(), 2, 0, 0, 0)
$fs.Close()
[Mdmp]::CloseHandle($h)
if (-not $ok) { throw "MiniDumpWriteDump failed" }
  `.trim()

  try {
    execPowerShell(psScript, { timeout: 15000, collapseLines: 'semicolons' })
    return fs.existsSync(outPath) && fs.statSync(outPath).size > 4096 ? outPath : null
  } catch {
    return null
  }
}

/** Извлечь строки из большого файла (читаем первые 100 МБ) */
function extractUniqueStringsFromLargeFile(filepath: string): string[] {
  const all = new Set<string>()
  try {
    const size = fs.statSync(filepath).size
    const fd = fs.openSync(filepath, 'r')
    const chunkSize = Math.min(100 * 1024 * 1024, size)
    const buf = Buffer.alloc(chunkSize)
    fs.readSync(fd, buf, 0, chunkSize, 0)
    fs.closeSync(fd)

    let cur = ''
    for (let i = 0; i < buf.length; i++) {
      const b = buf[i]
      if (b >= 0x20 && b <= 0x7E) {
        cur += String.fromCharCode(b)
      } else {
        if (cur.length >= 6 && cur.length <= 80) all.add(cur)
        cur = ''
      }
    }
  } catch (err) { console.warn('[memory-dump] failed:', (err as Error).message) }
  return Array.from(all)
}

/** Проверка дампа на inline hooks (jmp/detour в начале известных API) */
export function scanInlineHooksInDump(fileStrings: string[], rawBuffer?: Buffer): string[] {
  const hooks: string[] = []

  // Ищем имена API, которые часто хукают
  const HOOKED_API_NAMES = [
    'createremotethread', 'writeprocessmemory', 'ntcreatethreadex',
    'ntqueryinformationprocess', 'ntreadvirtualmemory', 'ntwritevirtualmemory',
    'ntopenprocess', 'ntsuspendprocess', 'ntresumeprocess',
    'setwindowshookex', 'callnexthookex', 'unhookwindowshookex',
    'dbguiremovessecurity', 'zwqueryinformationprocess',
    'getasynckeystate', 'getkeystate', 'getforegroundwindow',
  ]

  // Ищем фреймворки/строки детекта хуков
  const HOOK_KEYWORDS = [
    'hooked', 'detour', 'trampoline', 'minhook', 'easyhook', 'polyhook',
    'nop sled', 'jmp', 'call eax', 'call edx',
    'inline hook', 'iat hook', 'eat hook', 'vmt hook',
    'mhook', 'detours', 'function hook', 'api hook',
  ]

  // 1) Ищем строки хуков в дампе
  for (const s of fileStrings) {
    const sl = s.toLowerCase()
    for (const kw of HOOK_KEYWORDS) {
      if (sl.includes(kw)) {
        hooks.push(`🔗 Hook framework string: ${s.slice(0, 60)}`)
        break
      }
    }
  }

  // 2) Ищем подозрительное сочетание: рядом имя API и "hook"
  for (const apiName of HOOKED_API_NAMES) {
    const foundApi = fileStrings.some(s => s.toLowerCase().includes(apiName))
    const foundHook = fileStrings.some(s => {
      const sl = s.toLowerCase()
      return sl.includes('hook') || sl.includes('detour') || sl.includes('trampoline')
    })
    if (foundApi && foundHook) {
      hooks.push(`🔗 Suspicious: ${apiName} + hook keyword in dump (possible inline hook)`)
    }
  }

  // 3) Ищем JMP-инструкции (E9 xx xx xx xx) прямо в сыром буфере дампа
  if (rawBuffer && rawBuffer.length >= 5) {
    let jmpCount = 0
    for (let i = 0; i < rawBuffer.length - 4; i++) {
      // E9 = JMP rel32
      if (rawBuffer[i] === 0xE9) {
        jmpCount++
        if (jmpCount <= 5) {
          const target = rawBuffer.readInt32LE(i + 1)
          hooks.push(`🔗 JMP (E9) at offset 0x${i.toString(16)} → 0x${(i + 5 + target).toString(16)} (possible inline hook)`)
        }
      }
      // FF 25 = JMP [rip+disp32] (another common hook pattern)
      if (i + 1 < rawBuffer.length && rawBuffer[i] === 0xFF && rawBuffer[i + 1] === 0x25) {
        jmpCount++
        if (jmpCount <= 5) {
          const target = rawBuffer.readInt32LE(i + 2)
          hooks.push(`🔗 JMP [rip+off] (FF 25) at offset 0x${i.toString(16)} → 0x${(i + 6 + target).toString(16)} (possible hook)`)
        }
      }
    }
  }

  return hooks
}

/** Анализ дампа: ищем чит-строки */
export function analyzeDump(dumpPath: string, keywords: string[], _unused?: unknown): DumpResult {
  const result: DumpResult = {
    success: false,
    dumpPath,
    extractedStrings: [],
    cheatMatches: [],
    riskScore: 0,
  }

  if (!fs.existsSync(dumpPath)) return result

  try {
    const strings = extractUniqueStringsFromLargeFile(dumpPath)
    result.extractedStrings = strings
    result.success = true

    const kwLower = keywords.map(k => k.toLowerCase())
    for (const s of strings) {
      const sl = s.toLowerCase()
      for (const kw of kwLower) {
        if (sl.includes(kw)) {
          result.cheatMatches.push(`dump:${kw} → ${s.slice(0, 40)}`)
          result.riskScore += 15
        }
      }
    }

    try {
      const { matched, score } = checkAutoRulesOnStrings(strings)
      if (matched) {
        result.cheatMatches.push(`auto-rule-match: score ${score.toFixed(0)}`)
        result.riskScore += score
      }
    } catch { /* auto-rule check optional */ }

    // ── Inline Hooks detection in dump ──
    let rawDumpBuf: Buffer | undefined
    try {
      const fstat = fs.statSync(dumpPath)
      const readSize = Math.min(fstat.size, 10 * 1024 * 1024) // max 10 MB
      const fd = fs.openSync(dumpPath, 'r')
      rawDumpBuf = Buffer.alloc(readSize)
      fs.readSync(fd, rawDumpBuf, 0, readSize, 0)
      fs.closeSync(fd)
    } catch (err) { console.warn('[memory-dump] failed:', (err as Error).message) }
    const hookMatches = scanInlineHooksInDump(strings, rawDumpBuf)
    for (const h of hookMatches) {
      result.cheatMatches.push(h)
      result.riskScore += 20
    }

    result.riskScore = Math.min(result.riskScore, 100)
  } catch (err) { console.warn('[memory-dump] failed:', (err as Error).message) }

  return result
}

/** Полный pipeline: дамп + анализ + удаление дампа */
export function dumpAndAnalyze(
  pid: number,
  keywords: string[],
  tag?: string,
  checkAutoRulesFn?: (strings: string[]) => { matched: boolean; score: number },
): DumpResult {
  const dumpPath = dumpProcessMemory(pid, tag)
  if (!dumpPath) {
    return { success: false, dumpPath: '', extractedStrings: [], cheatMatches: [], riskScore: 0 }
  }

  const result = analyzeDump(dumpPath, keywords, checkAutoRulesFn)

  try { fs.unlinkSync(dumpPath) } catch (err) { console.warn('[memory-dump] failed:', (err as Error).message) }

  return result
}

/** Удалить все старые дампы */
export function purgeAllDumps() {
  try {
    if (fs.existsSync(TEMP_DIR)) {
      for (const f of fs.readdirSync(TEMP_DIR)) {
        fs.unlinkSync(path.join(TEMP_DIR, f))
      }
    }
  } catch (err) { console.warn('[memory-dump] failed:', (err as Error).message) }
}
