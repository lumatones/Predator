/**
 * Predator — APC Injection Detector: Tier 2 — Atom Table Scan
 *
 * Scan Windows global atom tables for shellcode/injection patterns.
 *
 * Atom Bombing stores shellcode in global atom tables (up to 255 chars each),
 * then triggers execution via APC. Atom names with PE headers, NOP sleds,
 * or injection API names are definitive malicious indicators.
 */

import { execSync } from 'child_process'
import { addFindingDedup, type ScanResult } from '../../types'

export function scanAtomTables(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public class AtomReader {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern uint GlobalGetAtomName(ushort nAtom, StringBuilder lpBuffer, int nSize);
}
'@

# Scan atoms from 0xC000 to 0xFFFF (global atom range)
$results = @()
$patterns = @('MZ', 'CreateRemoteThread', 'NtCreateThreadEx',
               'WriteProcessMemory', 'VirtualAllocEx', 'QueueUserAPC',
               'NtQueueApcThread', 'RtlCreateUserThread')

$sb = New-Object System.Text.StringBuilder(512)
for ($i = 0xC000; $i -le 0xFFFF; $i++) {
  # Clear StringBuilder before each call — prevents stale data leaks
  $sb.Clear() | Out-Null
  $len = [AtomReader]::GlobalGetAtomName([ushort]$i, $sb, 512)
  if ($len -gt 0) {
    $name = $sb.ToString()
    foreach ($pat in $patterns) {
      if ($name -match $pat) {
        $results += [PSCustomObject]@{
          AtomId = $i
          AtomHex = "0x$($i.ToString('X4'))"
          Pattern = $pat
          AtomName = $name.Substring(0, [Math]::Min(80, $name.Length))
        }
        break
      }
    }
  }
  # Early bail: stop scanning if no hits after 4096 iterations
  if ($i -gt 0xD000 -and $results.Count -eq 0) { break }
  if ($results.Count -ge 10) { break }
}

if ($results.Count -gt 0) {
  $results | ConvertTo-Json -Compress
} else {
  Write-Output '[]'
}
`
    const out = execSync(`powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 15000, windowsHide: true,
    }).trim()

    if (!out || out === '[]' || out.length < 5) return results

    let atoms: { AtomId?: number; AtomHex?: string; Pattern?: string; AtomName?: string }[] = []
    try { const p = JSON.parse(out); atoms = Array.isArray(p) ? p : [p] } catch { return results }

    for (const atom of atoms) {
      const key = `atom-bomb:${atom.AtomHex}:${atom.Pattern}`
      if (addFindingDedup(key)) {
        results.push({
          path: `system:atom-table`,
          fileName: `⚠ Atom Bombing: Shellcode in atom table — ${atom.AtomHex}`,
          type: 'system',
          risk: 'high',
          matches: [
            `Atom ID: ${atom.AtomHex}`,
            `Pattern: ${atom.Pattern}`,
            `Atom content (truncated): ${(atom.AtomName || '').slice(0, 60)}`,
            '⚠ Atom Bombing stores shellcode in global atom table',
            '⚠ Atom table entries with PE headers or injection APIs = definitive cheat indicator',
          ],
          size: atom.AtomId || 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch { /* atom scan optional */ }

  return results
}
