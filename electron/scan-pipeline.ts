/**
 * Predator — Scan Pipeline
 *
 * Composable chain of post-scan handlers. Each handler is a fire-and-forget
 * side effect that runs after a scan completes. Failures are isolated —
 * one handler crashing doesn't prevent others from running.
 *
 * Architecture:
 *   SessionRecorder → ShadowSubmitter → AutoWhitelister → HashSubmitter → ResultUploader
 *
 * Each step: (results, summary, ctx) => void, MUST NOT throw.
 *
 * v2: Uses TelemetryQueue for reliable delivery with retry + persistence.
 */

import fs from 'fs'

import type { ScanResult } from './types'
import { ctx } from './types'
import { recordSession, getProfileSummary, updateThreatActors } from './persistent-profile'
import { loadSafeFilesDb, markFilesSafe, saveSafeFilesDb, uploadSafeFiles, refreshSafeFilesDb } from './safe-files-db'
import { enqueue } from './telemetry-queue'
import { rescoreResults, calculateRisk } from './risk-scorer'
import { groupResults } from './result-grouper'

// ═══════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════

export interface PipelineContext {
  tokenId: number
  pcUsername: string
  mode: string
  startTime: number
}

export interface ScanSummary {
  totalScanned: number
  suspiciousFiles: number
  highRiskCount: number
  scanTimeMs: number
}

export type PipelineStep = (
  results: ScanResult[],
  summary: ScanSummary,
  pctx: PipelineContext,
) => Promise<void>

// ═══════════════════════════════════════════════════
// HELPER: Queue payload to telemetry (reliable delivery)
// ═══════════════════════════════════════════════════

function queuePost(path: string, body: unknown): void {
  try {
    enqueue(path, body)
  } catch (err) { console.error('[pipeline:queuePost]', (err as Error).message || err) }
}

// ═══════════════════════════════════════════════════
// HANDLER 1: SessionRecorder
// ═══════════════════════════════════════════════════

export async function recordScanSession(
  results: ScanResult[],
  summary: ScanSummary,
  pctx: PipelineContext,
): Promise<void> {
  try {
    // E18: Re-score results with weighted engine
    const weightedResults = rescoreResults(results)
    const riskReport = calculateRisk(weightedResults)

    const profile = getProfileSummary()
    recordSession({
      mode: pctx.mode as any,
      scanTimeMs: summary.scanTimeMs,
      filesScanned: summary.totalScanned,
      highRiskCount: summary.highRiskCount,
      mediumRiskCount: results.filter(r => r.risk === 'medium').length,
      lowRiskCount: results.filter(r => r.risk === 'low').length,
      topFindings: results.filter(r => r.risk === 'high').slice(0, 5).map(r => r.fileName),
    })

    // E19: Update threat actor profiles with detected cheat names
    const grouped = groupResults(weightedResults)
    const cheatNames = grouped.cheatGroups.map(g => g.cheatName)
    updateThreatActors(cheatNames, weightedResults.filter(r => r.risk === 'high').slice(0, 5).map(r => r.fileName))

    if (profile.escalated) {
      console.log(`  📈 Persistent profile: ${profile.totalScans} scans, ${profile.consistencyPercent}% consistent, trend=${profile.trend}`)
    }
    if (riskReport.level !== 'clean') {
      console.log(`  🎯 Weighted risk: ${riskReport.overall}/100 (${riskReport.level}) — ${riskReport.totalEvidence} signals, ${Object.keys(riskReport.categories).length} categories`)
    }
  } catch (err) { console.error('[pipeline:recordScanSession]', (err as Error).message || err) }
}

// ═══════════════════════════════════════════════════
// HANDLER 2: ShadowSubmitter
// ═══════════════════════════════════════════════════

export async function submitShadowFindings(
  _results: ScanResult[],
  _summary: ScanSummary,
  pctx: PipelineContext,
): Promise<void> {
  try {
    if (ctx.shadowFindings.length === 0) return
    queuePost('/api/auth/submit-shadow', {
      type: 'shadow-findings',
      token_id: pctx.tokenId,
      pc_username: pctx.pcUsername,
      findings: ctx.shadowFindings.map(f => ({
        path: f.path,
        fileName: f.fileName,
        type: f.type,
        ruleName: f.ruleName,
        matches: f.matches,
        sha256: f.sha256,
      })),
    })
  } catch (err) { console.error('[pipeline:submitShadowFindings]', (err as Error).message || err) }
}

// ═══════════════════════════════════════════════════
// HANDLER 3: AutoWhitelister
// ═══════════════════════════════════════════════════

export async function autoWhitelistLowRisk(
  results: ScanResult[],
  _summary: ScanSummary,
  _pctx: PipelineContext,
): Promise<void> {
  try {
    loadSafeFilesDb()

    // 1. Add NEW low-risk files from this scan
    const lowRiskFiles = results
      .filter(r => r.risk === 'low' && fs.existsSync(r.path))
      .map(r => {
        try {
          const st = fs.statSync(r.path)
          return { filepath: r.path, size: st.size, mtimeMs: st.mtimeMs }
        } catch { return null }
      })
      .filter(Boolean) as { filepath: string; size: number; mtimeMs: number }[]
    if (lowRiskFiles.length > 0) {
      markFilesSafe(lowRiskFiles, 'auto')
    }

    // 2. Refresh ALL existing safe DB entries — this fixes the confirmCount deadlock.
    //    Without this, confirmCount stays at 1 forever because isFileSafe() skips
    //    already-whitelisted files in the heuristic scan.
    const { refreshed, removed } = refreshSafeFilesDb()
    if (refreshed > 0 || removed > 0) {
      console.log(`  📁 Safe-files refresh: ${refreshed} confirmed, ${removed} expired`)
    }

    saveSafeFilesDb()

    // 3. Upload to community whitelist (threshold now ≥1 — immediate upload)
    try { uploadSafeFiles() } catch (err) { console.error('[pipeline:uploadSafeFiles]', (err as Error).message || err) }
  } catch (err) { console.error('[pipeline:autoWhitelistLowRisk]', (err as Error).message || err) }
}

// ═══════════════════════════════════════════════════
// HANDLER 4: HashSubmitter — отправляет ВСЕ файлы с хэшами на сервер
// ═══════════════════════════════════════════════════
// Серверный классификатор (classifier.ts) использует partialHash для:
//   1. Сопоставления с safe_files (community whitelist) → auto-safe
//   2. Crowdsource-анализа (сколько уникальных ПК видят этот файл как low-risk)
//   3. Auto-добавления в safe_files при классификации 'safe'
//
// До фикса: partialHash вычислялся только для high-risk, сервер получал undefined
// После фикса: partialHash вычисляется для ВСЕХ файлов (64KB — быстро)

export async function submitAllFindings(
  results: ScanResult[],
  _summary: ScanSummary,
  pctx: PipelineContext,
): Promise<void> {
  try {
    // File-type results with partial hash = can be classified server-side
    const findingsWithHash = results.filter(r => r.type === 'file' && r.partialHash)
    if (findingsWithHash.length === 0) return

    // Slice to 500 to stay within server schema limits
    const hashes = findingsWithHash.slice(0, 500).map(r => ({
      sha256: r.sha256,
      partialHash: r.partialHash,
      file_name: r.fileName,
      file_path: r.path,
      file_size: r.size || 0,
      risk: r.risk,
      matches: r.matches.slice(0, 5),
      risk_score: r.risk === 'high' ? 80 : r.risk === 'medium' ? 50 : 20,
      has_valid_signature: r.hasValidSignature,
    }))

    if (hashes.length === 0) return

    queuePost('/api/auth/submit-hashes', {
      token_id: pctx.tokenId,
      pc_username: pctx.pcUsername,
      hashes,
    })
    console.log(`  CLOUD  Submitted ${hashes.length} findings with hashes (${hashes.filter(h => h.risk === 'high').length} high, ${hashes.filter(h => h.risk === 'medium').length} med, ${hashes.filter(h => h.risk === 'low').length} low)`)
  } catch (err) { console.error('[pipeline:submitAllFindings]', (err as Error).message || err) }
}

// ═══════════════════════════════════════════════════
// HANDLER 5: ResultUploader
// ═══════════════════════════════════════════════════

export async function uploadScanResults(
  results: ScanResult[],
  summary: ScanSummary,
  pctx: PipelineContext,
): Promise<void> {
  try {
    if (results.length === 0) return

    queuePost('/api/auth/submit-scan', {
      token_id: pctx.tokenId,
      pc_username: pctx.pcUsername,
      mode: pctx.mode,
      total_scanned: summary.totalScanned,
      suspicious_files: summary.suspiciousFiles,
      high_risk_count: summary.highRiskCount,
      scan_time_ms: summary.scanTimeMs,
      results: results.slice(0, 100).map(r => ({
        file_name: r.fileName,
        path: r.path,
        type: r.type,
        risk: r.risk,
        matches: r.matches.slice(0, 3),
        sha256: r.sha256 || undefined,
      })),
    })
  } catch (err) { console.error('[pipeline:uploadScanResults]', (err as Error).message || err) }
}

// ═══════════════════════════════════════════════════
// PIPELINE RUNNER
// ═══════════════════════════════════════════════════

const DEFAULT_PIPELINE: PipelineStep[] = [
  recordScanSession,
  submitShadowFindings,
  autoWhitelistLowRisk,
  submitAllFindings,
  uploadScanResults,
]

/**
 * Run all post-scan pipeline steps sequentially.
 * Each step runs in its own try-catch — a failure in one
 * step does NOT prevent subsequent steps from executing.
 */
export async function runPostScanPipeline(
  results: ScanResult[],
  summary: ScanSummary,
  pctx: PipelineContext,
  steps: PipelineStep[] = DEFAULT_PIPELINE,
): Promise<void> {
  for (const step of steps) {
    try {
      await step(results, summary, pctx)
    } catch (err) { console.error(`[pipeline:${step.name || 'anonymous'}]`, (err as Error).message || err) }
  }
}
