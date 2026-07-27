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
import { recordSession, getProfileSummary } from './persistent-profile'
import { loadSafeFilesDb, markFilesSafe, saveSafeFilesDb, uploadSafeFiles } from './safe-files-db'
import { enqueue } from './telemetry-queue'

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
  } catch { /* telemetry queue optional */ }
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
    if (profile.escalated) {
      console.log(`  📈 Persistent profile: ${profile.totalScans} scans, ${profile.consistencyPercent}% consistent, trend=${profile.trend}`)
    }
  } catch { /* persistent scoring optional */ }
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
  } catch { /* shadow submission optional */ }
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
    saveSafeFilesDb()
    // Upload to community whitelist
    try { uploadSafeFiles() } catch { /* upload optional */ }
  } catch { /* safe-db optional */ }
}

// ═══════════════════════════════════════════════════
// HANDLER 4: HashSubmitter
// ═══════════════════════════════════════════════════

export async function submitHighRiskHashes(
  results: ScanResult[],
  _summary: ScanSummary,
  pctx: PipelineContext,
): Promise<void> {
  try {
    const highRiskWithHash = results.filter(r => r.risk === 'high' && r.sha256 && r.type === 'file')
    if (highRiskWithHash.length === 0) return

    queuePost('/api/auth/submit-hashes', {
      token_id: pctx.tokenId,
      pc_username: pctx.pcUsername,
      hashes: highRiskWithHash.map(r => ({
        sha256: r.sha256,
        file_name: r.fileName,
        file_size: r.size || 0,
        risk_score: 80,
      })),
    })
    console.log(`  CLOUD  Submitted ${highRiskWithHash.length} HIGH-risk hashes`)
  } catch { /* hash submission optional */ }
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
  } catch { /* upload optional */ }
}

// ═══════════════════════════════════════════════════
// PIPELINE RUNNER
// ═══════════════════════════════════════════════════

const DEFAULT_PIPELINE: PipelineStep[] = [
  recordScanSession,
  submitShadowFindings,
  autoWhitelistLowRisk,
  submitHighRiskHashes,
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
    } catch { /* isolated failure — continue to next step */ }
  }
}
