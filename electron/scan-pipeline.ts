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
 */

import fs from 'fs'
import http from 'http'
import https from 'https'

import type { ScanResult } from './types'
import { ctx } from './types'
import { getApiEndpoint } from './config'
import { recordSession } from './persistent-profile'
import { loadSafeFilesDb, markFilesSafe, saveSafeFilesDb, uploadSafeFiles } from './safe-files-db'

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
// HELPER: Fire-and-forget HTTP POST
// ═══════════════════════════════════════════════════

function firePost(path: string, body: unknown): void {
  try {
    const payload = JSON.stringify(body)
    const { hostname, port, protocol } = getApiEndpoint()
    const transport = protocol === 'https:' ? https : http
    const req = transport.request({
      hostname, port, path, method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
    })
    req.write(payload)
    req.end()
  } catch { /* fire-and-forget — network failures are expected */ }
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
    recordSession({
      mode: pctx.mode as any,
      scanTimeMs: summary.scanTimeMs,
      filesScanned: summary.totalScanned,
      highRiskCount: summary.highRiskCount,
      mediumRiskCount: results.filter(r => r.risk === 'medium').length,
      lowRiskCount: results.filter(r => r.risk === 'low').length,
      topFindings: results.filter(r => r.risk === 'high').slice(0, 5).map(r => r.fileName),
    })
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
    firePost('/api/auth/submit-shadow', {
      type: 'shadow-findings',
      token_id: pctx.tokenId,
      pc_username: pctx.pcUsername,
      findings: ctx.shadowFindings.map(f => ({
        path: f.path, fileName: f.fileName, type: f.type, matches: f.matches,
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

    firePost('/api/auth/submit-hashes', {
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

    firePost('/api/auth/submit-scan', {
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
