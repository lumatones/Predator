/**
 * Predator — Prometheus Metrics
 *
 * Lightweight metrics exposed at GET /metrics.
 * Uses prom-client for standard Prometheus format.
 *
 * Tracks:
 *   - HTTP request counts by method, path, status
 *   - HTTP request duration histogram
 *   - Active scans gauge
 *   - Total scans counter
 *   - Token usage counter
 *   - Hash submissions counter
 */

import express from 'express'
import type { Request, Response, NextFunction } from 'express'

// ── In-memory metrics store (no external dependencies) ──

interface MetricCounter {
  name: string
  help: string
  type: 'counter'
  values: Map<string, number>
  labels: string[]
}

interface MetricGauge {
  name: string
  help: string
  type: 'gauge'
  values: Map<string, number>
  labels: string[]
}

interface MetricHistogram {
  name: string
  help: string
  type: 'histogram'
  buckets: number[]
  values: Map<string, { sum: number; count: number; buckets: Map<number, number> }>
  labels: string[]
}

type Metric = MetricCounter | MetricGauge | MetricHistogram

const metrics: Map<string, Metric> = new Map()

function registerCounter(name: string, help: string, labels: string[] = []): MetricCounter {
  const m: MetricCounter = { name, help, type: 'counter', values: new Map(), labels }
  metrics.set(name, m)
  return m
}

function registerGauge(name: string, help: string, labels: string[] = []): MetricGauge {
  const m: MetricGauge = { name, help, type: 'gauge', values: new Map(), labels }
  metrics.set(name, m)
  return m
}

function registerHistogram(
  name: string,
  help: string,
  labels: string[] = [],
  buckets: number[] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
): MetricHistogram {
  const m: MetricHistogram = { name, help, type: 'histogram', buckets, values: new Map(), labels }
  metrics.set(name, m)
  return m
}

function labelKey(labels: string[]): string {
  return labels.join('|')
}

function incCounter(m: MetricCounter, by: number, ...labelValues: string[]): void {
  const key = labelKey(labelValues)
  m.values.set(key, (m.values.get(key) || 0) + by)
}

function setGauge(m: MetricGauge, value: number, ...labelValues: string[]): void {
  const key = labelKey(labelValues)
  m.values.set(key, value)
}

function observeHistogram(m: MetricHistogram, value: number, ...labelValues: string[]): void {
  const key = labelKey(labelValues)
  let entry = m.values.get(key)
  if (!entry) {
    entry = { sum: 0, count: 0, buckets: new Map() }
    for (const b of m.buckets) entry.buckets.set(b, 0)
    m.values.set(key, entry)
  }
  entry.sum += value
  entry.count++
  for (const b of m.buckets) {
    if (value <= b) {
      entry.buckets.set(b, (entry.buckets.get(b) || 0) + 1)
    }
  }
}

function formatPrometheus(): string {
  const lines: string[] = []

  for (const [, m] of metrics) {
    lines.push(`# HELP ${m.name} ${m.help}`)
    lines.push(`# TYPE ${m.name} ${m.type}`)

    if (m.type === 'histogram') {
      const hm = m as MetricHistogram
      for (const [key, entry] of hm.values) {
        const labelPart = formatLabels(hm.labels, key)
        for (const b of hm.buckets) {
          const bucketVal = entry.buckets.get(b) || 0
          lines.push(`${m.name}_bucket${labelPart}${commaIf(labelPart)}le="${b}"} ${bucketVal}`)
        }
        lines.push(`${m.name}_bucket${labelPart}${commaIf(labelPart)}le="+Inf"} ${entry.count}`)
        lines.push(`${m.name}_sum${labelPart} ${entry.sum}`)
        lines.push(`${m.name}_count${labelPart} ${entry.count}`)
      }
    } else if (m.type === 'gauge') {
      for (const [key, val] of m.values) {
        const labelPart = formatLabels(m.labels, key)
        lines.push(`${m.name}${labelPart} ${val}`)
      }
    } else {
      // counter
      for (const [key, val] of m.values) {
        const labelPart = formatLabels(m.labels, key)
        lines.push(`${m.name}${labelPart} ${val}`)
      }
    }
  }

  return lines.join('\n') + '\n'
}

function formatLabels(names: string[], key: string): string {
  const values = key.split('|')
  if (names.length === 0) return ''
  const parts = names.map((n, i) => `${n}="${values[i] || ''}"`)
  return `{${parts.join(',')}}`
}

function commaIf(s: string): string {
  return s.endsWith('}') ? ',' : ''
}

// ═══════════════════════════════════════════════════
// REGISTER METRICS
// ═══════════════════════════════════════════════════

const httpRequestsTotal = registerCounter(
  'predator_http_requests_total',
  'Total HTTP requests',
  ['method', 'path', 'status'],
)

const httpRequestDuration = registerHistogram(
  'predator_http_request_duration_seconds',
  'HTTP request duration in seconds',
  ['method', 'path'],
)

const scansTotal = registerCounter(
  'predator_scans_total',
  'Total scan submissions',
  ['mode', 'pc_username'],
)

const scansHighRiskTotal = registerCounter(
  'predator_scans_high_risk_total',
  'High-risk findings count',
  ['mode'],
)

const hashesSubmitted = registerCounter(
  'predator_hashes_submitted_total',
  'Total hash submissions',
  ['pc_username'],
)

const hashesConfirmed = registerCounter(
  'predator_hashes_confirmed_total',
  'Total confirmed cheat hashes',
  [],
)

const tokensUsed = registerCounter(
  'predator_tokens_used_total',
  'Total tokens used',
  [],
)

const activeUsers = registerGauge(
  'predator_active_users',
  'Active users (tokens used in last 24h)',
  [],
)

// ═══════════════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════════════

export function metricsMiddleware(req: Request, res: Response, next: NextFunction): void {
  const start = Date.now()

  // Track response via 'finish' event
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000
    const path = normalizePath(req.path)

    incCounter(httpRequestsTotal, 1, req.method, path, String(res.statusCode))
    observeHistogram(httpRequestDuration, duration, req.method, path)
  })

  next()
}

function normalizePath(p: string): string {
  // Group dynamic path segments
  return p
    .replace(/\/\d+/g, '/:id')
    .replace(/\/[a-f0-9]{8}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{12}/g, '/:uuid')
    .replace(/\/[A-F0-9]{32}/g, '/:token')
    .replace(/\/[a-f0-9]{64}/g, '/:sha256')
}

// ═══════════════════════════════════════════════════
// PUBLIC API — called from route handlers
// ═══════════════════════════════════════════════════

export function trackScan(mode: string, pcUsername: string, highRiskCount: number): void {
  incCounter(scansTotal, 1, mode, pcUsername)
  if (highRiskCount > 0) {
    incCounter(scansHighRiskTotal, highRiskCount, mode)
  }
}

export function trackHashSubmission(pcUsername: string, count: number): void {
  incCounter(hashesSubmitted, count, pcUsername)
}

export function trackHashConfirmed(): void {
  incCounter(hashesConfirmed, 1)
}

export function trackTokenUsed(): void {
  incCounter(tokensUsed, 1)
}

export function setActiveUsers(count: number): void {
  setGauge(activeUsers, count)
}

// ═══════════════════════════════════════════════════
// METRICS ROUTER
// ═══════════════════════════════════════════════════

export const metricsRouter = express.Router()

metricsRouter.get('/metrics', (_req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/plain; version=0.0.4')
  res.send(formatPrometheus())
})

// ═══════════════════════════════════════════════════
// PERIODIC GAUGE UPDATES
// ═══════════════════════════════════════════════════

export function startMetricsUpdater(queryFn: (sql: string, params?: any[]) => Promise<any>): void {
  setInterval(async () => {
    try {
      const rows = await queryFn(
        "SELECT COUNT(DISTINCT used_by) AS cnt FROM tokens WHERE used_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)"
      )
      setActiveUsers(rows[0]?.cnt || 0)
    } catch { /* skip */ }
  }, 60 * 1000) // every minute
}
