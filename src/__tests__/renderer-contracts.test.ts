import { describe, expect, it } from 'vitest'
import { exportHtml, exportJson, exportMarkdown } from '../utils/export-report'
import { buildFindingExplanation, getFindingKind } from '../utils/finding-explainer'
import { groupResults } from '../utils/result-grouper'
import type { ScanResponse, ScanResult } from '../types/electron'

const summary: ScanResponse['summary'] = {
  totalScanned: 42,
  suspiciousFiles: 2,
  highRiskCount: 2,
  scanTimeMs: 1500,
}

const findings: ScanResult[] = [
  {
    path: 'C:/Games/<suspicious>.dll',
    fileName: 'injector.dll',
    type: 'file',
    risk: 'critical',
    matches: ['signature:dll injector', 'entropy:7.9'],
    size: 2048,
    modifiedAt: '2026-08-01T10:00:00.000Z',
    findingId: 'finding-critical-1',
    riskScore: 97,
    riskExplanation: 'Independent injection and packing signals',
    evidence: [{
      id: 'evidence-critical-1',
      source: 'heuristic',
      category: 'injection',
      weight: 0.9,
      confidence: 92,
      explanation: 'DLL injection pattern',
      raw: 'CreateRemoteThread',
      timestamp: '2026-08-01T10:00:00.000Z',
    }],
  },
  {
    path: 'process:Cheat Engine (PID: 4821)',
    fileName: 'Cheat Engine',
    type: 'process',
    risk: 'high',
    matches: ['process:cheat engine', 'suspicious debugger'],
    size: 0,
    modifiedAt: '2026-08-01T10:01:00.000Z',
  },
]

describe('renderer report contracts', () => {
  it('keeps structured evidence and risk explanation in JSON export', () => {
    const report = JSON.parse(exportJson(findings, summary)) as {
      summary: { high_risk_count: number }
      findings: Array<{ finding_id?: string; evidence?: Array<{ id: string }>; risk_explanation?: string }>
    }

    expect(report.summary.high_risk_count).toBe(2)
    expect(report.findings[0]).toMatchObject({
      finding_id: 'finding-critical-1',
      risk_explanation: 'Independent injection and packing signals',
    })
    expect(report.findings[0].evidence?.[0].id).toBe('evidence-critical-1')
  })

  it('escapes finding content and includes critical risk in HTML and Markdown exports', () => {
    const html = exportHtml(findings, summary)
    const markdown = exportMarkdown(findings, summary)

    expect(html).toContain('C:/Games/&lt;suspicious&gt;.dll')
    expect(html).toContain('CRITICAL')
    expect(html).toContain('Evidence score: <strong>97/100</strong>')
    expect(markdown).toContain('| HIGH Risk | **2** |')
    expect(markdown).toContain('**Evidence score:** **97/100**')
    expect(markdown).toContain('**injection** (92% confidence, 90% weight)')
  })
})

describe('renderer finding explanation contracts', () => {
  it('classifies DMA findings and exposes independent evidence', () => {
    const finding: ScanResult = {
      path: 'PCI Bus',
      fileName: 'Xilinx FPGA Device',
      type: 'hardware',
      risk: 'critical',
      matches: ['pci:Xilinx', 'FPGA device detected'],
      size: 0,
      modifiedAt: '2026-08-01T10:00:00.000Z',
    }

    expect(getFindingKind(finding)).toBe('dma')
    const explanation = buildFindingExplanation(finding, 'en')
    expect(explanation.kind).toBe('dma')
    expect(explanation.confidenceNote).toContain('Risk assessment')
    expect(explanation.evidence.some(item => item.source === 'dma')).toBe(true)
    expect(explanation.indicators.length).toBeGreaterThan(0)
  })
})

describe('renderer result grouping contracts', () => {
  it('groups known cheat findings and counts critical as high risk', () => {
    const grouped = groupResults(findings)

    expect(grouped.cheatGroups).toHaveLength(1)
    expect(grouped.cheatGroups[0].cheatName).toBe('Cheat Engine')
    expect(grouped.cheatGroups[0].findings).toHaveLength(1)
    expect(grouped.otherHigh).toHaveLength(1)
    expect(grouped.summary.totalHighRisk).toBe(2)
    expect(grouped.summary.totalMediumRisk).toBe(0)
  })
})
