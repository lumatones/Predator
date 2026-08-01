/**
 * Predator v3.0 — Report Export Utilities
 * Generates HTML (Chart.js), JSON, Markdown, and PDF exports.
 * Plus Telegram bot integration for sending reports.
 */

import type { ScanResult, ScanResponse } from '../types/electron'

// ── JSON Export ──

export function exportJson(results: ScanResult[], summary: ScanResponse['summary']): string {
  const report = {
    scanner: 'Predator Anti-Cheat',
    scan_date: new Date().toISOString(),
    summary: {
      total_scanned: summary.totalScanned,
      suspicious_files: summary.suspiciousFiles,
      high_risk_count: summary.highRiskCount,
      scan_time_ms: summary.scanTimeMs,
    },
    findings: results.map(r => ({
      path: r.path,
      file_name: r.fileName,
      type: r.type,
      risk: r.risk,
      matches: r.matches,
      evidence: r.evidence,
      finding_id: r.findingId,
      risk_score: r.riskScore,
      risk_explanation: r.riskExplanation,
      size_bytes: r.size,
      modified_at: r.modifiedAt,
    })),
  }

  return JSON.stringify(report, null, 2)
}

// ── HTML Export with Chart.js ──

export function exportHtml(results: ScanResult[], summary: ScanResponse['summary']): string {
  const highCount = results.filter(r => r.risk === 'critical' || r.risk === 'high').length
  const mediumCount = results.filter(r => r.risk === 'medium').length
  const lowCount = results.filter(r => r.risk === 'low').length

  // Group by type
  const typeCounts: Record<string, number> = {}
  for (const r of results) {
    typeCounts[r.type] = (typeCounts[r.type] || 0) + 1
  }

  const findingsHtml = results
    .sort((a, b) => {
      const order = { critical: 0, high: 0, medium: 1, low: 2 }
      return (order[a.risk] || 0) - (order[b.risk] || 0)
    })
    .map(r => `
    <div class="finding ${escapeHtml(r.risk)}">
      <div class="finding-header">
        <span><strong>[${escapeHtml(r.type)}]</strong> ${escapeHtml(r.fileName)}</span>
        <span class="finding-level level-${escapeHtml(r.risk)}">${escapeHtml(r.risk.toUpperCase())}</span>
      </div>
      <div class="finding-path">${escapeHtml(r.path)}</div>
      <div class="finding-details">
        ${r.matches.slice(0, 3).map(m => `<span class="match-tag">${escapeHtml(m.split(':').slice(1).join(':') || m)}</span>`).join(' ')}
        ${r.matches.length > 3 ? `<span class="match-tag">+${r.matches.length - 3} more</span>` : ''}
      </div>
      ${r.riskScore !== undefined ? `<div class="finding-evidence">Evidence score: <strong>${r.riskScore}/100</strong>${r.riskExplanation ? ` — ${escapeHtml(r.riskExplanation)}` : ''}</div>` : ''}
      <div class="finding-meta">${r.size > 0 ? formatSize(r.size) : ''} | ${r.modifiedAt.slice(0, 10)}</div>
    </div>
  `).join('\n')

  const typeLabels = Object.keys(typeCounts)
  const typeValues = Object.values(typeCounts)
  const typeColors: Record<string, string> = {
    file: '#ff4444', process: '#3B82F6', browser: '#22c55e',
    registry: '#F59E0B', hardware: '#8B5CF6', software: '#06b6d4',
  }

  return `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>Predator Scan Report — ${new Date().toLocaleDateString()}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      line-height: 1.6;
      padding: 2rem;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header { text-align: center; padding: 2rem 0; border-bottom: 2px solid #334155; margin-bottom: 2rem; }
    h1 { color: #f8fafc; font-size: 2.2rem; margin-bottom: 0.5rem; }
    h1 span { background: linear-gradient(135deg, #ef4444, #ff6b35); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .subtitle { color: #94a3b8; font-size: 0.95rem; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .stat-card {
      background: #1e293b; padding: 1.5rem; border-radius: 12px;
      border-left: 4px solid #3b82f6;
    }
    .stat-card.high { border-color: #ef4444; }
    .stat-card.medium { border-color: #F59E0B; }
    .stat-card.low { border-color: #22c55e; }
    .stat-card.neutral { border-color: #3b82f6; }
    .stat-value { font-size: 2rem; font-weight: bold; margin-bottom: 0.25rem; }
    .stat-label { color: #94a3b8; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.5px; }
    .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }
    .chart-container { background: #1e293b; padding: 1.5rem; border-radius: 12px; }
    .findings { margin-bottom: 2rem; }
    h2 { margin-bottom: 1rem; color: #f8fafc; }
    .finding {
      background: #1e293b; margin: 0.5rem 0; padding: 1rem;
      border-radius: 8px; border-left: 4px solid;
    }
    .finding.high, .finding.critical { border-color: #ef4444; }
    .finding.medium { border-color: #F59E0B; }
    .finding.low { border-color: #22c55e; }
    .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
    .finding-level {
      padding: 0.2rem 0.6rem; border-radius: 9999px; font-size: 0.75rem;
      font-weight: bold; text-transform: uppercase;
    }
    .level-high, .level-critical { background: #ef4444; color: white; }
    .level-medium { background: #F59E0B; color: black; }
    .level-low { background: #22c55e; color: black; }
    .finding-path { color: #60a5fa; font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.875rem; margin-bottom: 0.5rem; word-break: break-all; }
    .finding-details { margin-bottom: 0.25rem; }
    .match-tag {
      display: inline-block; background: #334155; padding: 0.15rem 0.5rem;
      border-radius: 4px; font-size: 0.8rem; margin: 0.15rem;
    }
    .finding-meta { color: #64748b; font-size: 0.8rem; }
    .footer { text-align: center; color: #64748b; font-size: 0.85rem; padding: 1rem 0; border-top: 1px solid #334155; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1 style="display: flex; align-items: center; justify-content: center; gap: 12px;">
        <svg width="36" height="36" viewBox="0 0 80 80" fill="none" style="flex-shrink: 0;">
          <circle cx="40" cy="40" r="38" stroke="url(#predator-grad)" stroke-width="2"/>
          <path d="M40 10C40 10 25 30 25 45C25 55 31.7 62 40 62C48.3 62 55 55 55 45C55 30 40 10 40 10Z" fill="url(#predator-grad)" opacity="0.9"/>
          <path d="M28 50L16 68H64L52 50" stroke="url(#predator-grad)" stroke-width="2"/>
          <circle cx="40" cy="42" r="6" fill="white" opacity="0.3"/>
          <defs>
            <linearGradient id="predator-grad" x1="0" y1="0" x2="80" y2="80">
              <stop offset="0%" stop-color="#ef4444"/>
              <stop offset="50%" stop-color="#ff6b35"/>
              <stop offset="100%" stop-color="#cc0000"/>
            </linearGradient>
          </defs>
        </svg>
        <span>Predator</span> Anti-Cheat</h1>
      <p class="subtitle">Отчёт сканирования | ${new Date().toLocaleDateString('ru-RU', { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</p>
    </header>

    <div class="stats-grid">
      <div class="stat-card ${summary.suspiciousFiles > 0 ? 'high' : 'low'}">
        <div class="stat-value">${summary.totalScanned}</div>
        <div class="stat-label">Просканировано</div>
      </div>
      <div class="stat-card ${highCount > 0 ? 'high' : ''}">
        <div class="stat-value">${highCount}</div>
        <div class="stat-label">Высокий риск</div>
      </div>
      <div class="stat-card ${mediumCount > 0 ? 'medium' : ''}">
        <div class="stat-value">${mediumCount}</div>
        <div class="stat-label">Средний риск</div>
      </div>
      <div class="stat-card neutral">
        <div class="stat-value">${(summary.scanTimeMs / 1000).toFixed(1)}s</div>
        <div class="stat-label">Время сканирования</div>
      </div>
    </div>

    ${typeLabels.length > 0 ? `
    <div class="charts">
      <div class="chart-container">
        <canvas id="riskChart"></canvas>
      </div>
      <div class="chart-container">
        <canvas id="typeChart"></canvas>
      </div>
    </div>
    <script>
      new Chart(document.getElementById('riskChart'), {
        type: 'doughnut',
        data: {
          labels: ['High', 'Medium', 'Low'],
          datasets: [{
            data: [${highCount}, ${mediumCount}, ${lowCount}],
            backgroundColor: ['#ef4444', '#F59E0B', '#22c55e'],
            borderWidth: 0,
          }]
        },
        options: {
          responsive: true,
          plugins: { title: { display: true, text: 'По уровню риска', color: '#e2e8f0' } },
        }
      });
      new Chart(document.getElementById('typeChart'), {
        type: 'bar',
        data: {
          labels: [${typeLabels.map(l => `'${l}'`).join(',')}],
          datasets: [{
            label: 'Количество',
            data: [${typeValues.join(',')}],
            backgroundColor: [${typeLabels.map(l => `'${typeColors[l] || '#3b82f6'}'`).join(',')}],
            borderRadius: 4,
          }]
        },
        options: {
          responsive: true,
          plugins: { title: { display: true, text: 'По типу', color: '#e2e8f0' } },
          scales: { y: { ticks: { color: '#94a3b8' } }, x: { ticks: { color: '#94a3b8' } } },
        }
      });
    </script>
    ` : ''}

    <div class="findings">
      <h2 style="display: flex; align-items: center; gap: 8px;">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" style="flex-shrink: 0;">
          <circle cx="11" cy="11" r="8"/>
          <path d="M21 21l-4.35-4.35"/>
        </svg>
        Найденные угрозы (${results.length})</h2>
      ${results.length > 0 ? findingsHtml : '<p style="color: #22c55e; font-size: 1.2rem; display: flex; align-items: center; gap: 8px; justify-content: center;"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2.5" style="flex-shrink: 0;"><polyline points="20 6 9 17 4 12"/></svg> Подозрительных элементов не обнаружено</p>'}
    </div>

    <div class="footer">
      Predator Anti-Cheat v3.0 | ${new Date().toISOString().slice(0, 10)}
    </div>
  </div>
</body>
</html>`
}

// ── Helpers ──

// ── Markdown Export ──

export function exportMarkdown(results: ScanResult[], summary: ScanResponse['summary']): string {
  const highCount = results.filter(r => r.risk === 'critical' || r.risk === 'high').length
  const mediumCount = results.filter(r => r.risk === 'medium').length
  const lowCount = results.filter(r => r.risk === 'low').length
  const date = new Date().toLocaleDateString('ru-RU', {
    year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })

  let md = `# Predator Anti-Cheat — Scan Report\n`
  md += `**Date:** ${date}\n\n`
  md += `---\n\n`
  md += `## Summary\n\n`
  md += `| Metric | Value |\n`
  md += `|--------|-------|\n`
  md += `| Files Scanned | **${summary.totalScanned}** |\n`
  md += `| Suspicious | **${summary.suspiciousFiles}** |\n`
  md += `| HIGH Risk | **${highCount}** |\n`
  md += `| MEDIUM Risk | **${mediumCount}** |\n`
  md += `| LOW Risk | **${lowCount}** |\n`
  md += `| Scan Time | **${(summary.scanTimeMs / 1000).toFixed(1)}s** |\n\n`

  if (results.length > 0) {
    md += `---\n\n## Threats Found (${results.length})\n\n`
    const sorted = [...results].sort((a, b) => {
      const order = { critical: 0, high: 0, medium: 1, low: 2 }
      return (order[a.risk] || 0) - (order[b.risk] || 0)
    })
    for (const r of sorted) {
      const prefix = r.risk === 'critical' || r.risk === 'high' ? '!!' : r.risk === 'medium' ? '! ' : '  '
      md += `### ${prefix} ${r.fileName}\n\n`
      md += `- **Type:** \`${r.type}\` | **Risk:** \`${r.risk.toUpperCase()}\`\n`
      md += `- **Path:** \`${r.path}\`\n`
      if (r.size > 0) md += `- **Size:** ${formatSize(r.size)}\n`
      if (r.modifiedAt) md += `- **Modified:** ${r.modifiedAt.slice(0, 10)}\n`
      if (r.riskScore !== undefined) md += `- **Evidence score:** **${r.riskScore}/100**${r.riskExplanation ? ` — ${r.riskExplanation}` : ''}\\n`
      if (r.evidence && r.evidence.length > 0) {
        md += `- **Evidence:**\\n`
        for (const item of r.evidence.slice(0, 6)) {
          md += `  - **${item.category}** (${item.confidence}% confidence, ${(item.weight * 100).toFixed(0)}% weight): ${item.explanation}\\n`
        }
      }
      if (r.matches.length > 0) {
        md += `- **Matches:**\n`
        for (const m of r.matches.slice(0, 8)) {
          md += `  - ${m}\n`
        }
        if (r.matches.length > 8) md += `  - *...и ещё ${r.matches.length - 8}*\n`
      }
      if (r.sha256) md += `- **SHA256:** \`${r.sha256}\`\n`
      md += `\n`
    }
  } else {
    md += `---\n\n## System Clean\n\nNo suspicious items detected.\n\n`
  }

  md += `---\n\n*Report generated by Predator Anti-Cheat v3.0*\n`
  return md
}

// ── Telegram Export ──

export async function sendToTelegram(
  botToken: string,
  chatId: string,
  results: ScanResult[],
  summary: ScanResponse['summary'],
): Promise<{ success: boolean; error?: string }> {
  if (!botToken || !chatId) {
    return { success: false, error: 'Bot token or chat ID not configured' }
  }

  const md = exportMarkdown(results, summary)

  // Telegram limits: 4096 chars per message
  const MAX_LEN = 3800
  const chunks: string[] = []

  if (md.length <= MAX_LEN) {
    chunks.push(md)
  } else {
    // Split by sections
    const sections = md.split('\n---\n')
    let current = ''
    for (const section of sections) {
      if (current.length + section.length > MAX_LEN) {
        if (current) chunks.push(current)
        current = section
      } else {
        current += (current ? '\n---\n' : '') + section
      }
    }
    if (current) chunks.push(current)
  }

  try {
    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i]
      const prefix = chunks.length > 1 ? `(${i + 1}/${chunks.length})\n` : ''
      const body = prefix + chunk

      const res = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: chatId,
          text: body,
          parse_mode: 'Markdown',
          disable_web_page_preview: true,
        }),
      })

      if (!res.ok) {
        const errData: unknown = await res.json().catch(() => ({}))
        const description = typeof errData === 'object' && errData !== null &&
          'description' in errData && typeof errData.description === 'string'
          ? errData.description
          : `HTTP ${res.status}`
        return { success: false, error: description }
      }

      // Small delay between chunks to avoid rate limiting
      if (i < chunks.length - 1) {
        await new Promise(r => setTimeout(r, 500))
      }
    }
    return { success: true }
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : String(err) }
  }
}

// ── PDF Export (via browser print) ──

export function exportPdf(results: ScanResult[], summary: ScanResponse['summary']): void {
  const html = exportHtml(results, summary)
  const blob = new Blob([html], { type: 'text/html' })
  const url = URL.createObjectURL(blob)
  const win = window.open(url, '_blank', 'width=900,height=700')
  if (win) {
    // Print once window loads; don't revoke URL since print dialog may need it
    const doPrint = () => {
      try { win.print() } catch {}
    }
    if (win.document.readyState === 'complete') {
      doPrint()
    } else {
      win.onload = doPrint
    }
  }
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}
