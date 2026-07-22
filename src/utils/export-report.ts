/**
 * Predator v3.0 — Report Export Utilities
 * Ported from predator_scanner_v3/reporters/
 *
 * Generates HTML reports with Chart.js graphs and JSON exports
 * from scan results (compatible with ScanResult type).
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
      size_bytes: r.size,
      modified_at: r.modifiedAt,
    })),
  }

  return JSON.stringify(report, null, 2)
}

// ── HTML Export with Chart.js ──

export function exportHtml(results: ScanResult[], summary: ScanResponse['summary']): string {
  const highCount = results.filter(r => r.risk === 'high').length
  const mediumCount = results.filter(r => r.risk === 'medium').length
  const lowCount = results.filter(r => r.risk === 'low').length

  const riskLevels = { high: highCount, medium: mediumCount, low: lowCount }

  // Group by type
  const typeCounts: Record<string, number> = {}
  for (const r of results) {
    typeCounts[r.type] = (typeCounts[r.type] || 0) + 1
  }

  const findingsHtml = results
    .sort((a, b) => {
      const order = { high: 0, medium: 1, low: 2 }
      return (order[a.risk] || 0) - (order[b.risk] || 0)
    })
    .map(r => `
    <div class="finding ${r.risk}">
      <div class="finding-header">
        <span><strong>[${r.type}]</strong> ${escapeHtml(r.fileName)}</span>
        <span class="finding-level level-${r.risk}">${r.risk.toUpperCase()}</span>
      </div>
      <div class="finding-path">${escapeHtml(r.path)}</div>
      <div class="finding-details">
        ${r.matches.slice(0, 3).map(m => `<span class="match-tag">${escapeHtml(m.split(':').slice(1).join(':') || m)}</span>`).join(' ')}
        ${r.matches.length > 3 ? `<span class="match-tag">+${r.matches.length - 3} more</span>` : ''}
      </div>
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
    .finding.high { border-color: #ef4444; }
    .finding.medium { border-color: #F59E0B; }
    .finding.low { border-color: #22c55e; }
    .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
    .finding-level {
      padding: 0.2rem 0.6rem; border-radius: 9999px; font-size: 0.75rem;
      font-weight: bold; text-transform: uppercase;
    }
    .level-high { background: #ef4444; color: white; }
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
      <h1>🛡️ <span>Predator</span> Anti-Cheat</h1>
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
      <h2>🔍 Найденные угрозы (${results.length})</h2>
      ${results.length > 0 ? findingsHtml : '<p style="color: #22c55e; font-size: 1.2rem;">✅ Подозрительных элементов не обнаружено</p>'}
    </div>

    <div class="footer">
      Predator Anti-Cheat v3.0 | ${new Date().toISOString().slice(0, 10)}
    </div>
  </div>
</body>
</html>`
}

// ── Helpers ──

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
