import { useMemo, useState } from 'react'
import type { BinaryTriageReport, TriageSeverity } from '../../../types/binary-triage'

interface BinaryTriagePanelProps {
  report: BinaryTriageReport
  lang: 'ru' | 'en'
  onClose: () => void
}

const severityColor: Record<TriageSeverity, string> = {
  critical: 'var(--accent-red)',
  high: 'var(--accent-orange)',
  medium: 'var(--color-warning)',
  low: 'var(--text-muted)',
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function severityLabel(severity: TriageSeverity, lang: 'ru' | 'en'): string {
  if (lang === 'en') return severity.toUpperCase()
  return ({ critical: 'КРИТИЧЕСКИЙ', high: 'ВЫСОКИЙ', medium: 'СРЕДНИЙ', low: 'НИЗКИЙ' } as Record<TriageSeverity, string>)[severity]
}

export function BinaryTriagePanel({ report, lang, onClose }: BinaryTriagePanelProps) {
  const [showImports, setShowImports] = useState(false)
  const [showManifest, setShowManifest] = useState(false)
  const t = (ru: string, en: string) => lang === 'ru' ? ru : en
  const riskIndicators = useMemo(() => report.indicators.filter(item => item.severity !== 'low'), [report.indicators])
  const verdictLabel = report.verdict === 'high-risk'
    ? t('ВЫСОКИЙ РИСК', 'HIGH RISK')
    : report.verdict === 'suspicious'
      ? t('ПОДОЗРИТЕЛЬНЫЙ', 'SUSPICIOUS')
      : report.verdict === 'inconclusive'
        ? t('НЕПОЛНЫЙ АНАЛИЗ', 'INCONCLUSIVE')
        : t('НИЗКИЙ РИСК', 'LOW RISK')

  return (
    <section className="binary-triage-panel" data-testid="binary-triage-panel" aria-label={t('Статический разбор бинарника', 'Static binary triage')}>
      <div className="binary-triage-header">
        <div>
          <span className="binary-triage-kicker">STATIC / NO EXECUTION</span>
          <h3>{report.file.fileName}</h3>
          <p>{report.file.path}</p>
        </div>
        <button type="button" className="filedetail-close" onClick={onClose} aria-label={t('Закрыть отчёт', 'Close report')}>×</button>
      </div>

      <div className="binary-triage-verdict" data-verdict={report.verdict}>
        <div>
          <span className="binary-triage-label">{t('Вердикт', 'Verdict')}</span>
          <strong>{verdictLabel}</strong>
        </div>
        <div className="binary-triage-score"><span>{report.score}</span><small>/100</small></div>
      </div>

      <div className="binary-triage-grid">
        <div><span>{t('Размер', 'Size')}</span><strong>{formatSize(report.file.size)}</strong></div>
        <div><span>{t('SHA-256', 'SHA-256')}</span><strong className="binary-triage-mono">{report.file.sha256.slice(0, 16)}…</strong></div>
        <div><span>{t('Подпись', 'Signature')}</span><strong className={report.file.signatureStatus === 'valid' ? 'is-safe' : report.file.signatureStatus === 'unsigned' ? 'is-danger' : 'is-warning'}>{report.file.signatureStatus === 'valid' ? t('Valid', 'Valid') : report.file.signatureStatus === 'unsigned' ? t('Нет', 'Unsigned') : t('Недоступна', 'Unknown')}</strong></div>
        <div><span>{t('Архитектура', 'Architecture')}</span><strong>{report.pe.architecture}</strong></div>
        <div><span>{t('Entry point', 'Entry point')}</span><strong className="binary-triage-mono">{report.pe.entryPointRva}</strong></div>
        <div><span>{t('Секция entry', 'Entry section')}</span><strong>{report.pe.entryPointSection || '—'}</strong></div>
      </div>

      <div className="binary-triage-subsection">
        <div className="binary-triage-section-title">
          <h4>{t('Индикаторы', 'Indicators')} <span>{riskIndicators.length}</span></h4>
          <span className="binary-triage-static-badge">{t('Файл не запускался', 'File not executed')}</span>
        </div>
        <div className="binary-triage-indicators">
          {riskIndicators.map(indicator => (
            <article key={indicator.id} className="binary-triage-indicator" style={{ borderLeftColor: severityColor[indicator.severity] }}>
              <div className="binary-triage-indicator-head">
                <strong>{indicator.title}</strong>
                <span style={{ color: severityColor[indicator.severity] }}>{severityLabel(indicator.severity, lang)} · {Math.round(indicator.confidence * 100)}%</span>
              </div>
              <p>{indicator.explanation}</p>
            </article>
          ))}
          {riskIndicators.length === 0 && <p className="binary-triage-muted">{t('Сильных индикаторов не обнаружено.', 'No strong indicators found.')}</p>}
        </div>
      </div>

      <div className="binary-triage-subsection">
        <div className="binary-triage-section-title">
          <h4>{t('PE-карта', 'PE map')}</h4>
          <span>{report.pe.sectionCount} sections · {report.pe.subsystem}</span>
        </div>
        <div className="binary-triage-table-wrap">
          <table className="binary-triage-table"><thead><tr><th>{t('Секция', 'Section')}</th><th>RVA</th><th>{t('Размер', 'Size')}</th><th>{t('Raw', 'Raw')}</th><th>{t('Entropy', 'Entropy')}</th><th>{t('Flags', 'Flags')}</th></tr></thead><tbody>
            {report.pe.sections.map(section => <tr key={`${section.name}-${section.virtualAddress}`}><td><strong>{section.name}</strong></td><td className="binary-triage-mono">0x{section.virtualAddress.toString(16)}</td><td>{section.virtualSize.toLocaleString()}</td><td>{section.rawBacked ? `${formatSize(section.rawSize)} @ 0x${section.rawOffset.toString(16)}` : 'virtual-only'}</td><td>{section.entropy === null ? '—' : section.entropy.toFixed(2)}</td><td>{[section.executable && 'X', section.writable && 'W'].filter(Boolean).join(' ') || 'R'}</td></tr>)}
          </tbody></table>
        </div>
      </div>

      <div className="binary-triage-subsection">
        <button type="button" className="binary-triage-disclosure" onClick={() => setShowImports(value => !value)} aria-expanded={showImports}>
          <span>{t('Импорты API', 'API imports')} <b>{report.pe.imports.length}</b></span><span>{showImports ? '−' : '+'}</span>
        </button>
        {showImports && <div className="binary-triage-imports">{report.pe.imports.map((item, index) => <div key={`${item.dll}-${item.name || item.ordinal}-${index}`} className="binary-triage-import"><span>{item.dll}</span><strong>{item.name || `ordinal ${item.ordinal}`}</strong><em style={{ color: severityColor[item.risk] }}>{severityLabel(item.risk, lang)}</em>{item.reason && <small>{item.reason}</small>}</div>)}</div>}
      </div>

      <div className="binary-triage-subsection">
        <div className="binary-triage-section-title"><h4>TLS</h4><span>{report.pe.tls.present ? `${report.pe.tls.callbackCount} callbacks · ${report.pe.tls.physicalCallbackCount} raw-backed` : t('не найден', 'not present')}</span></div>
        {report.pe.requestedExecutionLevel && <p className="binary-triage-mono">requestedExecutionLevel = {report.pe.requestedExecutionLevel}</p>}
      </div>

      {report.pe.manifest && <div className="binary-triage-subsection"><button type="button" className="binary-triage-disclosure" onClick={() => setShowManifest(value => !value)} aria-expanded={showManifest}><span>Manifest</span><span>{showManifest ? '−' : '+'}</span></button>{showManifest && <pre className="binary-triage-manifest">{report.pe.manifest}</pre>}</div>}

      <div className="binary-triage-subsection binary-triage-limitations"><h4>{t('Ограничения анализа', 'Analysis limitations')}</h4><ul>{report.limitations.map(item => <li key={item}>{item}</li>)}</ul></div>
    </section>
  )
}
