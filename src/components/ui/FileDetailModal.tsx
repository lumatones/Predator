import React, { useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { buildFindingExplanation, TYPE_LABELS } from '../../utils/finding-explainer'
import type { Lang } from '../../types'
import type { ScanResult } from '../../types/electron'

interface FileDetailModalProps {
  open: boolean
  onClose: () => void
  fileName: string
  filePath: string
  fileType: string
  risk: string
  matches: string[]
  size: number
  sha256?: string
  lang?: Lang
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export const FileDetailModal: React.FC<FileDetailModalProps> = ({
  open, onClose, fileName, filePath, fileType, risk, matches, size, sha256, lang = 'ru',
}) => {
  const finding = useMemo<ScanResult>(() => ({
    fileName,
    path: filePath,
    type: fileType as ScanResult['type'],
    risk: risk as ScanResult['risk'],
    matches,
    size,
    modifiedAt: new Date().toISOString(),
    sha256,
  }), [fileName, filePath, fileType, risk, matches, size, sha256])

  const summary = useMemo(
    () => buildFindingExplanation(finding, lang),
    [finding, lang],
  )

  const riskColor = risk === 'high' ? 'var(--accent-red)' : risk === 'medium' ? 'var(--color-warning)' : '#6B7280'
  const typeLabel = TYPE_LABELS[lang][fileType] || fileType
  const riskLabel = lang === 'ru'
    ? risk === 'high' ? 'Высокий' : risk === 'medium' ? 'Средний' : 'Низкий'
    : risk === 'high' ? 'High' : risk === 'medium' ? 'Medium' : 'Low'

  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            className="filedetail-backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            onClick={onClose}
          />
          <motion.div
            className="filedetail-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="filedetail-title"
            initial={{ opacity: 0, scale: 0.96, y: 12 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96, y: 12 }}
            transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
          >
            <div className="filedetail-header">
              <div className="filedetail-header-left">
                <span className="filedetail-risk-dot" style={{ background: riskColor }} />
                <div>
                  <h3 id="filedetail-title" className="filedetail-filename">{fileName}</h3>
                  <span className="filedetail-path">{filePath}</span>
                </div>
              </div>
              <button className="filedetail-close" onClick={onClose} aria-label={lang === 'ru' ? 'Закрыть' : 'Close'}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>

            <div className="filedetail-stats">
              <div className="filedetail-stat">
                <span className="filedetail-stat-label">{lang === 'ru' ? 'Тип' : 'Type'}</span>
                <span className="filedetail-stat-value">{typeLabel}</span>
              </div>
              <div className="filedetail-stat">
                <span className="filedetail-stat-label">{lang === 'ru' ? 'Риск' : 'Risk'}</span>
                <span className="filedetail-stat-value" style={{ color: riskColor, fontWeight: 700 }}>{riskLabel}</span>
              </div>
              <div className="filedetail-stat">
                <span className="filedetail-stat-label">{lang === 'ru' ? 'Размер' : 'Size'}</span>
                <span className="filedetail-stat-value">{size > 0 ? formatSize(size) : 'N/A'}</span>
              </div>
              {sha256 && (
                <div className="filedetail-stat filedetail-stat-wide">
                  <span className="filedetail-stat-label">SHA256</span>
                  <span className="filedetail-stat-value filedetail-hash">{sha256}</span>
                </div>
              )}
            </div>

            <div className={`filedetail-verdict ${risk}`}>
              <div className="filedetail-verdict-kicker">{lang === 'ru' ? 'Объяснение находки' : 'Finding explanation'}</div>
              <h4 className="filedetail-verdict-title">{summary.title}</h4>
              <p>{summary.description}</p>
              <p><strong>{lang === 'ru' ? 'Почему это важно:' : 'Why it matters:'}</strong> {summary.whyDangerous}</p>
              <p><strong>{lang === 'ru' ? 'Что делать:' : 'Recommended action:'}</strong> {summary.recommendation}</p>
              <p className="filedetail-confidence-note">{summary.confidenceNote}</p>
            </div>

            <div className="filedetail-section">
              <h4 className="filedetail-section-title">{lang === 'ru' ? 'Ключевые индикаторы' : 'Key indicators'}</h4>
              <ul className="filedetail-indicators">
                {summary.indicators.map((indicator, i) => (
                  <li key={i}>{indicator}</li>
                ))}
              </ul>
            </div>

            <div className="filedetail-section">
              <h4 className="filedetail-section-title">{lang === 'ru' ? `Все совпадения детекта (${matches.length})` : `All detection matches (${matches.length})`}</h4>
              <div className="filedetail-tags">
                {matches.map((m, i) => (
                  <span key={i} className="filedetail-tag">{m}</span>
                ))}
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  )
}
