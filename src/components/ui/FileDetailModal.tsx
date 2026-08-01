import React, { useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { buildFindingExplanation, TYPE_LABELS } from '../../utils/finding-explainer'
import type { Lang } from '../../types'
import type { EvidenceRecord, ScanResult } from '../../types/electron'

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
  evidence?: EvidenceRecord[]
  riskScore?: number
  riskExplanation?: string
  lang?: Lang
  returnFocusRef?: React.RefObject<HTMLElement | null>
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export const FileDetailModal: React.FC<FileDetailModalProps> = ({
  open, onClose, fileName, filePath, fileType, risk, matches, size, sha256,
  evidence, riskScore, riskExplanation, lang = 'ru', returnFocusRef,
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
    evidence,
    riskScore,
    riskExplanation,
  }), [fileName, filePath, fileType, risk, matches, size, sha256, evidence, riskScore, riskExplanation])

  const summary = useMemo(
    () => buildFindingExplanation(finding, lang),
    [finding, lang],
  )

  const closeButtonRef = useRef<HTMLButtonElement>(null)
  const modalRef = useRef<HTMLDivElement>(null)
  const wasOpenRef = useRef(false)
  const [copied, setCopied] = useState(false)

  const onCloseRef = useRef(onClose)

  useEffect(() => {
    onCloseRef.current = onClose
  }, [onClose])

  useEffect(() => {
    if (!open) {
      if (wasOpenRef.current) returnFocusRef?.current?.focus()
      wasOpenRef.current = false
      return
    }

    wasOpenRef.current = true
    const appRoot = document.getElementById('root')
    appRoot?.setAttribute('inert', '')
    closeButtonRef.current?.focus()
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onCloseRef.current()
        return
      }

      if (event.key !== 'Tab') return
      const modal = modalRef.current
      if (!modal) return

      const focusable = Array.from(modal.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ))
      if (focusable.length === 0) return

      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      const active = document.activeElement

      if (event.shiftKey && (active === first || !modal.contains(active))) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && (active === last || !modal.contains(active))) {
        event.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      appRoot?.removeAttribute('inert')
    }
  }, [open, returnFocusRef])

  const riskColor = risk === 'critical' ? 'var(--accent-red)' : risk === 'high' ? 'var(--accent-orange)' : risk === 'medium' ? 'var(--color-warning)' : '#6B7280'
  const typeLabel = TYPE_LABELS[lang][fileType] || fileType
  const riskLabel = lang === 'ru'
    ? risk === 'critical' ? 'Критический' : risk === 'high' ? 'Высокий' : risk === 'medium' ? 'Средний' : 'Низкий'
    : risk === 'critical' ? 'Critical' : risk === 'high' ? 'High' : risk === 'medium' ? 'Medium' : 'Low'

  return createPortal(
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
          <div className="filedetail-layer">
            <motion.div
              ref={modalRef}
              className="filedetail-modal"
              data-testid="file-detail-modal"
              role="dialog"
              aria-modal="true"
              aria-labelledby="filedetail-title"
              aria-describedby="filedetail-description"
              initial={{ opacity: 0, scale: 0.96, y: 12 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.96, y: 12 }}
              transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
            >
            <div className="filedetail-header">
              <div className="filedetail-header-left">
                <span className="filedetail-risk-dot" style={{ background: riskColor, color: riskColor }} />
                <div>
                  <h3 id="filedetail-title" className="filedetail-filename">{fileName}</h3>
                  <span className="filedetail-path">{filePath}</span>
                </div>
              </div>
              <motion.button ref={closeButtonRef} className="filedetail-close" onClick={onClose} aria-label={lang === 'ru' ? 'Закрыть' : 'Close'} whileHover={{ scale: 1.1, rotate: 90 }} whileTap={{ scale: 0.9 }} transition={{ type: 'spring', stiffness: 400, damping: 25 }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </motion.button>
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
                  <div className="filedetail-hash-row">
                    <span className="filedetail-stat-value filedetail-hash">{sha256}</span>
                    <button
                      type="button"
                      className={`filedetail-copy-btn${copied ? ' copied' : ''}`}
                      aria-label={lang === 'ru' ? 'Скопировать хеш' : 'Copy hash'}
                      onClick={() => {
                        navigator.clipboard.writeText(sha256).catch(() => {})
                        setCopied(true)
                        window.setTimeout(() => setCopied(false), 1600)
                      }}
                    >
                      {copied ? (
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                          <polyline points="20 6 9 17 4 12" />
                        </svg>
                      ) : (
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <rect x="9" y="9" width="13" height="13" rx="2" />
                          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                        </svg>
                      )}
                    </button>
                  </div>
                </div>
              )}
            </div>

            <div className={`filedetail-verdict ${risk}`}>
              <div className="filedetail-verdict-kicker">{lang === 'ru' ? 'Объяснение находки' : 'Finding explanation'}</div>
              <h4 className="filedetail-verdict-title">{summary.title}</h4>
              <p id="filedetail-description">{summary.description}</p>
              <p><strong>{lang === 'ru' ? 'Почему это важно:' : 'Why it matters:'}</strong> {summary.whyDangerous}</p>
              <p><strong>{lang === 'ru' ? 'Что делать:' : 'Recommended action:'}</strong> {summary.recommendation}</p>
              <p className="filedetail-confidence-note">{summary.confidenceNote}</p>
            </div>

            <div className="filedetail-section">
              <h4 className="filedetail-section-title section-title">{lang === 'ru' ? 'Ключевые индикаторы' : 'Key indicators'}</h4>
              <ul className="filedetail-indicators">
                {summary.indicators.map((indicator, i) => (
                  <li key={i}>{indicator}</li>
                ))}
              </ul>
            </div>

            <div className="filedetail-section">
              <h4 className="filedetail-section-title section-title">{lang === 'ru' ? 'Доказательная база' : 'Evidence summary'}</h4>
              {(riskScore !== undefined || riskExplanation) && (
                <div className="filedetail-evidence-summary">
                  {riskScore !== undefined && (
                    <span>{lang === 'ru' ? 'Вклад риска' : 'Risk contribution'}: <strong>{riskScore}/100</strong></span>
                  )}
                  {riskExplanation && <span>{riskExplanation}</span>}
                </div>
              )}
              {evidence && evidence.length > 0 ? (
                <div className="filedetail-evidence-list">
                  {evidence.map(item => (
                    <div key={item.id} className="filedetail-evidence-item">
                      <div className="filedetail-evidence-head">
                        <strong>{item.category}</strong>
                        <span>{item.confidence}% · {(item.weight * 100).toFixed(0)}%</span>
                      </div>
                      <span>{item.explanation}</span>
                      <code>{item.raw}</code>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="filedetail-confidence-note">
                  {lang === 'ru' ? 'Структурированные доказательства для старого результата отсутствуют.' : 'Structured evidence is unavailable for this legacy result.'}
                </p>
              )}
            </div>

            <div className="filedetail-section">
              <h4 className="filedetail-section-title section-title">{lang === 'ru' ? `Все совпадения детекта (${matches.length})` : `All detection matches (${matches.length})`}</h4>
              {matches.length > 0 ? (
                <div className="filedetail-tags">
                  {matches.map((m, i) => (
                    <span key={i} className="filedetail-tag">{m}</span>
                  ))}
                </div>
              ) : (
                <p className="filedetail-matches-empty">
                  {lang === 'ru' ? 'Совпадений детекта не зафиксировано.' : 'No detection matches were recorded.'}
                </p>
              )}
            </div>
          </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>,
    document.body,
  )
}
