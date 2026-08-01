/**
 * Predator — Compact Scan Overlay
 * Mini floating window (400x300) showing scan progress.
 * Can be toggled from full Checker mode.
 */
import React, { memo, useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import type { ScanProgress, ScanMode } from '../../types/electron'
import { SpinnerRing } from './AnimatedIcons'

interface CompactScanOverlayProps {
  open: boolean
  onClose: () => void
  onExpand: () => void
  progress: ScanProgress | null
  mode: ScanMode
  modeLabel: string
  accent: string
  light: string
  lang: 'ru' | 'en'
}

const modeIcons: Record<ScanMode, React.ReactNode> = {
  full: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2l8 3v6c0 5-3.5 9.5-8 11-4.5-1.5-8-6-8-11V5l8-3z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  ),
  quick: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  ),
  dma: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="9" y="2" width="6" height="8" rx="1" />
      <path d="M7 10h10v3a5 5 0 0 1-10 0v-3z" />
      <path d="M12 18v4" />
    </svg>
  ),
  cleaner: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 3l7 7-8 3-2-2 3-8z" />
      <path d="M4 20l3-3" />
      <path d="M8 16l3 3" />
    </svg>
  ),
}

const COMPACT_LANG: Record<string, Record<string, string>> = {
  ru: {
    scanning: 'Сканирование...',
    analyzing: 'Анализ...',
    done: 'Завершено',
    preparing: 'Подготовка...',
    progress: 'Прогресс',
    time: 'Время',
    files: 'Файлов',
    expand: 'Развернуть',
    compact: 'Компактно',
    close: 'Закрыть',
  },
  en: {
    scanning: 'Scanning...',
    analyzing: 'Analyzing...',
    done: 'Done',
    preparing: 'Preparing...',
    progress: 'Progress',
    time: 'Time',
    files: 'Files',
    expand: 'Expand',
    compact: 'Compact',
    close: 'Close',
  },
}

export const CompactScanOverlay: React.FC<CompactScanOverlayProps> = memo(function CompactScanOverlay({
  open, onClose, onExpand, progress, mode, modeLabel, accent, light, lang,
}) {
  const [elapsed, setElapsed] = useState(0)
  const startRef = useRef(Date.now())

  useEffect(() => {
    if (open) {
      startRef.current = Date.now()
      setElapsed(0)
      const t = setInterval(() => setElapsed(Date.now() - startRef.current), 1000)
      return () => clearInterval(t)
    }
  }, [open])

  const pct = progress
    ? progress.phase === 'done'
      ? 100
      : progress.totalDirs > 0
        ? Math.round((progress.dirsDone / progress.totalDirs) * 100)
        : progress.filesScanned > 300
          ? 90
          : Math.round((progress.filesScanned / 300) * 80)
    : 0

  const t = (key: string) => COMPACT_LANG[lang]?.[key] || key

  if (!open) return null

  return (
    <AnimatePresence>
      <motion.div
        className="compact-overlay"
        initial={{ opacity: 0, scale: 0.9, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.9, y: 20 }}
        transition={{ type: 'spring', stiffness: 400, damping: 30 }}
      >
        {/* Header */}
        <div className="compact-header">
          <div className="compact-header-left">
            <span className="compact-mode-icon" style={{ color: accent }}>
              {modeIcons[mode]}
            </span>
            <div className="compact-title-block">
              <div className="compact-title">{modeLabel}</div>
              <div className="compact-subtitle">
                {progress?.phase === 'scanning' ? t('scanning') :
                 progress?.phase === 'analyzing' ? t('analyzing') :
                 progress?.phase === 'done' ? t('done') : t('preparing')}
              </div>
            </div>
          </div>
          <div className="compact-btn-group">
            <motion.button
              className="compact-btn"
              onClick={onExpand}
              title={t('expand')}
              whileHover={{ scale: 1.1 }}
              whileTap={{ scale: 0.9 }}
              transition={{ type: 'spring', stiffness: 400, damping: 25 }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="15 3 21 3 21 9" /><polyline points="9 21 3 21 3 15" />
                <line x1="21" y1="3" x2="14" y2="10" /><line x1="3" y1="21" x2="10" y2="14" />
              </svg>
            </motion.button>
            <motion.button
              className="compact-btn"
              onClick={onClose}
              title={t('close')}
              whileHover={{ scale: 1.1 }}
              whileTap={{ scale: 0.9 }}
              transition={{ type: 'spring', stiffness: 400, damping: 25 }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </motion.button>
          </div>
        </div>

        {/* Progress bar */}
        <div className="compact-progress-track">
          <motion.div
            className="compact-progress-fill"
            style={{ background: `linear-gradient(90deg, ${accent}, ${light})` }}
            animate={{ width: `${pct}%` }}
            transition={{ duration: 0.3, ease: 'easeOut' }}
          />
          {/* Shimmer */}
          <motion.div
            className="compact-shimmer"
            animate={{ x: ['-100%', '400%'] }}
            transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
          />
        </div>

        {/* Stats row */}
        <div className="compact-stats">
          <div>
            <span className="compact-stat-label">{t('progress')}</span>
            <span className="compact-stat-value">{pct}%</span>
          </div>
          <div>
            <span className="compact-stat-label">{t('time')}</span>
            <span className="compact-stat-value">
              {Math.floor(elapsed / 60)}:{(elapsed % 60).toString().padStart(2, '0')}
            </span>
          </div>
          {progress && (
            <div>
              <span className="compact-stat-label">{t('files')}</span>
              <span className="compact-stat-value">{progress.filesFound}</span>
            </div>
          )}
        </div>

        {/* Current directory */}
        {progress?.currentDir && (
          <div className="compact-dir">
            {progress.currentDir}
          </div>
        )}

        {/* Spinner */}
        <div className="compact-spinner">
          <SpinnerRing size={28} color={accent} />
        </div>
      </motion.div>
    </AnimatePresence>
  )
})
