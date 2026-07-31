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

const modeIcons: Record<ScanMode, string> = {
  full: '🛡️',
  quick: '⚡',
  dma: '🔌',
  cleaner: '🧹',
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
        style={{
          position: 'fixed',
          bottom: 24,
          right: 24,
          width: 400,
          maxHeight: 300,
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-color)',
          borderRadius: 16,
          padding: 20,
          zIndex: 200,
          boxShadow: `0 20px 60px rgba(0,0,0,0.5), 0 0 0 1px ${accent}15`,
          overflow: 'hidden',
          display: 'flex',
          flexDirection: 'column',
          gap: 12,
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 18 }}>{modeIcons[mode] || '🔍'}</span>
            <div>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{modeLabel}</div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                {progress?.phase === 'scanning' ? t('scanning') :
                 progress?.phase === 'analyzing' ? t('analyzing') :
                 progress?.phase === 'done' ? t('done') : t('preparing')}
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 4 }}>
            <motion.button
              className="compact-btn"
              onClick={onExpand}
              title={t('expand')}
              style={{ padding: '4px 8px', fontSize: 12 }}
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
              style={{ padding: '4px 8px', fontSize: 12 }}
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
        <div style={{ position: 'relative', height: 6, borderRadius: 3, background: 'var(--bg-raised)', overflow: 'hidden' }}>
          <motion.div
            style={{
              height: '100%',
              borderRadius: 3,
              background: `linear-gradient(90deg, ${accent}, ${light})`,
            }}
            animate={{ width: `${pct}%` }}
            transition={{ duration: 0.3, ease: 'easeOut' }}
          />
          {/* Shimmer */}
          <motion.div
            style={{
              position: 'absolute', top: 0, left: 0, height: '100%', width: '30%',
              background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent)',
            }}
            animate={{ x: ['-100%', '400%'] }}
            transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
          />
        </div>

        {/* Stats row */}
        <div style={{ display: 'flex', gap: 16, fontSize: 11 }}>
          <div>
            <span style={{ color: 'var(--text-secondary)' }}>{t('progress')}</span>
            <span style={{ marginLeft: 6, color: 'var(--text-primary)', fontWeight: 600 }}>{pct}%</span>
          </div>
          <div>
            <span style={{ color: 'var(--text-secondary)' }}>{t('time')}</span>
            <span style={{ marginLeft: 6, color: 'var(--text-primary)', fontWeight: 600 }}>
              {Math.floor(elapsed / 60)}:{(elapsed % 60).toString().padStart(2, '0')}
            </span>
          </div>
          {progress && (
            <div>
              <span style={{ color: 'var(--text-secondary)' }}>{t('files')}</span>
              <span style={{ marginLeft: 6, color: 'var(--text-primary)', fontWeight: 600 }}>{progress.filesFound}</span>
            </div>
          )}
        </div>

        {/* Current directory */}
        {progress?.currentDir && (
          <div
            style={{
              fontSize: 11,
              color: 'var(--text-secondary)',
              fontFamily: '"Cascadia Code", "Fira Code", monospace',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              padding: '6px 10px',
              background: 'var(--bg-raised)',
              borderRadius: 6,
              flexShrink: 0,
            }}
          >
            {progress.currentDir}
          </div>
        )}

        {/* Spinner */}
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', flex: 1, minHeight: 40 }}>
          <SpinnerRing size={28} color={accent} />
        </div>
      </motion.div>
    </AnimatePresence>
  )
})
