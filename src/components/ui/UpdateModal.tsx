import React from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { motion, useReducedMotion } from 'framer-motion'
import { ThemeId, THEMES, Lang, T } from '../../types'

interface UpdateModalProps {
  state: { show: boolean; version: string; state: 'available' | 'downloading' | 'done' | 'error'; percent: number; speed: string; size: string; errorMsg: string }
  theme: ThemeId
  lang: Lang
  onClose: () => void
  onDownload: () => void
  onRestart: () => void
}

const UpdateModal: React.FC<UpdateModalProps> = ({ state: modal, theme, lang, onClose, onDownload, onRestart }) => {
  if (!modal.show) return null
  const t = (key: string) => T[lang][key] || key
  const c = THEMES[theme]
  const reducedMotion = useReducedMotion()

  const transition = reducedMotion
    ? { duration: 0 }
    : { type: 'spring' as const, stiffness: 300, damping: 25 }

  return (
    <Dialog.Root open={modal.show} onOpenChange={(open) => { if (!open) onClose() }}>
      <Dialog.Portal>
        <Dialog.Overlay asChild>
          <motion.div
            className="update-modal-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={transition}
          />
        </Dialog.Overlay>
        <Dialog.Content asChild>
          <motion.div
            className="update-modal"
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={transition}
          >
            {/* Available */}
            {modal.state === 'available' && (
              <>
                <div className="update-modal-icon">
                  <svg width="40" height="40" viewBox="0 0 48 48" fill="none">
                    <circle cx="24" cy="24" r="22" stroke={c.light} strokeWidth="2" />
                    <path d="M24 14V34M14 24H34" stroke={c.light} strokeWidth="3" strokeLinecap="round" />
                  </svg>
                </div>
                <p className="update-modal-title">{t('updateAvailable')}</p>
                <p className="update-modal-version">{modal.version}</p>
                <div className="update-modal-actions">
                  <button className="update-modal-btn secondary" onClick={onClose}>{t('close')}</button>
                  <button className="update-modal-btn primary" onClick={onDownload}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                    </svg>
                    {t('download')}
                  </button>
                </div>
              </>
            )}

            {/* Downloading */}
            {modal.state === 'downloading' && (
              <>
                <div className="update-modal-icon">
                  <div className="spinner" style={{ width: 36, height: 36 }}>
                    <div className="spinner-ring" style={{ borderWidth: 2 }} />
                  </div>
                </div>
                <p className="update-modal-title">{t('downloading')}</p>
                <div className="update-modal-actions" style={{ flexDirection: 'column', gap: 8 }}>
                  <div className="progress-bar">
                    <div className="progress-fill" style={{ width: `${modal.percent}%` }} />
                  </div>
                  <div className="progress-info">
                    <span>{modal.speed}</span>
                    <span>{modal.percent}%</span>
                  </div>
                  <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)' }}>{modal.size}</span>
                </div>
              </>
            )}

            {/* Done */}
            {modal.state === 'done' && (
              <>
                <div className="update-modal-icon">
                  <svg width="40" height="40" viewBox="0 0 48 48" fill="none">
                    <circle cx="24" cy="24" r="22" stroke="#22c55e" strokeWidth="2" />
                    <path d="M16 24L22 30L32 18" stroke="#22c55e" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </div>
                <p className="update-modal-title">{t('downloaded')}</p>
                <p className="update-modal-version">{modal.version}</p>
                <div className="update-modal-actions">
                  <button className="update-modal-btn secondary" onClick={onClose}>{t('close')}</button>
                  <button className="update-modal-btn primary restart" onClick={onRestart}>{t('installRestart')}</button>
                </div>
              </>
            )}

            {/* Error */}
            {modal.state === 'error' && (
              <>
                <div className="update-modal-icon error">
                  <svg width="40" height="40" viewBox="0 0 48 48" fill="none">
                    <circle cx="24" cy="24" r="22" stroke="#EF4444" strokeWidth="2" />
                    <line x1="16" y1="16" x2="32" y2="32" stroke="#EF4444" strokeWidth="3" strokeLinecap="round" />
                    <line x1="32" y1="16" x2="16" y2="32" stroke="#EF4444" strokeWidth="3" strokeLinecap="round" />
                  </svg>
                </div>
                <p className="update-modal-title" style={{ color: '#EF4444' }}>{t('updateAvailable')}</p>
                <p className="update-modal-version" style={{ color: 'rgba(255,68,68,0.6)' }}>{modal.errorMsg}</p>
                <div className="update-modal-actions">
                  <button className="update-modal-btn secondary" onClick={onClose}>{t('close')}</button>
                  <button className="update-modal-btn primary" onClick={onDownload}>{t('download')}</button>
                </div>
              </>
            )}
          </motion.div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}

export default UpdateModal
