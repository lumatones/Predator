import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import type { ThemeId, Lang } from '../../types'
import { THEMES } from '../../types'

interface SettingsPanelProps {
  open: boolean
  onClose: () => void
  currentTheme: ThemeId
  currentLang: Lang
  onThemeChange: (id: ThemeId) => void
  onLangChange: (l: Lang) => void
  lang: Lang
}

const LABELS: Record<Lang, Record<string, string>> = {
  ru: {
    title: 'Настройки',
    themeLabel: 'Тема оформления',
    langLabel: 'Язык интерфейса',
    close: 'Закрыть',
  },
  en: {
    title: 'Settings',
    themeLabel: 'Theme',
    langLabel: 'Interface language',
    close: 'Close',
  },
}

export const SettingsPanel: React.FC<SettingsPanelProps> = ({
  open, onClose, currentTheme, currentLang, onThemeChange, onLangChange, lang,
}) => {
  const t = LABELS[lang]

  return (
    <AnimatePresence>
      {open && (
        <>
          {/* Backdrop */}
          <motion.div
            className="settings-backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            onClick={onClose}
          />

          {/* Panel */}
          <motion.div
            className="settings-panel"
            initial={{ opacity: 0, x: 40, scale: 0.97 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 40, scale: 0.97 }}
            transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
          >
            <div className="settings-header">
              <h3 className="settings-title">{t.title}</h3>
              <motion.button className="settings-close-btn" onClick={onClose} aria-label={t.close} whileHover={{ scale: 1.1, rotate: 90 }} whileTap={{ scale: 0.9 }} transition={{ type: 'spring', stiffness: 400, damping: 25 }}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </motion.button>
            </div>

            <div className="settings-section">
              <p className="settings-section-label">{t.langLabel}</p>
              <div className="settings-lang-grid">
                <motion.button
                  className={`settings-lang-btn${currentLang === 'ru' ? ' active' : ''}`}
                  onClick={() => onLangChange('ru')}
                  whileHover={{ scale: 1.03, y: -2 }}
                  whileTap={{ scale: 0.97 }}
                >
                  <span className="settings-lang-flag">🇷🇺</span>
                  <span className="settings-lang-name">Русский</span>
                </motion.button>
                <motion.button
                  className={`settings-lang-btn${currentLang === 'en' ? ' active' : ''}`}
                  onClick={() => onLangChange('en')}
                  whileHover={{ scale: 1.03, y: -2 }}
                  whileTap={{ scale: 0.97 }}
                >
                  <span className="settings-lang-flag">🇬🇧</span>
                  <span className="settings-lang-name">English</span>
                </motion.button>
              </div>
            </div>

            <div className="settings-section">
              <p className="settings-section-label">{t.themeLabel}</p>
              <div className="settings-theme-grid">
                {(Object.entries(THEMES) as [ThemeId, typeof THEMES['predator']][]).map(([id, th]) => (
                  <motion.button
                    key={id}
                    className={`settings-theme-card${currentTheme === id ? ' active' : ''}`}
                    style={{
                      '--th-accent': th.accent,
                      '--th-light': th.light,
                      '--th-dark': th.dark,
                    } as React.CSSProperties}
                    onClick={() => onThemeChange(id)}
                    whileHover={{ scale: 1.03, y: -2 }}
                    whileTap={{ scale: 0.97 }}
                  >
                    <div className="settings-theme-swatch" style={{ background: th.accent }} />
                    <span className="settings-theme-name">{th.name}</span>
                    {currentTheme === id && (
                      <motion.div
                        className="settings-theme-check"
                        layoutId="settings-theme-check"
                        initial={{ scale: 0 }}
                        animate={{ scale: 1 }}
                        transition={{ type: 'spring', stiffness: 400, damping: 25 }}
                      >
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3">
                          <polyline points="20 6 9 17 4 12" />
                        </svg>
                      </motion.div>
                    )}
                    <div className="settings-theme-colors">
                      <span style={{ background: th.accent, width: 10, height: 10, borderRadius: '50%' }} />
                      <span style={{ background: th.light, width: 10, height: 10, borderRadius: '50%' }} />
                      <span style={{ background: th.dark, width: 10, height: 10, borderRadius: '50%' }} />
                    </div>
                  </motion.button>
                ))}
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  )
}
