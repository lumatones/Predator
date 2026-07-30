import React from 'react'
import { motion } from 'framer-motion'
import { Button } from '../ui/Button'

interface WelcomeStepProps {
  welcomeTitle: string
  welcomeDesc: string
  welcomeStart: string
  accent: string
  light: string
  lang: 'ru' | 'en'
  onNext: () => void
}

const featuresRu = [
  { icon: '🛡️', label: 'Многослойный анализ', desc: 'Процессы, файлы, реестр, DMA, сеть' },
  { icon: '🧬', label: 'Эвристика + YARA', desc: '13+ YARA-правил, PE-анализ, энтропия' },
  { icon: '☁️', label: 'Облачная база', desc: 'SHA256 + TLSH синхронизация угроз' },
]

const featuresEn = [
  { icon: '🛡️', label: 'Multi-layer Analysis', desc: 'Processes, files, registry, DMA, network' },
  { icon: '🧬', label: 'Heuristics + YARA', desc: '13+ YARA rules, PE analysis, entropy' },
  { icon: '☁️', label: 'Cloud Database', desc: 'SHA256 + TLSH threat sync' },
]

export const WelcomeStep: React.FC<WelcomeStepProps> = ({
  welcomeTitle, welcomeDesc, welcomeStart,
  accent, lang, onNext,
}) => {
  const featList = lang === 'ru' ? featuresRu : featuresEn

  return (
    <div className="ob-welcome">
      <motion.div
        className="ob-welcome-glow"
        animate={{
          scale: [1, 1.08, 1],
          opacity: [0.3, 0.5, 0.3],
        }}
        transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
        style={{
          background: `radial-gradient(circle, ${accent}20 0%, transparent 70%)`,
        }}
      />
      <motion.h2
        className="ob-welcome-title"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.1 }}
      >
        {welcomeTitle}
      </motion.h2>
      <motion.p
        className="ob-welcome-desc"
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.25 }}
      >
        {welcomeDesc}
      </motion.p>
      <motion.div
        className="ob-welcome-features"
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.4 }}
      >
        {featList.map((f, i) => (
          <motion.div
            key={f.label}
            className="ob-feature-card"
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 + i * 0.1, duration: 0.35 }}
            whileHover={{ y: -2, borderColor: accent + '40' }}
          >
            <span className="ob-feature-icon">{f.icon}</span>
            <span className="ob-feature-label">{f.label}</span>
            <span className="ob-feature-desc">{f.desc}</span>
          </motion.div>
        ))}
      </motion.div>
      <motion.div
        className="onb-step-actions"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.8, duration: 0.4 }}
      >
        <Button className="start-button ob-welcome-btn" onClick={onNext}>
          {welcomeStart}
        </Button>
      </motion.div>
    </div>
  )
}
