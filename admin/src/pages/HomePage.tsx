import { memo } from 'react'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import {
  Shield, Search, Activity, Key, Users, Zap, ShieldCheck,
  Cpu, HardDrive, Globe, ArrowRight, Terminal,
} from 'lucide-react'
import { springEase, smoothEase } from '../constants'

const containerVariants = {
  hidden: {},
  show: { transition: { staggerChildren: 0.08 } },
}

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0, transition: { duration: 0.45, ease: smoothEase } },
}

const FEATURES = [
  {
    icon: Search, color: '#ff4444',
    title: '7-слойный детектор',
    desc: 'Файлы, процессы, реестр, сеть, память, DMA-устройства, браузер — полный анализ системы.',
  },
  {
    icon: Shield, color: '#3B82F6',
    title: 'Forensiс-анализ',
    desc: 'USN Journal, ShellBags, Prefetch, Event Logs — детект чистки ПК перед проверкой.',
  },
  {
    icon: Cpu, color: '#a855f7',
    title: 'DMA-детект',
    desc: 'FPGA-карты, PCILeech, FTDI-чипы — обнаружение аппаратных читов.',
  },
  {
    icon: Globe, color: '#22c55e',
    title: 'GTA 5 RP проекты',
    desc: 'FiveM, RAGE:MP, ALT:V — специализированные сигнатуры для RP-серверов.',
  },
  {
    icon: Terminal, color: '#f59e0b',
    title: 'API-хешинг + YARA',
    desc: 'Обнаружение обфускации вызовов API и YARA-правила для известных читов.',
  },
  {
    icon: Zap, color: '#ec4899',
    title: 'Anti-Forensic детект',
    desc: 'Timestomping, SDelete, очистка логов — обнаружение попыток скрыть следы.',
  },
]

const STATS = [
  { icon: Users, value: 'GTA 5 RP', label: 'Проекты: FiveM, RAGE:MP, ALT:V' },
  { icon: HardDrive, value: '7+', label: 'Режимов сканирования' },
  { icon: Activity, value: '90+', label: 'Известных читов в базе' },
  { icon: ShieldCheck, value: '0', label: 'Ложных срабатываний (hash-based)' },
]

export default memo(function HomePage() {
  const navigate = useNavigate()

  return (
    <div>
      {/* ── Hero ── */}
      <motion.div
        style={{
          textAlign: 'center',
          padding: '48px 24px 40px',
          position: 'relative',
        }}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.6 }}
      >
        {/* Ambient glow */}
        <div style={{
          position: 'absolute',
          top: '50%', left: '50%',
          transform: 'translate(-50%, -50%)',
          width: 500, height: 500,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(255,68,68,0.08) 0%, transparent 70%)',
          pointerEvents: 'none',
        }} />

        <motion.div
          style={{ marginBottom: 16, display: 'flex', justifyContent: 'center' }}
          initial={{ scale: 0, rotate: -15 }}
          animate={{ scale: 1, rotate: 0 }}
          transition={{ duration: 0.6, ease: springEase, delay: 0.1 }}
        >
          <div style={{
            width: 72, height: 72,
            borderRadius: 16,
            background: 'linear-gradient(135deg, rgba(255,68,68,0.15), rgba(255,107,53,0.1))',
            border: '1px solid rgba(255,68,68,0.2)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 40px rgba(255,68,68,0.15)',
          }}>
            <Shield size={36} color="#ff4444" />
          </div>
        </motion.div>

        <motion.h1
          style={{
            fontFamily: 'var(--font-display)',
            fontSize: 'clamp(28px, 5vw, 42px)',
            fontWeight: 900,
            letterSpacing: '-0.03em',
            background: 'linear-gradient(135deg, #ff4444 0%, #ff6b35 50%, #ff4444 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            marginBottom: 12,
          }}
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.25 }}
        >
          Predator Admin
        </motion.h1>

        <motion.p
          style={{
            fontSize: 15,
            color: 'var(--text-secondary)',
            maxWidth: 520,
            margin: '0 auto 24px',
            lineHeight: 1.6,
          }}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.35 }}
        >
          Панель управления античит-сканером Predator.
          Управляйте токенами доступа, обрабатывайте запросы пользователей,
          просматривайте результаты сканирований и пополняйте базу сигнатур читов.
        </motion.p>

        <motion.div
          style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.45 }}
        >
          <button
            className="btn btn-primary"
            onClick={() => navigate('/dashboard')}
            style={{ padding: '12px 28px', fontSize: 15, gap: 10 }}
          >
            Панель управления
            <ArrowRight size={18} />
          </button>
          <button
            className="btn btn-outline"
            onClick={() => navigate('/tokens')}
            style={{ padding: '12px 28px', fontSize: 15, gap: 10 }}
          >
            <Key size={18} />
            Токены
          </button>
        </motion.div>
      </motion.div>

      {/* ── Stats row ── */}
      <motion.div
        className="stats-grid"
        style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', marginBottom: 40 }}
        variants={containerVariants}
        initial="hidden"
        animate="show"
      >
        {STATS.map((stat) => {
          const Icon = stat.icon
          return (
            <motion.div
              key={stat.label}
              className="stat-card"
              variants={itemVariants}
              whileHover={{ scale: 1.02, y: -2, transition: { duration: 0.2 } }}
              style={{ textAlign: 'center', padding: '24px 16px' }}
            >
              <Icon size={28} style={{ color: 'var(--accent)', marginBottom: 12, opacity: 0.8 }} />
              <div style={{
                fontFamily: 'var(--font-display)',
                fontSize: 28,
                fontWeight: 800,
                color: 'var(--text-primary)',
                marginBottom: 4,
              }}>
                {stat.value}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{stat.label}</div>
            </motion.div>
          )
        })}
      </motion.div>

      {/* ── Features grid ── */}
      <motion.div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: 16,
          marginBottom: 32,
        }}
        variants={containerVariants}
        initial="hidden"
        animate="show"
      >
        {FEATURES.map((feat) => {
          const Icon = feat.icon
          return (
            <motion.div
              key={feat.title}
              className="stat-card"
              variants={itemVariants}
              whileHover={{ scale: 1.02, y: -3, transition: { duration: 0.2 } }}
              style={{ padding: 24, cursor: 'default' }}
            >
              <div style={{
                width: 44, height: 44, borderRadius: 12,
                background: `${feat.color}18`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                marginBottom: 16,
              }}>
                <Icon size={22} color={feat.color} />
              </div>
              <h3 style={{
                fontSize: 16, fontWeight: 700, marginBottom: 6,
                color: 'var(--text-primary)',
              }}>
                {feat.title}
              </h3>
              <p style={{
                fontSize: 13, color: 'var(--text-secondary)',
                lineHeight: 1.5,
              }}>
                {feat.desc}
              </p>
            </motion.div>
          )
        })}
      </motion.div>

      {/* ── Bottom CTA ── */}
      <motion.div
        className="table-container"
        style={{
          textAlign: 'center',
          padding: '40px 24px',
          background: 'linear-gradient(135deg, rgba(255,68,68,0.05), rgba(255,107,53,0.03))',
          borderColor: 'rgba(255,68,68,0.15)',
        }}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.5 }}
      >
        <Activity size={32} style={{ color: 'var(--accent)', marginBottom: 16, opacity: 0.7 }} />
        <h2 style={{
          fontSize: 20, fontWeight: 700, marginBottom: 8,
          color: 'var(--text-primary)',
        }}>
          Готовы к работе?
        </h2>
        <p style={{
          fontSize: 14, color: 'var(--text-secondary)', marginBottom: 20, maxWidth: 400,
          margin: '0 auto 20px', lineHeight: 1.5,
        }}>
          Управляйте токенами, обрабатывайте запросы и следите за безопасностью серверов в реальном времени.
        </p>
        <div style={{ display: 'flex', gap: 10, justifyContent: 'center', flexWrap: 'wrap' }}>
          <button className="btn btn-primary" onClick={() => navigate('/pending')}>
            Запросы на доступ
          </button>
          <button className="btn btn-outline" onClick={() => navigate('/hashes')}>
            База сигнатур
          </button>
        </div>
      </motion.div>
    </div>
  )
})
