import { useEffect, useRef, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { Link } from 'react-router-dom'
import { ArrowRight, FileCheck2, Fingerprint, ScanSearch, ShieldCheck, Sparkles } from 'lucide-react'
import { fetchStats, type WebsiteStats } from '../api'

const SIGNALS = [
  { id: 'files', label: 'Файлы', detail: 'YARA / traces', description: 'Сигнатуры и следы очистки в файловой среде.', icon: FileCheck2, position: 'evidence-signal--files' },
  { id: 'memory', label: 'Память', detail: 'DMA / regions', description: 'Аппаратный контур, PCIe и подозрительные регионы.', icon: ScanSearch, position: 'evidence-signal--memory' },
  { id: 'behavior', label: 'Поведение', detail: 'process graph', description: 'Инъекции, дерево процессов и аномальные связи.', icon: Fingerprint, position: 'evidence-signal--behavior' },
] as const

const STEPS = [
  { number: '01', title: 'Собрать состояние', text: 'Клиент фиксирует систему игрока: файлы, память, процессы и устройства.' },
  { number: '02', title: 'Сопоставить сигналы', text: 'Каждый след сверяется с локальными правилами и проверенной базой.' },
  { number: '03', title: 'Показать основания', text: 'Администратор видит риск и источник сигнала, а не безымянный балл.' },
]

function StatValue({ value }: { value: number }) {
  const [ready, setReady] = useState(false)
  useEffect(() => {
    const timer = window.setTimeout(() => setReady(true), 240)
    return () => window.clearTimeout(timer)
  }, [])
  return <>{ready ? value.toLocaleString('ru-RU') : '—'}</>
}

function EvidenceOrb() {
  const [activeSignal, setActiveSignal] = useState<(typeof SIGNALS)[number]['id'] | null>(null)
  const suppressNextClick = useRef(false)
  const reduceMotion = useReducedMotion()
  const motionDisabled = reduceMotion !== false
  const active = SIGNALS.find(signal => signal.id === activeSignal)

  return (
    <div className="relative mx-auto h-[410px] w-full max-w-[520px] sm:h-[470px]" aria-label="Интерактивная карта источников доказательств">
      <div className="absolute inset-0 grid place-items-center">
        <motion.div className="evidence-orb" animate={motionDisabled ? undefined : { rotate: [0, 1, -1, 0], scale: [1, 1.035, 1] }} transition={{ duration: 9, repeat: Infinity, ease: 'easeInOut' }}>
          <div className="relative z-10 text-center">
            <motion.div animate={motionDisabled ? undefined : { scale: activeSignal ? 1.06 : 1 }} transition={motionDisabled ? undefined : { type: 'spring', stiffness: 280, damping: 18 }}>
              <ShieldCheck size={34} strokeWidth={1.4} className="mx-auto text-predator-accent" />
              <div className="mt-4 text-sm font-medium text-predator-text">Evidence core</div>
              <div className="data-mono mt-2 text-[10px] uppercase tracking-[0.14em] text-predator-muted">{active ? active.label : 'Система готова'}</div>
            </motion.div>
          </div>
        </motion.div>
      </div>

      {SIGNALS.map((signal, index) => {
        const Icon = signal.icon
        const isActive = activeSignal === signal.id
        const toggleSignal = () => setActiveSignal(current => current === signal.id ? null : signal.id)

        return (
          <motion.button
            key={signal.id}
            type="button"
            className={`evidence-signal ${signal.position}`}
            data-active={isActive}
            initial={motionDisabled ? false : { opacity: 0, scale: 0.8 }}
            animate={motionDisabled ? undefined : { opacity: 1, scale: 1, y: [0, index % 2 ? -5 : 4, 0] }}
            transition={motionDisabled ? undefined : { opacity: { delay: 0.25 + index * 0.12 }, scale: { delay: 0.25 + index * 0.12, type: 'spring' }, y: { delay: 1 + index * 0.3, duration: 5 + index, repeat: Infinity, ease: 'easeInOut' } }}
            onPointerDown={event => {
              if (event.pointerType === 'touch') {
                event.preventDefault()
                suppressNextClick.current = true
                toggleSignal()
              }
            }}
            onPointerUp={event => {
              if (event.pointerType === 'touch') {
                window.setTimeout(() => { suppressNextClick.current = false }, 0)
              }
            }}
            onPointerEnter={event => { if (event.pointerType === 'mouse') setActiveSignal(signal.id) }}
            onPointerLeave={event => {
              if (event.pointerType === 'mouse' && document.activeElement !== event.currentTarget) setActiveSignal(null)
            }}
            onFocus={() => setActiveSignal(signal.id)}
            onBlur={() => setActiveSignal(null)}
            onClick={() => {
              if (suppressNextClick.current) {
                suppressNextClick.current = false
                return
              }
              toggleSignal()
            }}
            aria-label={`${signal.label}: ${signal.description}`}
            aria-expanded={isActive}
            aria-controls="evidence-description-active"
          >
            <span className="evidence-signal-dot"><Icon size={14} strokeWidth={1.7} /></span>
            <span className="text-left"><span className="block font-medium">{signal.label}</span><span className="data-mono mt-0.5 block text-[9px] text-predator-muted">{signal.detail}</span></span>
          </motion.button>
        )
      })}

      <svg className="evidence-connectors" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
        {([
          ['desktop', [[24, 18], [76, 48], [34, 82]]],
          ['compact', [[18, 18], [82, 48], [22, 82]]],
          ['mobile', [[20, 15], [80, 48], [20, 85]]],
        ] as const).map(([layout, endpoints]) => (
          <g key={layout} className={`evidence-connectors-${layout}`}>
            {SIGNALS.map((signal, index) => {
              const [x2, y2] = endpoints[index]
              const isActive = activeSignal === signal.id
              return (
                <motion.line
                  key={`${layout}-${signal.id}`}
                  x1="50"
                  y1="50"
                  x2={x2}
                  y2={y2}
                  className={isActive ? 'evidence-connector evidence-connector--active' : 'evidence-connector'}
                  initial={motionDisabled ? false : { pathLength: 0, opacity: 0 }}
                  animate={motionDisabled ? { opacity: isActive ? 0.9 : 0.34 } : { pathLength: 1, opacity: isActive ? 0.9 : 0.34 }}
                  transition={motionDisabled ? undefined : { pathLength: { duration: 0.7, delay: 0.18 + index * 0.1 }, opacity: { duration: 0.22 } }}
                />
              )
            })}
          </g>
        ))}
      </svg>

      <motion.div id="evidence-description-active" initial={false} animate={motionDisabled ? { opacity: active ? 1 : 0 } : { opacity: active ? 1 : 0, y: active ? 0 : 8 }} className="absolute bottom-1 left-1/2 w-[min(88%,310px)] -translate-x-1/2 rounded-2xl border border-predator-accent/30 bg-[#151a21]/95 p-4 text-center shadow-2xl shadow-black/20 backdrop-blur-xl" aria-live="polite" aria-hidden={!active}>
        <p className="text-sm text-predator-text">{active?.description || 'Выберите источник, чтобы увидеть, что именно проверяет Predator.'}</p>
      </motion.div>
    </div>
  )
}

export default function Hero() {
  const [stats, setStats] = useState<WebsiteStats | null>(null)
  const [statsError, setStatsError] = useState(false)
  const reduceMotion = useReducedMotion()
  const motionDisabled = reduceMotion !== false

  useEffect(() => {
    fetchStats().then(setStats).catch(() => setStatsError(true))
  }, [])

  const statsList = statsError || !stats
    ? [
        { label: 'Профили проверены', value: '—' },
        { label: 'Серверы подключены', value: '—' },
        { label: 'Проверки завершены', value: '—' },
        { label: 'Сигналы риска', value: '—' },
      ]
    : [
        { label: 'Профили проверены', value: <StatValue value={stats.totalPlayers} /> },
        { label: 'Серверы подключены', value: <StatValue value={stats.totalServers} /> },
        { label: 'Проверки завершены', value: <StatValue value={stats.totalScans} /> },
        { label: 'Сигналы риска', value: <StatValue value={stats.flaggedPlayers} /> },
      ]

  return (
    <div className="overflow-hidden">
      <section className="mx-auto max-w-6xl px-4 pb-20 pt-32 sm:px-6 lg:px-8 lg:pt-40">
        <div className="grid items-center gap-8 lg:grid-cols-[0.82fr_1.18fr] lg:gap-4">
          <motion.div initial={{ opacity: 0, y: 22 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.7 }} className="relative z-10">
            <div className="mb-7 flex items-center gap-2 text-xs text-predator-accent"><Sparkles size={14} /><span>Verification, with context</span></div>
            <h1 className="display-face max-w-xl text-5xl font-semibold leading-[1.02] text-predator-text sm:text-7xl">Решение должно иметь <span className="text-predator-accent">основание.</span></h1>
            <p className="mt-7 max-w-lg text-base leading-7 text-predator-muted sm:text-lg">Predator связывает файлы, память и поведение процессов в один понятный результат — без догадок и без чёрного ящика.</p>
            <div className="mt-8 flex flex-col items-start gap-4 sm:flex-row sm:items-center">
              <Link to="/players" className="group inline-flex items-center gap-3 rounded-full bg-predator-accent px-5 py-3 text-sm font-semibold text-predator-bg transition-colors hover:bg-predator-text">Открыть реестр <ArrowRight size={16} className="transition-transform group-hover:translate-x-1" /></Link>
              <Link to="/news" className="inline-flex items-center gap-2 text-sm font-medium text-predator-muted transition-colors hover:text-predator-text">Как это работает <ArrowRight size={15} /></Link>
            </div>
          </motion.div>

          <motion.div initial={motionDisabled ? false : { opacity: 0, scale: 0.94 }} animate={{ opacity: 1, scale: 1 }} transition={motionDisabled ? undefined : { delay: 0.12, duration: 0.8 }}>
            <EvidenceOrb />
          </motion.div>
        </div>

        <div className="mt-8 grid grid-cols-2 gap-2 sm:grid-cols-4">
          {statsList.map(stat => (
            <div key={stat.label} className="rounded-2xl border border-white/[0.08] bg-white/[0.025] px-4 py-4">
              <div className="data-mono text-xl font-semibold text-predator-text">{stat.value}</div>
              <div className="mt-2 text-xs text-predator-muted">{stat.label}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-4 py-20 sm:px-6 lg:px-8">
        <div className="mb-10 max-w-xl"><p className="data-mono text-[10px] uppercase tracking-[0.14em] text-predator-muted">Three independent sources</p><h2 className="mt-4 text-3xl font-semibold tracking-[-0.05em] text-predator-text sm:text-4xl">Не один сигнал. Контекст.</h2><p className="mt-4 text-sm leading-6 text-predator-muted">Слабый индикатор сам по себе ничего не доказывает. Система собирает картину из нескольких независимых источников.</p></div>
        <div className="grid gap-4 md:grid-cols-3">
          {SIGNALS.map((signal, index) => { const Icon = signal.icon; return <motion.div key={signal.id} initial={{ opacity: 0, y: 14 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true, margin: '-60px' }} transition={{ delay: index * 0.1 }} className="evidence-panel-hover rounded-3xl p-6"><div className="flex items-center justify-between"><span className="evidence-signal-dot"><Icon size={16} /></span><span className="data-mono text-[10px] text-predator-muted">0{index + 1}</span></div><h3 className="mt-10 text-lg font-semibold tracking-tight text-predator-text">{signal.label}</h3><p className="mt-2 text-sm leading-6 text-predator-muted">{signal.description}</p></motion.div> })}
        </div>
      </section>

      <section className="border-y border-white/[0.08] bg-white/[0.015]">
        <div className="mx-auto max-w-6xl px-4 py-20 sm:px-6 lg:px-8"><div className="grid gap-14 lg:grid-cols-[0.72fr_1.28fr] lg:gap-24"><div><p className="data-mono text-[10px] uppercase tracking-[0.14em] text-predator-muted">The method</p><h2 className="mt-4 text-3xl font-semibold leading-tight tracking-[-0.05em] text-predator-text sm:text-4xl">Проверка как цепочка фактов.</h2></div><div>{STEPS.map(step => <div key={step.number} className="grid grid-cols-[48px_1fr] gap-5 border-b border-white/[0.09] py-6 first:border-t sm:grid-cols-[64px_1fr]"><span className="data-mono text-sm text-predator-accent">{step.number}</span><div><h3 className="text-lg font-semibold text-predator-text">{step.title}</h3><p className="mt-2 max-w-xl text-sm leading-6 text-predator-muted">{step.text}</p></div></div>)}</div></div></div>
      </section>

      <section className="mx-auto max-w-6xl px-4 py-20 sm:px-6 lg:px-8"><div className="evidence-sheet flex flex-col items-start justify-between gap-6 p-7 sm:p-9 lg:flex-row lg:items-center"><div><p className="data-mono text-[10px] uppercase tracking-[0.14em] text-predator-muted">For server operators</p><h2 className="mt-3 text-2xl font-semibold tracking-[-0.04em] text-predator-text">Посмотрите реальные результаты проверок.</h2></div><Link to="/login" className="inline-flex items-center gap-2 rounded-full border border-white/[0.14] px-5 py-3 text-sm font-semibold text-predator-text transition-colors hover:border-predator-accent hover:text-predator-accent">Создать доступ <ArrowRight size={15} /></Link></div></section>
    </div>
  )
}
