import { useState, useMemo } from 'react'
import { motion } from 'framer-motion'
import { Search, Shield, AlertTriangle, CheckCircle, Filter, ChevronDown } from 'lucide-react'

interface PlayerEntry {
  id: number
  username: string
  server: string
  lastScan: string
  risk: 'clean' | 'low' | 'medium' | 'high'
  scansCount: number
  cheatTraces: number
}

const MOCK_PLAYERS: PlayerEntry[] = [
  { id: 1, username: 'Player_X', server: 'Majestic RP', lastScan: '2026-07-30', risk: 'clean', scansCount: 12, cheatTraces: 0 },
  { id: 2, username: 'GhostRider99', server: 'Majestic RP', lastScan: '2026-07-29', risk: 'high', scansCount: 5, cheatTraces: 7 },
  { id: 3, username: 'NightWolf', server: 'CityLife RP', lastScan: '2026-07-28', risk: 'medium', scansCount: 8, cheatTraces: 3 },
  { id: 4, username: 'SpeedDemon', server: 'Majestic RP', lastScan: '2026-07-30', risk: 'clean', scansCount: 20, cheatTraces: 0 },
  { id: 5, username: 'ShadowBlade', server: 'AltLife RP', lastScan: '2026-07-27', risk: 'low', scansCount: 3, cheatTraces: 1 },
  { id: 6, username: 'ViperStrike', server: 'Majestic RP', lastScan: '2026-07-30', risk: 'clean', scansCount: 15, cheatTraces: 0 },
  { id: 7, username: 'IronFist', server: 'CityLife RP', lastScan: '2026-07-25', risk: 'high', scansCount: 2, cheatTraces: 12 },
  { id: 8, username: 'PhantomX', server: 'Majestic RP', lastScan: '2026-07-29', risk: 'clean', scansCount: 9, cheatTraces: 0 },
  { id: 9, username: 'DarkMatter', server: 'AltLife RP', lastScan: '2026-07-30', risk: 'medium', scansCount: 6, cheatTraces: 4 },
  { id: 10, username: 'BlazeRunner', server: 'Majestic RP', lastScan: '2026-07-28', risk: 'clean', scansCount: 18, cheatTraces: 0 },
  { id: 11, username: 'StormBreaker', server: 'CityLife RP', lastScan: '2026-07-30', risk: 'low', scansCount: 4, cheatTraces: 2 },
  { id: 12, username: 'CrimsonTide', server: 'Majestic RP', lastScan: '2026-07-26', risk: 'high', scansCount: 7, cheatTraces: 9 },
]

const RISK_CONFIG = {
  clean: { color: '#22c55e', bg: '#22c55e15', label: 'Чисто', icon: CheckCircle },
  low: { color: '#f59e0b', bg: '#f59e0b15', label: 'Низкий', icon: Shield },
  medium: { color: '#f97316', bg: '#f9731615', label: 'Средний', icon: AlertTriangle },
  high: { color: '#ef4444', bg: '#ef444415', label: 'Высокий', icon: AlertTriangle },
}

const fadeUp = {
  hidden: { opacity: 0, y: 20 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.03, duration: 0.4, ease: [0.16, 1, 0.3, 1] as const },
  }),
}

export default function PlayersDB() {
  const [search, setSearch] = useState('')
  const [riskFilter, setRiskFilter] = useState<string>('all')
  // Сортировка таблицы фиксирована (по умолчанию — последняя проверка, desc);
  // UI для смены порядка пока не добавлен, поэтому сеттеры не используются.
  const [sortField] = useState<'username' | 'lastScan' | 'scansCount'>('lastScan')
  const [sortDir] = useState<'asc' | 'desc'>('desc')

  const filtered = useMemo(() => {
    let list = [...MOCK_PLAYERS]
    if (search) {
      const q = search.toLowerCase()
      list = list.filter(p => p.username.toLowerCase().includes(q) || p.server.toLowerCase().includes(q))
    }
    if (riskFilter !== 'all') list = list.filter(p => p.risk === riskFilter)
    list.sort((a, b) => {
      const mul = sortDir === 'asc' ? 1 : -1
      if (sortField === 'username') return mul * a.username.localeCompare(b.username)
      if (sortField === 'lastScan') return mul * a.lastScan.localeCompare(b.lastScan)
      return mul * (a.scansCount - b.scansCount)
    })
    return list
  }, [search, riskFilter, sortField, sortDir])

  const stats = useMemo(() => ({
    total: MOCK_PLAYERS.length,
    clean: MOCK_PLAYERS.filter(p => p.risk === 'clean').length,
    flagged: MOCK_PLAYERS.filter(p => p.risk !== 'clean').length,
  }), [])

  return (
    <div className="pt-24 pb-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}>
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl sm:text-4xl font-bold text-predator-text mb-2">База данных игроков</h1>
          <p className="text-predator-muted">Публичный реестр результатов проверок Predator Anti-Cheat</p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          {[
            { label: 'Всего проверено', value: stats.total, color: '#6b7280' },
            { label: 'Чистых', value: stats.clean, color: '#22c55e' },
            { label: 'С нарушениями', value: stats.flagged, color: '#ef4444' },
          ].map(s => (
            <div key={s.label} className="glass-card p-4 text-center">
              <div className="text-2xl font-bold" style={{ color: s.color }}>{s.value}</div>
              <div className="text-xs text-predator-muted mt-1">{s.label}</div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="flex flex-col sm:flex-row gap-3 mb-6">
          <div className="relative flex-1">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-predator-muted" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Поиск по имени или серверу..."
              className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-predator-card border border-predator-border text-predator-text text-sm placeholder:text-predator-muted/50 focus:outline-none focus:border-predator-accent/50 transition-colors"
            />
          </div>
          <div className="relative">
            <Filter size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-predator-muted" />
            <select
              value={riskFilter}
              onChange={e => setRiskFilter(e.target.value)}
              className="pl-9 pr-8 py-2.5 rounded-xl bg-predator-card border border-predator-border text-predator-text text-sm appearance-none focus:outline-none focus:border-predator-accent/50 cursor-pointer"
            >
              <option value="all">Все статусы</option>
              <option value="clean">Чисто</option>
              <option value="low">Низкий риск</option>
              <option value="medium">Средний риск</option>
              <option value="high">Высокий риск</option>
            </select>
            <ChevronDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 text-predator-muted pointer-events-none" />
          </div>
        </div>

        {/* Table */}
        <div className="glass-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-predator-border">
                  <th className="text-left px-5 py-3.5 text-xs font-semibold text-predator-muted uppercase tracking-wider">Игрок</th>
                  <th className="text-left px-5 py-3.5 text-xs font-semibold text-predator-muted uppercase tracking-wider">Сервер</th>
                  <th className="text-left px-5 py-3.5 text-xs font-semibold text-predator-muted uppercase tracking-wider">Статус</th>
                  <th className="text-left px-5 py-3.5 text-xs font-semibold text-predator-muted uppercase tracking-wider">Проверок</th>
                  <th className="text-left px-5 py-3.5 text-xs font-semibold text-predator-muted uppercase tracking-wider">Следы</th>
                  <th className="text-left px-5 py-3.5 text-xs font-semibold text-predator-muted uppercase tracking-wider">Последняя</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((player, i) => {
                  const risk = RISK_CONFIG[player.risk]
                  const RiskIcon = risk.icon
                  return (
                    <motion.tr
                      key={player.id}
                      custom={i}
                      variants={fadeUp}
                      initial="hidden"
                      animate="visible"
                      className="border-b border-predator-border/50 hover:bg-predator-card/50 transition-colors"
                    >
                      <td className="px-5 py-3.5">
                        <div className="flex items-center gap-2.5">
                          <div className="w-8 h-8 rounded-lg bg-predator-accent/10 flex items-center justify-center text-predator-accent text-xs font-bold">
                            {player.username.slice(0, 2).toUpperCase()}
                          </div>
                          <span className="font-medium text-predator-text">{player.username}</span>
                        </div>
                      </td>
                      <td className="px-5 py-3.5 text-predator-muted">{player.server}</td>
                      <td className="px-5 py-3.5">
                        <span
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium"
                          style={{ background: risk.bg, color: risk.color }}
                        >
                          <RiskIcon size={12} />
                          {risk.label}
                        </span>
                      </td>
                      <td className="px-5 py-3.5 text-predator-text">{player.scansCount}</td>
                      <td className="px-5 py-3.5">
                        <span className={player.cheatTraces > 0 ? 'text-predator-danger font-medium' : 'text-predator-muted'}>
                          {player.cheatTraces}
                        </span>
                      </td>
                      <td className="px-5 py-3.5 text-predator-muted text-xs">{player.lastScan}</td>
                    </motion.tr>
                  )
                })}
                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-5 py-12 text-center text-predator-muted">
                      Игроки не найдены
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <p className="text-xs text-predator-muted mt-4 text-center">
          Данные обновляются в реальном времени. Показаны анонимизированные результаты.
        </p>
      </motion.div>
    </div>
  )
}
