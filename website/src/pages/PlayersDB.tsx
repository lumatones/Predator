import { useState, useEffect, useMemo, useCallback } from 'react'
import { motion } from 'framer-motion'
import { Search, Shield, AlertTriangle, CheckCircle, Filter, ChevronDown, ChevronUp, ArrowUpDown, RefreshCw, Database, Radio } from 'lucide-react'
import { fetchPlayers, fetchStats, type PlayerProfile, type WebsiteStats } from '../api'

const RISK_CONFIG = {
  clean: { color: '#8da2ff', label: 'Чисто', icon: CheckCircle },
  low: { color: '#d8ad68', label: 'Низкий риск', icon: Shield },
  medium: { color: '#d88b64', label: 'Средний риск', icon: AlertTriangle },
  high: { color: '#e17979', label: 'Высокий риск', icon: AlertTriangle },
}

type SortField = 'display_name' | 'last_scan_at' | 'total_scans'

function SortableTh({ label, field, sortField, sortDir, onSort }: { label: string; field: SortField; sortField: SortField; sortDir: 'asc' | 'desc'; onSort: (field: SortField) => void }) {
  const active = sortField === field
  return (
    <th className="px-4 py-3 text-left font-mono text-[10px] uppercase tracking-[0.14em]" aria-sort={active ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button type="button" onClick={() => onSort(field)} title={`Сортировать по: ${label}`} className={`inline-flex items-center gap-2 transition-colors ${active ? 'text-predator-accent' : 'text-predator-muted hover:text-predator-text'}`}>
        {label}
        {active ? (sortDir === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />) : <ArrowUpDown size={11} className="opacity-50" />}
      </button>
    </th>
  )
}

function formatDate(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('ru-RU')
}

export default function PlayersDB() {
  const [search, setSearch] = useState('')
  const [riskFilter, setRiskFilter] = useState('all')
  const [sortField, setSortField] = useState<SortField>('last_scan_at')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')
  const [players, setPlayers] = useState<PlayerProfile[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [stats, setStats] = useState<WebsiteStats | null>(null)

  useEffect(() => { fetchStats().then(setStats).catch(() => setStats(null)) }, [])

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    fetchPlayers({ search, risk: riskFilter })
      .then(({ players: list, total: count }) => { setPlayers(list); setTotal(count) })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [search, riskFilter])

  useEffect(() => { load() }, [load])

  const handleSort = (field: SortField) => {
    if (field === sortField) setSortDir(dir => dir === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('desc') }
  }

  const filtered = useMemo(() => {
    const list = [...players]
    list.sort((a, b) => {
      const multiplier = sortDir === 'asc' ? 1 : -1
      if (sortField === 'display_name') return multiplier * a.display_name.localeCompare(b.display_name)
      if (sortField === 'last_scan_at') return multiplier * ((a.last_scan_at ? Date.parse(a.last_scan_at) : 0) - (b.last_scan_at ? Date.parse(b.last_scan_at) : 0))
      return multiplier * (a.total_scans - b.total_scans)
    })
    return list
  }, [players, sortField, sortDir])

  const displayStats = useMemo(() => ({
    total: stats?.totalPlayers ?? total,
    clean: stats?.cleanPlayers ?? players.filter(player => player.risk_level === 'clean').length,
    flagged: stats?.flaggedPlayers ?? players.filter(player => player.risk_level !== 'clean').length,
  }), [stats, players, total])

  return (
    <div className="mx-auto max-w-[1440px] px-4 pb-20 pt-28 sm:px-6 lg:px-10 lg:pt-36">
      <motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.55 }}>
        <div className="mb-8 flex flex-col justify-between gap-6 border-b border-predator-border pb-8 lg:flex-row lg:items-end">
          <div>
            <div className="section-rule mb-5 max-w-xl">Публичный реестр / только просмотр</div>
            <div className="flex items-center gap-3"><Database size={22} className="text-predator-accent" /><h1 className="display-face text-4xl tracking-wide text-predator-text sm:text-5xl">Реестр игроков</h1></div>
            <p className="mt-3 max-w-xl text-sm leading-6 text-predator-muted">Анонимизированный реестр результатов проверок. Откройте строку, чтобы быстро оценить состояние узла.</p>
          </div>
          <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.16em] text-predator-accent"><Radio size={13} className="animate-blink-soft" /> Данные доступны</div>
        </div>

        <div className="mb-8 grid grid-cols-1 overflow-hidden rounded-3xl border border-white/[0.08] sm:grid-cols-3">
          {[
            { label: 'Профили в реестре', value: displayStats.total, color: '#f0f1ed' },
            { label: 'Чистые проверки', value: displayStats.clean, color: '#8da2ff' },
            { label: 'Сигналы риска', value: displayStats.flagged, color: '#e17979' },
          ].map((stat, index) => (
            <div key={stat.label} className={`flex items-end justify-between p-4 ${index > 0 ? 'border-t border-predator-border sm:border-l sm:border-t-0' : ''}`}>
              <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-predator-muted">{stat.label}</span>
              <span className="data-mono text-2xl font-bold" style={{ color: stat.color }}>{stat.value}</span>
            </div>
          ))}
        </div>

        <div className="mb-5 flex flex-col gap-3 rounded-3xl border border-white/[0.08] bg-white/[0.02] p-3 sm:flex-row">
          <div className="relative flex-1">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-predator-muted" />
            <label htmlFor="player-search" className="sr-only">Поиск по имени или серверу</label>
            <input id="player-search" type="text" value={search} onChange={event => setSearch(event.target.value)} placeholder="Поиск по игроку или серверу" className="w-full rounded-full border border-white/[0.1] bg-predator-card py-3 pl-10 pr-4 font-mono text-xs text-predator-text placeholder:text-predator-muted/60 focus:border-predator-accent focus:outline-none" />
          </div>
          <div className="relative">
            <Filter size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-predator-muted" />
            <label htmlFor="risk-filter" className="sr-only">Фильтр риска</label>
            <select id="risk-filter" value={riskFilter} onChange={event => setRiskFilter(event.target.value)} className="w-full appearance-none rounded-full border border-white/[0.1] bg-predator-card py-3 pl-9 pr-9 font-mono text-xs text-predator-text focus:border-predator-accent focus:outline-none sm:w-52">
              <option value="all">Все статусы</option><option value="clean">Чисто</option><option value="low">Низкий риск</option><option value="medium">Средний риск</option><option value="high">Высокий риск</option>
            </select>
            <ChevronDown size={13} className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-predator-muted" />
          </div>
          <button type="button" onClick={load} title="Обновить данные" aria-label="Обновить данные" className="flex items-center justify-center rounded-full border border-white/[0.1] px-4 text-predator-muted transition-colors hover:border-predator-accent hover:text-predator-accent"><RefreshCw size={15} className={loading ? 'animate-spin' : ''} /></button>
        </div>

        <div className="evidence-panel overflow-hidden">
          {loading ? (
            <div className="space-y-3 p-5" role="status" aria-label="Загрузка реестра">
              <div className="flex items-center gap-3 pb-3"><span className="evidence-skeleton h-3 w-20 rounded-full" /><span className="evidence-skeleton h-3 w-32 rounded-full" /></div>
              {Array.from({ length: 5 }, (_, index) => <div key={index} className="grid grid-cols-4 gap-4 border-t border-white/[0.06] py-4"><span className="evidence-skeleton h-4 rounded-full" /><span className="evidence-skeleton h-4 rounded-full" /><span className="evidence-skeleton h-4 w-3/4 rounded-full" /><span className="evidence-skeleton h-4 w-1/2 rounded-full" /></div>)}
            </div>
          ) : error ? (
            <div className="evidence-state mx-5 my-5 p-10 text-center" role="alert"><AlertTriangle size={24} className="mx-auto mb-3 text-predator-danger" aria-hidden="true" /><p className="text-sm text-predator-text">Не удалось получить данные реестра.</p><p className="mt-2 text-xs text-predator-muted">{error}</p><button type="button" onClick={load} className="mt-5 rounded-full border border-white/[0.1] px-4 py-2 text-xs text-predator-muted transition-colors hover:border-predator-accent hover:text-predator-accent">Повторить запрос</button></div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[760px] text-sm">
                <thead className="bg-predator-bg">
                  <tr className="border-b border-predator-border"><SortableTh label="Игрок" field="display_name" sortField={sortField} sortDir={sortDir} onSort={handleSort} /><th className="px-4 py-3 text-left font-mono text-[10px] uppercase tracking-[0.14em] text-predator-muted">Сервер</th><th className="px-4 py-3 text-left font-mono text-[10px] uppercase tracking-[0.14em] text-predator-muted">Статус</th><SortableTh label="Проверки" field="total_scans" sortField={sortField} sortDir={sortDir} onSort={handleSort} /><th className="px-4 py-3 text-left font-mono text-[10px] uppercase tracking-[0.14em] text-predator-muted">Следы</th><SortableTh label="Последняя" field="last_scan_at" sortField={sortField} sortDir={sortDir} onSort={handleSort} /></tr>
                </thead>
                <tbody>
                  {filtered.map((player, index) => {
                    const risk = RISK_CONFIG[player.risk_level] || RISK_CONFIG.clean
                    const RiskIcon = risk.icon
                    return (
                      <motion.tr key={player.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: index * 0.025 }} className="border-b border-white/[0.07] transition-colors hover:bg-white/[0.035]">
                        <td className="px-4 py-4"><div className="flex items-center gap-3"><span className="data-mono text-[10px] text-predator-muted">{String(index + 1).padStart(2, '0')}</span><span className="flex h-8 w-8 items-center justify-center rounded-full border border-predator-border font-mono text-[10px] text-predator-accent">{player.display_name.slice(0, 2).toUpperCase()}</span><span className="font-medium text-predator-text">{player.display_name}</span></div></td>
                        <td className="data-mono px-4 py-4 text-xs text-predator-muted">{player.server_name || '—'}</td>
                        <td className="px-4 py-4"><span className="inline-flex items-center gap-2 font-mono text-[10px] tracking-[0.08em]" style={{ color: risk.color }}><RiskIcon size={12} /> {risk.label}</span></td>
                        <td className="data-mono px-4 py-4 text-predator-text">{player.total_scans}</td>
                        <td className="data-mono px-4 py-4" style={{ color: player.cheat_traces > 0 ? '#e17979' : '#929aa3' }}>{String(player.cheat_traces).padStart(2, '0')}</td>
                        <td className="data-mono px-4 py-4 text-xs text-predator-muted">{formatDate(player.last_scan_at)}</td>
                      </motion.tr>
                    )
                  })}
                  {filtered.length === 0 && <tr><td colSpan={6} className="px-5 py-16 text-center"><Database size={22} className="mx-auto mb-3 text-predator-muted" aria-hidden="true" /><p className="text-sm text-predator-text">{search || riskFilter !== 'all' ? 'По запросу ничего не найдено.' : 'Реестр пока пуст.'}</p><p className="mx-auto mt-2 max-w-sm text-xs leading-5 text-predator-muted">{search || riskFilter !== 'all' ? 'Попробуйте изменить имя игрока или фильтр риска.' : 'После первой проверки здесь появятся результаты и источники сигнала.'}</p></td></tr>}
                </tbody>
              </table>
            </div>
          )}
        </div>
        <p className="mt-4 text-center text-[10px] text-predator-muted">Публичный реестр · анонимизированные результаты · обновление по запросу</p>
      </motion.div>
    </div>
  )
}
