import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { useAuth } from '../App'
import { getHistory, type HistoryItem } from '../api'
import { Key, User, RefreshCw, Search, List } from 'lucide-react'
import { SkeletonStatCard, SkeletonTimeline, SkeletonText } from '../components/Skeleton'

const springEase = [0.34, 1.56, 0.64, 1] as const
const smoothEase = [0.16, 1, 0.3, 1] as const

const filters = [
  { key: 'all', label: 'Все' },
  { key: 'token', label: 'Токены' },
  { key: 'request', label: 'Запросы' },
] as const

export default function History() {
  const { auth } = useAuth()
  const [items, setItems] = useState<HistoryItem[]>([])
  const [stats, setStats] = useState({ totalTokensUsed: 0, totalRequestsProcessed: 0 })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState<'all' | 'token' | 'request'>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [searchFocused, setSearchFocused] = useState(false)

  async function load() {
    if (!auth) return
    setLoading(true)
    setError('')
    try {
      const data = await getHistory(auth.token, 200)
      setItems(data.items)
      setStats(data.stats)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка загрузки')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [auth])

  const filtered = items.filter(item => {
    if (filter === 'token' && item.type !== 'token') return false
    if (filter === 'request' && item.type !== 'request') return false
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      return (
        item.description.toLowerCase().includes(q) ||
        item.detail.toLowerCase().includes(q) ||
        item.actor.toLowerCase().includes(q)
      )
    }
    return true
  })

  function formatDate(dateStr: string) {
    if (!dateStr) return '—'
    return new Date(dateStr).toLocaleString('ru-RU', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    })
  }

  function formatTime(dateStr: string) {
    if (!dateStr) return '—'
    return new Date(dateStr).toLocaleString('ru-RU', {
      hour: '2-digit', minute: '2-digit',
    })
  }

  const getItemMeta = (item: HistoryItem) => {
    if (item.type === 'token') {
      return {
        icon: <Key size={14} />,
        color: '#3B82F6',
        bg: 'rgba(59, 130, 246, 0.15)',
        label: 'Токен',
      }
    }
    if (item.subType === 'approved') {
      return {
        icon: <User size={14} />,
        color: '#22c55e',
        bg: 'rgba(34, 197, 94, 0.15)',
        label: 'Одобрен',
      }
    }
    return {
      icon: <User size={14} />,
      color: '#ff6b6b',
      bg: 'rgba(255, 68, 68, 0.15)',
      label: 'Отклонён',
    }
  }

  const cardVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: (i: number) => ({
      opacity: 1,
      y: 0,
      transition: { delay: i * 0.08, duration: 0.45, ease: smoothEase },
    }),
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>История</h1>
          <p>Все события: использование токенов и обработка запросов</p>
        </div>
        <div className="page-actions">
          <button className="btn btn-outline" onClick={load} disabled={loading}>
            <RefreshCw size={16} className={loading ? 'spin' : ''} />
            {loading ? 'Загрузка...' : 'Обновить'}
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="stats-grid">
        <motion.div className="stat-card" initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, ease: springEase }}>
          <div className="stat-card-icon red"><Key size={20} /></div>
          <div className="stat-card-value">{stats.totalTokensUsed}</div>
          <div className="stat-card-label">Токенов использовано</div>
        </motion.div>
        <motion.div className="stat-card" initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08, duration: 0.4, ease: springEase }}>
          <div className="stat-card-icon green"><User size={20} /></div>
          <div className="stat-card-value">{stats.totalRequestsProcessed}</div>
          <div className="stat-card-label">Запросов обработано</div>
        </motion.div>
        <motion.div className="stat-card" initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.16, duration: 0.4, ease: springEase }}>
          <div className="stat-card-icon yellow"><List size={20} /></div>
          <div className="stat-card-value">{items.length}</div>
          <div className="stat-card-label">Всего событий</div>
        </motion.div>
      </div>

      {/* Filters + search */}
      <div className="table-container history-filters">
        <div className="history-filters-inner">
          <div className="history-filter-pills">
            {filters.map(f => (
              <button
                key={f.key}
                className={`history-filter-pill ${filter === f.key ? 'active' : ''}`}
                onClick={() => setFilter(f.key as typeof filter)}
              >
                {filter === f.key && (
                  <motion.div className="history-pill-bg" layoutId="history-pill-bg" />
                )}
                <span>{f.label}</span>
              </button>
            ))}
          </div>

          <motion.div className="history-search" animate={{ width: searchFocused ? 260 : 180 }} transition={{ duration: 0.25, ease: smoothEase }}>
            <Search size={14} className="history-search-icon" />
            <input
              type="text"
              className="history-search-input"
              placeholder="Поиск..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              onFocus={() => setSearchFocused(true)}
              onBlur={() => setSearchFocused(false)}
            />
          </motion.div>
        </div>
      </div>

      {/* Timeline */}
      <div className="table-container history-timeline-container">
      {loading && !items.length ? (
        <>
          <div className="stats-grid">
            <SkeletonStatCard />
            <SkeletonStatCard />
            <SkeletonStatCard />
          </div>
          <div className="table-container history-filters">
            <SkeletonText lines={1} width={200} />
          </div>
          <div className="table-container history-timeline-container">
            <SkeletonTimeline items={5} />
          </div>
        </>
      ) : error ? (
          <div className="history-error">
            <p>{error}</p>
            <button className="btn btn-primary" onClick={load}>Повторить</button>
          </div>
        ) : filtered.length === 0 ? (
          <div className="table-empty history-empty">
            <div className="table-empty-icon">📭</div>
            <p>Событий не найдено</p>
            <p>{searchQuery ? 'Попробуйте изменить поисковый запрос' : 'Нет истории — используйте токены и обрабатывайте запросы'}</p>
          </div>
        ) : (
          <div className="history-timeline">
            <motion.div
              className="timeline-line"
              initial={{ scaleY: 0 }}
              animate={{ scaleY: 1 }}
              transition={{ duration: 2, ease: smoothEase }}
            />
            <div className="timeline-items">
              {filtered.map((item, i) => {
                const meta = getItemMeta(item)
                return (
                  <motion.div
                    key={item.id}
                    className="timeline-item"
                    initial="hidden"
                    animate="visible"
                    custom={filtered.length - 1 - i}
                    variants={cardVariants}
                  >
                    <div className="timeline-node" style={{ color: meta.color, background: meta.bg, boxShadow: `0 0 12px ${meta.color}33` }}>
                      {meta.icon}
                    </div>
                    <div className="timeline-card">
                      <div className="timeline-card-header">
                        <span className="timeline-type" style={{ color: meta.color }}>{meta.label}</span>
                        <time className="timeline-time">{formatDate(item.date)}</time>
                      </div>
                      <p className="timeline-description">{item.description}</p>
                      <div className="timeline-detail">
                        {item.type === 'token' ? (
                          <span className="token-code token-code-sm">{item.detail}</span>
                        ) : (
                          <span>{item.detail}</span>
                        )}
                      </div>
                      <div className="timeline-actor">{item.actor} · {formatTime(item.date)}</div>
                    </div>
                  </motion.div>
                )
              })}
            </div>
          </div>
        )}

        {!loading && filtered.length > 0 && (
          <div className="history-footer">
            Показано {filtered.length} из {items.length} событий
          </div>
        )}
      </div>
    </div>
  )
}
