import { useState, useEffect } from 'react'
import { useAuth } from '../App'
import { getHistory, HistoryItem } from '../api'

export default function History() {
  const { auth } = useAuth()
  const [items, setItems] = useState<HistoryItem[]>([])
  const [stats, setStats] = useState({ totalTokensUsed: 0, totalRequestsProcessed: 0 })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState<'all' | 'token' | 'request'>('all')
  const [searchQuery, setSearchQuery] = useState('')

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

  function getTypeIcon(type: string) {
    return type === 'token' ? '🔑' : '👤'
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
            {loading ? 'Загрузка...' : 'Обновить'}
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-card-icon red">🔑</div>
          <div className="stat-card-value">{stats.totalTokensUsed}</div>
          <div className="stat-card-label">Токенов использовано</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-icon green">✓</div>
          <div className="stat-card-value">{stats.totalRequestsProcessed}</div>
          <div className="stat-card-label">Запросов обработано</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-icon yellow">📋</div>
          <div className="stat-card-value">{items.length}</div>
          <div className="stat-card-label">Всего событий</div>
        </div>
      </div>

      {/* Filters */}
      <div className="table-container" style={{ marginBottom: 20 }}>
        <div className="table-header">
          <h3>События</h3>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <div className="filter-tabs" style={{ display: 'flex', gap: 4, background: 'rgba(255,255,255,0.03)', borderRadius: 8, padding: 3 }}>
              {(['all', 'token', 'request'] as const).map(f => (
                <button
                  key={f}
                  className={`btn btn-sm ${filter === f ? 'btn-primary' : 'btn-outline'}`}
                  onClick={() => setFilter(f)}
                  style={{ padding: '5px 12px', fontSize: 11 }}
                >
                  {f === 'all' ? 'Все' : f === 'token' ? 'Токены' : 'Запросы'}
                </button>
              ))}
            </div>
            <input
              type="text"
              className="form-input"
              placeholder="Поиск..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              style={{ width: 180, padding: '6px 12px', fontSize: 12 }}
            />
          </div>
        </div>

        {loading && !items.length ? (
          <div className="loading">
            <div className="spinner" />
            Загрузка истории...
          </div>
        ) : error ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#ff6b6b' }}>
            <p>{error}</p>
            <button className="btn btn-primary" style={{ marginTop: 12 }} onClick={load}>
              Повторить
            </button>
          </div>
        ) : filtered.length === 0 ? (
          <div className="table-empty">
            <div className="table-empty-icon">📭</div>
            <p>Событий не найдено</p>
            <p style={{ fontSize: 13, marginTop: 4, color: 'var(--text-muted)' }}>
              {searchQuery ? 'Попробуйте изменить поисковый запрос' : 'Нет истории — используйте токены и обрабатывайте запросы'}
            </p>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th style={{ width: 40 }}></th>
                <th>Событие</th>
                <th>Описание</th>
                <th>Детали</th>
                <th>Администратор</th>
                <th>Дата</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(item => (
                <tr key={item.id}>
                  <td style={{ textAlign: 'center', fontSize: 16 }}>{getTypeIcon(item.type)}</td>
                  <td>
                    <span className={`badge ${item.subType === 'used' || item.subType === 'approved' ? 'badge-approved' : 'badge-rejected'}`}>
                      {item.subType === 'used' ? 'Использован' :
                       item.subType === 'approved' ? 'Одобрен' : 'Отклонён'}
                    </span>
                  </td>
                  <td style={{ fontWeight: 500 }}>{item.description}</td>
                  <td>
                    {item.type === 'token' ? (
                      <span className="token-code token-code-sm">{item.detail}</span>
                    ) : (
                      <span style={{ color: 'var(--text-secondary)' }}>{item.detail}</span>
                    )}
                  </td>
                  <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{item.actor}</td>
                  <td style={{ color: 'var(--text-secondary)', fontSize: 12, whiteSpace: 'nowrap' }}>
                    {formatDate(item.date)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {!loading && filtered.length > 0 && (
          <div style={{ padding: '10px 20px', borderTop: '1px solid var(--border)', fontSize: 12, color: 'var(--text-muted)' }}>
            Показано {filtered.length} из {items.length} событий
          </div>
        )}
      </div>
    </div>
  )
}
