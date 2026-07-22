import { useState, useEffect } from 'react'
import { useAuth } from '../App'
import { getDashboardStats, DashboardStats } from '../api'

export default function Dashboard() {
  const { auth } = useAuth()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  async function load() {
    if (!auth) return
    setLoading(true)
    setError('')
    try {
      const data = await getDashboardStats(auth.token)
      setStats(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка загрузки')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [auth])

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner" />
        Загрузка...
      </div>
    )
  }

  if (error) {
    return (
      <div style={{ color: '#ff6b6b', padding: 40, textAlign: 'center' }}>
        <p>Ошибка загрузки: {error}</p>
        <button className="btn btn-primary" style={{ marginTop: 16 }} onClick={load}>
          Повторить
        </button>
      </div>
    )
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Панель управления</h1>
          <p>Сводка по системе авторизации Predator</p>
        </div>
      </div>

      {/* Stats cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-card-icon yellow">⏳</div>
          <div className="stat-card-value">{stats?.pendingCount ?? 0}</div>
          <div className="stat-card-label">Ожидающих запросов</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-icon green">✓</div>
          <div className="stat-card-value">{stats?.activeTokens ?? 0}</div>
          <div className="stat-card-label">Активных токенов</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-icon red">👤</div>
          <div className="stat-card-value">{stats?.usedTokens ?? 0}</div>
          <div className="stat-card-label">Использованных токенов</div>
        </div>
      </div>

      {/* Recent requests */}
      <div className="table-container" style={{ marginBottom: 20 }}>
        <div className="table-header">
          <h3>Последние запросы</h3>
        </div>
        {stats?.recentRequests && stats.recentRequests.length > 0 ? (
          <table>
            <thead>
              <tr>
                <th>Имя ПК</th>
                <th>Статус</th>
                <th>Дата</th>
              </tr>
            </thead>
            <tbody>
              {stats.recentRequests.map(r => (
                <tr key={r.id}>
                  <td style={{ fontWeight: 500 }}>{r.pc_username}</td>
                  <td>
                    <span className={`badge badge-${r.status}`}>
                      {r.status === 'pending' ? 'Ожидает' : r.status === 'approved' ? 'Одобрен' : 'Отклонён'}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }}>
                    {new Date(r.created_at).toLocaleString('ru-RU')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="table-empty">
            <div className="table-empty-icon">📋</div>
            Нет запросов на доступ
          </div>
        )}
      </div>

      {/* Recent tokens */}
      <div className="table-container">
        <div className="table-header">
          <h3>Последние токены</h3>
        </div>
        {stats?.recentTokens && stats.recentTokens.length > 0 ? (
          <table>
            <thead>
              <tr>
                <th>Токен</th>
                <th>Статус</th>
                <th>Создан</th>
              </tr>
            </thead>
            <tbody>
              {stats.recentTokens.map(t => (
                <tr key={t.id}>
                  <td>
                    <span className="token-code token-code-sm">{t.code_display}</span>
                  </td>
                  <td>
                    <span className={`badge ${t.is_active ? 'badge-active' : 'badge-inactive'}`}>
                      {t.is_active ? 'Активен' : t.used_by ? 'Использован' : 'Отозван'}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }}>
                    {new Date(t.created_at).toLocaleString('ru-RU')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="table-empty">
            <div className="table-empty-icon">🔑</div>
            Токены ещё не созданы
          </div>
        )}
      </div>
    </div>
  )
}
