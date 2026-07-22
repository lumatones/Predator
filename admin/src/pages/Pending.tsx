import { useState, useEffect, useRef } from 'react'
import { useAuth } from '../App'
import { getPending, approveRequest, rejectRequest, PendingRequest } from '../api'

export default function Pending() {
  const { auth } = useAuth()
  const [requests, setRequests] = useState<PendingRequest[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null)
  const [actionId, setActionId] = useState<number | null>(null)
  const toastTimer = useRef<ReturnType<typeof setTimeout>>(undefined)

  useEffect(() => {
    return () => {
      if (toastTimer.current) clearTimeout(toastTimer.current)
    }
  }, [])

  function showToast(type: 'success' | 'error', message: string) {
    setToast({ type, message })
    if (toastTimer.current) clearTimeout(toastTimer.current)
    toastTimer.current = setTimeout(() => setToast(null), 4000)
  }

  async function load() {
    if (!auth) return
    setLoading(true)
    setError('')
    try {
      const data = await getPending(auth.token)
      setRequests(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка загрузки')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [auth])

  async function handleApprove(id: number) {
    if (!auth) return
    setActionId(id)
    try {
      await approveRequest(auth.token, id)
      showToast('success', 'Запрос одобрен')
      setRequests(prev => prev.filter(r => r.id !== id))
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Ошибка')
    } finally {
      setActionId(null)
    }
  }

  async function handleReject(id: number) {
    if (!auth) return
    setActionId(id)
    try {
      await rejectRequest(auth.token, id)
      showToast('success', 'Запрос отклонён')
      setRequests(prev => prev.filter(r => r.id !== id))
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Ошибка')
    } finally {
      setActionId(null)
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Запросы на доступ</h1>
          <p>Пользователи, ожидающие подтверждения {requests.length > 0 && `(${requests.length})`}</p>
        </div>
        <div className="page-actions">
          <button className="btn btn-outline" onClick={load} disabled={loading}>
            {loading ? 'Загрузка...' : 'Обновить'}
          </button>
        </div>
      </div>

      {error && (
        <div style={{ background: 'rgba(255,68,68,0.1)', border: '1px solid rgba(255,68,68,0.2)', borderRadius: 8, padding: 12, marginBottom: 20, color: '#ff6b6b', fontSize: 13 }}>
          {error}
        </div>
      )}

      <div className="table-container">
        <div className="table-header">
          <h3>Ожидающие проверки</h3>
          {requests.length > 0 && <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>{requests.length} запрос(ов)</span>}
        </div>

        {loading && !requests.length ? (
          <div className="loading">
            <div className="spinner" />
            Загрузка запросов...
          </div>
        ) : requests.length === 0 ? (
          <div className="table-empty">
            <div className="table-empty-icon">✅</div>
            <p>Нет ожидающих запросов</p>
            <p style={{ fontSize: 13, marginTop: 4 }}>Все запросы обработаны</p>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Имя ПК</th>
                <th>Дата запроса</th>
                <th>Истекает</th>
                <th>Действия</th>
              </tr>
            </thead>
            <tbody>
              {requests.map(r => (
                <tr key={r.id}>
                  <td style={{ color: 'var(--text-muted)', fontFamily: 'monospace' }}>#{r.id}</td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontWeight: 500 }}>{r.pc_username}</span>
                    </div>
                  </td>
                  <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                    {new Date(r.created_at).toLocaleString('ru-RU')}
                  </td>
                  <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                    {r.expires_at
                      ? new Date(r.expires_at).toLocaleString('ru-RU')
                      : '—'}
                  </td>
                  <td>
                    <div className="action-btns">
                      <button
                        className="btn btn-green btn-sm"
                        onClick={() => handleApprove(r.id)}
                        disabled={actionId === r.id}
                      >
                        {actionId === r.id ? '...' : 'Одобрить'}
                      </button>
                      <button
                        className="btn btn-danger btn-sm"
                        onClick={() => handleReject(r.id)}
                        disabled={actionId === r.id}
                      >
                        {actionId === r.id ? '...' : 'Отклонить'}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Toast */}
      {toast && (
        <div className="toast-container">
          <div className={`toast toast-${toast.type}`}>{toast.message}</div>
        </div>
      )}
    </div>
  )
}
