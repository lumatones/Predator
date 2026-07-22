import { useState, useEffect, useRef } from 'react'
import { useAuth } from '../App'
import { getTokens, generateTokens, revokeToken, Token } from '../api'

export default function Tokens() {
  const { auth } = useAuth()
  const [tokens, setTokens] = useState<Token[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null)
  const [genCount, setGenCount] = useState(1)
  const [generating, setGenerating] = useState(false)
  const [generatedCodes, setGeneratedCodes] = useState<string[] | null>(null)
  const [copiedId, setCopiedId] = useState<number | null>(null)
  const toastTimer = useRef<ReturnType<typeof setTimeout>>(undefined)
  const genTimeout = useRef<ReturnType<typeof setTimeout>>(undefined)

  useEffect(() => {
    return () => {
      if (toastTimer.current) clearTimeout(toastTimer.current)
      if (genTimeout.current) clearTimeout(genTimeout.current)
    }
  }, [])

  function showToast(type: 'success' | 'error', message: string) {
    setToast({ type, message })
    if (toastTimer.current) clearTimeout(toastTimer.current)
    toastTimer.current = setTimeout(() => setToast(null), 4000)
  }

  function clearGenerated() {
    setGeneratedCodes(null)
    load()
  }

  async function load() {
    if (!auth) return
    setLoading(true)
    setError('')
    try {
      const data = await getTokens(auth.token)
      setTokens(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка загрузки')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [auth])

  async function handleGenerate() {
    if (!auth) return
    setGenerating(true)
    setGeneratedCodes(null)
    try {
      const result = await generateTokens(auth.token, genCount)
      setGeneratedCodes(result.tokens)
      showToast('success', `Создано ${result.tokens.length} токен(ов)`)
      // Reload list after short delay
      if (genTimeout.current) clearTimeout(genTimeout.current)
      genTimeout.current = setTimeout(clearGenerated, 8000)
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Ошибка генерации')
    } finally {
      setGenerating(false)
    }
  }

  async function handleRevoke(id: number) {
    if (!auth) return
    if (!confirm('Отозвать этот токен?')) return
    try {
      await revokeToken(auth.token, id)
      showToast('success', 'Токен отозван')
      setTokens(prev => prev.map(t => t.id === id ? { ...t, is_active: false } : t))
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Ошибка')
    }
  }

  function handleCopy(code: string, id: number) {
    navigator.clipboard.writeText(code)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const activeTokens = tokens.filter(t => t.is_active)
  const usedTokens = tokens.filter(t => !t.is_active && t.used_by)
  const revokedTokens = tokens.filter(t => !t.is_active && !t.used_by)

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Управление токенами</h1>
          <p>Создание и управление токенами доступа</p>
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
          <div className="stat-card-icon green">✓</div>
          <div className="stat-card-value">{activeTokens.length}</div>
          <div className="stat-card-label">Активных</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-icon red">👤</div>
          <div className="stat-card-value">{usedTokens.length}</div>
          <div className="stat-card-label">Использовано</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-icon yellow">📋</div>
          <div className="stat-card-value">{tokens.length}</div>
          <div className="stat-card-label">Всего</div>
        </div>
      </div>

      {/* Generate form */}
      <div className="table-container" style={{ marginBottom: 20 }}>
        <div className="table-header">
          <h3>Создать токены</h3>
        </div>
        <div style={{ padding: '16px 20px' }}>
          <div className="generate-form">
            <label style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Количество:</label>
            <input
              type="number"
              min={1}
              max={10}
              value={genCount}
              onChange={e => setGenCount(Math.min(10, Math.max(1, parseInt(e.target.value) || 1)))}
            />
            <button className="btn btn-primary" onClick={handleGenerate} disabled={generating}>
              {generating ? 'Генерация...' : 'Сгенерировать'}
            </button>
          </div>

          {generatedCodes && (
            <div className="generate-result">
              <h4>Созданные токены</h4>
              <div className="token-list">
                {generatedCodes.map((code, i) => (
                  <div key={i} className="token-item">
                    <span>{code}</span>
                    <button className="copy-btn" onClick={() => handleCopy(code, -1)}>
                      {copiedId === -1 ? 'Скопировано ✓' : 'Копировать'}
                    </button>
                  </div>
                ))}
              </div>
              <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 10 }}>
                Эти токены будут показаны здесь ещё 8 секунд. Скопируйте их сейчас.
              </p>
            </div>
          )}
        </div>
      </div>

      {error && (
        <div style={{ background: 'rgba(255,68,68,0.1)', border: '1px solid rgba(255,68,68,0.2)', borderRadius: 8, padding: 12, marginBottom: 20, color: '#ff6b6b', fontSize: 13 }}>
          {error}
        </div>
      )}

      {/* Tokens list */}
      <div className="table-container">
        <div className="table-header">
          <h3>Все токены</h3>
          {tokens.length > 0 && <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>{tokens.length} шт.</span>}
        </div>

        {loading && !tokens.length ? (
          <div className="loading">
            <div className="spinner" />
            Загрузка токенов...
          </div>
        ) : tokens.length === 0 ? (
          <div className="table-empty">
            <div className="table-empty-icon">🔑</div>
            <p>Токены ещё не созданы</p>
            <p style={{ fontSize: 13, marginTop: 4 }}>Используйте форму выше для создания первых токенов</p>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Токен</th>
                <th>Статус</th>
                <th>Использован</th>
                <th>Создан</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {tokens.map(t => (
                <tr key={t.id}>
                  <td>
                    <span className="token-code">{t.code_display}</span>
                    <button
                      className="copy-btn"
                      style={{ marginLeft: 8 }}
                      onClick={() => handleCopy(t.code_display, t.id)}
                    >
                      {copiedId === t.id ? '✓' : '📋'}
                    </button>
                  </td>
                  <td>
                    <span className={`badge ${t.is_active ? 'badge-active' : 'badge-inactive'}`}>
                      {t.is_active ? 'Активен' : t.used_by ? 'Использован' : 'Отозван'}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                    {t.used_by ? (
                      <>
                        {t.used_by}
                        <br />
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          {t.used_at ? new Date(t.used_at).toLocaleString('ru-RU') : ''}
                        </span>
                      </>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                    {new Date(t.created_at).toLocaleString('ru-RU')}
                    <br />
                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      {t.created_by_name}
                    </span>
                  </td>
                  <td>
                    {t.is_active && (
                      <button className="btn btn-danger btn-sm" onClick={() => handleRevoke(t.id)}>
                        Отозвать
                      </button>
                    )}
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
