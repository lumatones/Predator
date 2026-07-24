import { useState, useEffect } from 'react'
import { useAuth } from '../App'
import {
  getSuspiciousHashes, approveHash, rejectHash,
  getScanResultHashes, confirmHashFromScan,
  type SuspiciousHash, type ScanResultHash,
} from '../api'

// ── Tab definitions ──

interface TabDef {
  key: string
  label: string
  icon: string
}

const TABS: TabDef[] = [
  { key: 'pending', label: 'На проверке', icon: '⏳' },
  { key: 'confirmed', label: 'Подтверждённые', icon: '✅' },
  { key: 'false_positive', label: 'Ложные', icon: '❌' },
  { key: 'scan_results', label: 'Из сканов', icon: '📊' },
]

// ── Component ──

export default function SuspiciousHashes() {
  const { auth } = useAuth()
  const [tab, setTab] = useState<string>('pending')
  const [hashes, setHashes] = useState<(SuspiciousHash | ScanResultHash)[]>([])
  const [scanResultsTotal, setScanResultsTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = async (status: string) => {
    if (!auth) return
    setLoading(true)
    setError('')
    try {
      if (status === 'scan_results') {
        const data = await getScanResultHashes(auth.token, 100)
        setHashes(data.hashes)
        setScanResultsTotal(data.total)
      } else {
        const data = await getSuspiciousHashes(auth.token, status)
        setHashes(data)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка загрузки')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load(tab) }, [auth, tab])

  const handleApprove = async (id: number) => {
    if (!auth) return
    try {
      await approveHash(auth.token, id)
      load(tab)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка')
    }
  }

  const handleReject = async (id: number) => {
    if (!auth) return
    try {
      await rejectHash(auth.token, id)
      load(tab)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка')
    }
  }

  const handleConfirmFromScan = async (sha256: string, fileName: string, fileSize: number) => {
    if (!auth) return
    try {
      await confirmHashFromScan(auth.token, sha256, fileName, fileSize)
      load(tab)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка')
    }
  }

  const isScanTab = tab === 'scan_results'

  // ── Status helper for scan results ──
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'new': return <span style={{
        fontSize: 11, padding: '2px 6px', borderRadius: 4,
        background: 'rgba(245, 158, 11, 0.15)', color: '#eab308',
      }}>Новый</span>
      case 'pending': return <span style={{
        fontSize: 11, padding: '2px 6px', borderRadius: 4,
        background: 'rgba(59, 130, 246, 0.15)', color: '#3b82f6',
      }}>На проверке</span>
      case 'confirmed': return <span style={{
        fontSize: 11, padding: '2px 6px', borderRadius: 4,
        background: 'rgba(34, 197, 94, 0.15)', color: '#22c55e',
      }}>✅ Чит</span>
      case 'false_positive': return <span style={{
        fontSize: 11, padding: '2px 6px', borderRadius: 4,
        background: 'rgba(255, 107, 107, 0.15)', color: '#ff6b6b',
      }}>❌ Спам</span>
      default: return null
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Облачная база сигнатур</h1>
          <p>
            {isScanTab
              ? 'SHA256 хеши, извлечённые из результатов сканирований пользователей'
              : 'Хеши SHA256 подозрительных файлов, отправленные пользователями'}
          </p>
        </div>
      </div>

      <div className="tabs" style={{ display: 'flex', gap: 4, marginBottom: 20, flexWrap: 'wrap' }}>
        {TABS.map(t => (
          <button
            key={t.key}
            className={`btn ${tab === t.key ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setTab(t.key)}
            style={{ fontSize: 13, padding: '8px 16px' }}
          >
            {t.icon} {t.label}
            {t.key === 'scan_results' && scanResultsTotal > 0 &&
              ` (${scanResultsTotal})`}
          </button>
        ))}
      </div>

      {error && (
        <div style={{ color: '#ff6b6b', padding: 16, textAlign: 'center' }}>
          <p>{error}</p>
        </div>
      )}

      {loading ? (
        <div className="loading"><div className="spinner" />Загрузка...</div>
      ) : hashes.length === 0 ? (
        <div className="table-container">
          <div className="table-empty" style={{ padding: 60 }}>
            <div className="table-empty-icon" style={{ fontSize: 48 }}>🔍</div>
            <p>Нет хешей в статусе «{TABS.find(t => t.key === tab)?.label}»</p>
            <p style={{ fontSize: 13, marginTop: 4, color: 'var(--text-muted)' }}>
              {tab === 'pending'
                ? 'Хеши появляются после того, как пользователи запускают сканирование и находят подозрительные файлы'
                : tab === 'scan_results'
                  ? 'Хеши появятся после того, как пользователи отправят результаты сканирования'
                  : 'Подтверждённые хеши автоматически попадают в базу и используются при проверках'}
            </p>
          </div>
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>SHA256</th>
                <th>Имя файла</th>
                {!isScanTab && <th>Пользователь</th>}
                {isScanTab && <th>Пользователи</th>}
                <th>Размер</th>
                {!isScanTab && <th>Риск</th>}
                {isScanTab && <th>Найдено раз</th>}
                {isScanTab && <th>Статус</th>}
                {!isScanTab && <th>Дата</th>}
                {isScanTab && <th>Последний раз</th>}
                <th style={{ width: 200 }}>Действия</th>
              </tr>
            </thead>
            <tbody>
              {hashes.map((h: any, idx: number) => (
                <tr key={isScanTab ? `scan-${h.sha256}-${idx}` : `hash-${h.id}`} style={{
                  background: !isScanTab && h.status === 'new'
                    ? 'rgba(255, 255, 255, 0.02)' : undefined,
                }}>
                  <td>
                    <code style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                      {h.sha256.slice(0, 16)}...
                    </code>
                  </td>
                  <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{h.file_name}</span>
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }}>
                    {isScanTab
                      ? h.pc_usernames?.slice(0, 2).join(', ') || '—'
                      : h.pc_username}
                  </td>
                  <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                    {h.file_size > 0
                      ? h.file_size > 1024 * 1024
                        ? `${(h.file_size / (1024 * 1024)).toFixed(1)} MB`
                        : `${(h.file_size / 1024).toFixed(0)} KB`
                      : '—'}
                  </td>
                  {!isScanTab && (
                    <td>
                      <span className={`badge ${h.risk_score > 60 ? 'badge-high' : h.risk_score > 30 ? 'badge-medium' : 'badge-low'}`}
                        style={{ fontSize: 11 }}>
                        {h.risk_score}
                      </span>
                    </td>
                  )}
                  {isScanTab && (
                    <td style={{ fontSize: 12, textAlign: 'center' }}>
                      <span style={{
                        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                        minWidth: 24, height: 24, borderRadius: 12,
                        background: 'rgba(59, 130, 246, 0.15)', color: '#60a5fa',
                        fontSize: 11, fontWeight: 600,
                      }}>
                        {h.occurrences}
                      </span>
                    </td>
                  )}
                  {isScanTab && (
                    <td>{getStatusBadge(h.status)}</td>
                  )}
                  <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                    {new Date(isScanTab ? h.last_seen : h.created_at).toLocaleString('ru-RU')}
                  </td>
                  <td>
                    {!isScanTab && tab === 'pending' && (
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button
                          className="btn btn-primary"
                          style={{ fontSize: 11, padding: '4px 10px' }}
                          onClick={() => handleApprove(h.id)}
                        >
                          ✅ Чит
                        </button>
                        <button
                          className="btn btn-secondary"
                          style={{ fontSize: 11, padding: '4px 10px' }}
                          onClick={() => handleReject(h.id)}
                        >
                          ❌ Спам
                        </button>
                      </div>
                    )}
                    {!isScanTab && tab === 'confirmed' && (
                      <span style={{ fontSize: 12, color: '#22c55e' }}>
                        Reviewed by {h.reviewed_by_name || 'admin'}
                      </span>
                    )}
                    {!isScanTab && tab === 'false_positive' && (
                      <span style={{ fontSize: 12, color: '#ff6b6b' }}>
                        Отклонён {h.reviewed_by_name || 'admin'}
                      </span>
                    )}
                    {isScanTab && h.status === 'new' && (
                      <button
                        className="btn btn-primary"
                        style={{ fontSize: 11, padding: '4px 10px' }}
                        onClick={() => handleConfirmFromScan(h.sha256, h.file_name, h.file_size)}
                      >
                        ✅ Подтвердить чит
                      </button>
                    )}
                    {isScanTab && h.status !== 'new' && (
                      <span style={{ fontSize: 12, color: '#22c55e' }}>
                        {h.status === 'confirmed' ? '✅ В базе' :
                         h.status === 'pending' ? '⏳ На проверке' :
                         '❌ Отклонён'}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
