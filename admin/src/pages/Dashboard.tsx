import { useState, useEffect, useCallback } from 'react'
import { useAuth } from '../App'
import { getDashboardStats, getScanStats, type DashboardStats, type ScanStats } from '../api'
import { io, Socket } from 'socket.io-client'
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  Title,
} from 'chart.js'
import { Doughnut, Bar } from 'react-chartjs-2'

ChartJS.register(
  ArcElement, Tooltip, Legend,
  CategoryScale, LinearScale, BarElement,
  PointElement, LineElement, Title,
)

// WebSocket URL — используем hostname браузера (работает через Vite proxy и на сервере)
const WS_BASE = `http://${window.location.hostname}:3001`

// ── Notification Toast ──

interface Toast {
  type: 'success' | 'warning' | 'info'
  message: string
}

function ToastItem({ toast, onDone }: { toast: Toast; onDone: () => void }) {
  useEffect(() => {
    const timer = setTimeout(onDone, 5000)
    return () => clearTimeout(timer)
  }, [onDone])

  const bgColor = toast.type === 'success' ? 'rgba(34,197,94,0.15)' :
    toast.type === 'warning' ? 'rgba(234,179,8,0.15)' : 'rgba(59,130,246,0.15)'
  const borderColor = toast.type === 'success' ? 'rgba(34,197,94,0.25)' :
    toast.type === 'warning' ? 'rgba(234,179,8,0.25)' : 'rgba(59,130,246,0.25)'
  const textColor = toast.type === 'success' ? '#22c55e' :
    toast.type === 'warning' ? '#eab308' : '#3B82F6'

  return (
    <div className="toast" style={{ background: bgColor, border: `1px solid ${borderColor}`, color: textColor }}>
      {toast.message}
    </div>
  )
}

export default function Dashboard() {
  const { auth } = useAuth()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [scanStats, setScanStats] = useState<ScanStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [scanLoading, setScanLoading] = useState(true)
  const [error, setError] = useState('')
  const [toasts, setToasts] = useState<Toast[]>([])
  const [wsConnected, setWsConnected] = useState(false)

  const addToast = useCallback((type: Toast['type'], message: string) => {
    setToasts(prev => [...prev, { type, message }])
  }, [])

  const removeToast = useCallback((index: number) => {
    setToasts(prev => prev.filter((_, i) => i !== index))
  }, [])

  // ── Initial data load ──

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

  async function loadScanStats() {
    if (!auth) return
    setScanLoading(true)
    try {
      const data = await getScanStats(auth.token)
      setScanStats(data)
    } catch { /* optional */ }
    finally { setScanLoading(false) }
  }

  useEffect(() => { load(); loadScanStats() }, [auth])

  // ── WebSocket connection (Socket.IO) ──

  useEffect(() => {
    if (!auth) return

    let socket: Socket | null = null
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null

    function connect() {
      socket = io(WS_BASE, {
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionAttempts: Infinity,
        reconnectionDelay: 2000,
      })

      socket.on('connect', () => {
        console.log('🔌 WebSocket connected:', socket?.id)
        setWsConnected(true)
        socket?.emit('join-admin')

        // Initial data load on reconnect
        load()
        loadScanStats()
      })

      socket.on('disconnect', (reason) => {
        console.log('🔌 WebSocket disconnected:', reason)
        setWsConnected(false)
      })

      socket.on('connect_error', (err) => {
        console.log('🔌 WebSocket error:', err.message)
        setWsConnected(false)
      })

      // ── Server events ──

      socket.on('request-update', (data) => {
        const msg = data.type === 'approved'
          ? `✅ Запрос ${data.pcUsername} одобрен администратором ${data.admin}`
          : `❌ Запрос ${data.pcUsername} отклонён администратором ${data.admin}`
        addToast('success', msg)
        // Reload data
        load()
        loadScanStats()
      })

      socket.on('token-generated', (data) => {
        addToast('success', `🔑 Создано ${data.count} новых токенов администратором ${data.admin}`)
        loadScanStats()
      })

      socket.on('new-request', (data) => {
        addToast('warning', `👤 Новый запрос на доступ от ${data.pcUsername} (ID: ${data.requestId})`)
        load()
      })

      socket.on('scan-result', (data) => {
        addToast('info', `📊 Новое сканирование от ${data.pc_username}: режим ${data.mode}, ${data.suspicious_files} угроз`)
        loadScanStats()
      })
    }

    connect()

    return () => {
      if (socket) {
        socket.removeAllListeners()
        socket.disconnect()
      }
      if (reconnectTimer) clearTimeout(reconnectTimer)
    }
  }, [auth, addToast])

  // ── Chart configs ──

  const modeColors: Record<string, string> = {
    files: '#ff4444', processes: '#3B82F6', cheats: '#F59E0B',
    dma: '#8B5CF6', extended: '#22c55e', network: '#06b6d4',
  }

  const modeNames: Record<string, string> = {
    files: 'Файлы', processes: 'Процессы', cheats: 'Читы',
    dma: 'DMA', extended: 'Расширенный', network: 'Сеть',
  }

  const modeChartData = {
    labels: (scanStats?.byMode || []).map(m => modeNames[m.mode] || m.mode),
    datasets: [{
      data: (scanStats?.byMode || []).map(m => m.cnt),
      backgroundColor: (scanStats?.byMode || []).map(m => modeColors[m.mode] || '#3b82f6'),
      borderWidth: 0,
      hoverOffset: 8,
    }],
  }

  const dayBarChartData = {
    labels: (scanStats?.byDay || []).map(d => {
      const date = new Date(d.day)
      return date.toLocaleDateString('ru-RU', { day: 'numeric', month: 'short' })
    }),
    datasets: [
      {
        label: 'Сканирования',
        data: (scanStats?.byDay || []).map(d => d.cnt),
        backgroundColor: 'rgba(59, 130, 246, 0.3)',
        borderColor: '#3B82F6',
        borderWidth: 2,
      },
      {
        label: 'Угрозы',
        data: (scanStats?.byDay || []).map(d => d.threats),
        backgroundColor: 'rgba(255, 68, 68, 0.3)',
        borderColor: '#ff4444',
        borderWidth: 2,
      },
    ],
  }

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: '#94a3b8', font: { size: 11 } },
      },
    },
    scales: {
      x: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.03)' } },
      y: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.03)' }, beginAtZero: true },
    },
  }

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom' as const,
        labels: { color: '#94a3b8', font: { size: 11 }, padding: 12 },
      },
    },
  }

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
          <p>Сводка по системе авторизации и сканированиям Predator</p>
        </div>
        <div className="page-actions" style={{ alignItems: 'center', gap: 12 }}>
          {/* WebSocket status indicator */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            fontSize: 12, color: wsConnected ? '#22c55e' : '#ff6b6b',
          }}>
            <span style={{
              width: 8, height: 8, borderRadius: '50%',
              background: wsConnected ? '#22c55e' : '#ff6b6b',
              animation: wsConnected ? 'none' : 'pulse 1.5s ease-in-out infinite',
            }} />
            {wsConnected ? 'Real-time' : 'Disconnected'}
          </div>
        </div>
      </div>

      {/* ── Stats cards ── */}
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
        <div className="stat-card">
          <div className="stat-card-icon" style={{ background: 'rgba(59,130,246,0.15)', color: '#3B82F6' }}>📊</div>
          <div className="stat-card-value">{scanStats?.totalScans ?? 0}</div>
          <div className="stat-card-label">Всего сканирований</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-icon" style={{ background: 'rgba(255,68,68,0.15)', color: '#ff4444' }}>⚠️</div>
          <div className="stat-card-value">{scanStats?.totalSuspicious ?? 0}</div>
          <div className="stat-card-label">Найдено угроз</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-icon" style={{ background: 'rgba(34,197,94,0.15)', color: '#22c55e' }}>🔍</div>
          <div className="stat-card-value">{scanStats?.totalScanned ?? 0}</div>
          <div className="stat-card-label">Файлов проверено</div>
        </div>
      </div>

      {/* ── Charts Section ── */}
      {!scanLoading && scanStats && (
        <>
          <div className="stats-grid" style={{ gridTemplateColumns: '1fr 1fr', marginBottom: 20 }}>
            <div className="table-container">
              <div className="table-header"><h3>Статистика сканирований</h3></div>
              <div style={{ padding: 16 }}>
                {scanStats.totalScans > 0 ? (
                  <div style={{ height: 240 }}>
                    <Bar data={dayBarChartData} options={chartOptions} />
                  </div>
                ) : (
                  <div className="table-empty" style={{ padding: 40 }}>
                    <div className="table-empty-icon">📊</div>
                    <p>Нет данных сканирований</p>
                    <p style={{ fontSize: 13, marginTop: 4, color: 'var(--text-muted)' }}>
                      Данные появятся после того, как пользователи начнут сканировать систему
                    </p>
                  </div>
                )}
              </div>
            </div>
            <div className="table-container">
              <div className="table-header"><h3>По режимам</h3></div>
              <div style={{ padding: 16 }}>
                <div style={{ height: 240, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  {scanStats.byMode.length > 0 ? (
                    <div style={{ width: 220, height: 220 }}>
                      <Doughnut data={modeChartData} options={doughnutOptions} />
                    </div>
                  ) : (
                    <div className="table-empty" style={{ padding: 20 }}>
                      <div className="table-empty-icon">📊</div>
                      <p style={{ fontSize: 13 }}>Нет данных</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Recent scans */}
          {scanStats.recent.length > 0 && (
            <div className="table-container" style={{ marginBottom: 20 }}>
              <div className="table-header">
                <h3>Последние сканирования</h3>
                <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>{scanStats.totalScans} всего</span>
              </div>
              <table>
                <thead>
                  <tr>
                    <th>Пользователь</th>
                    <th>Режим</th>
                    <th>Проверено</th>
                    <th>Угрозы</th>
                    <th>Дата</th>
                  </tr>
                </thead>
                <tbody>
                  {scanStats.recent.slice(0, 10).map(r => (
                    <tr key={r.id}>
                      <td style={{ fontWeight: 500 }}>{r.pc_username}</td>
                      <td>
                        <span className="badge badge-pending" style={{ fontSize: 11 }}>
                          {r.mode}
                        </span>
                      </td>
                      <td>{r.total_scanned}</td>
                      <td>
                        <span style={{ color: r.suspicious_files > 0 ? '#ff6b6b' : '#22c55e', fontWeight: 600 }}>
                          {r.suspicious_files > 0 ? `⚠ ${r.suspicious_files}` : '✓ 0'}
                        </span>
                      </td>
                      <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                        {new Date(r.created_at).toLocaleString('ru-RU')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {/* ── Recent requests ── */}
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

      {/* ── Recent tokens ── */}
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

      {/* ── Toast notifications ── */}
      {toasts.length > 0 && (
        <div className="toast-container">
          {toasts.map((t, i) => (
            <ToastItem key={i} toast={t} onDone={() => removeToast(i)} />
          ))}
        </div>
      )}
    </div>
  )
}
