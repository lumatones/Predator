import { useState, useEffect, useCallback, useMemo, memo } from 'react'
import { useAuth } from '../App'
import { getDashboardStats, getScanStats, type DashboardStats, type ScanStats } from '../api'
import { io, Socket } from 'socket.io-client'
import { motion } from 'framer-motion'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as ReTooltip,
  PieChart, Pie, Cell, ResponsiveContainer,
} from 'recharts'
import {
  Clock, Key, UserCheck, Activity, AlertTriangle, Search,
  Inbox, BarChart3, PieChart as PieChartIcon, Wifi, WifiOff,
  type LucideIcon,
} from 'lucide-react'
import AnimatedNumber from '../components/AnimatedNumber'
import { SkeletonStatCard, SkeletonTable } from '../components/Skeleton'
import { useToasts, ToastContainer, type ToastType } from '../components/Toast'
import { springEase } from '../constants'

const DEV = import.meta.env.DEV

export default memo(function Dashboard() {
  const { auth } = useAuth()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [scanStats, setScanStats] = useState<ScanStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [scanLoading, setScanLoading] = useState(true)
  const [error, setError] = useState('')
  const { toasts, addToast, removeToast } = useToasts()
  const [wsConnected, setWsConnected] = useState(false)

  const WS_BASE = 'http://5.164.42.189:3001'

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

  // ── WebSocket connection (JWT-authenticated) ──

  useEffect(() => {
    if (!auth) return
    const token = auth.token // capture for TS narrowing

    let socket: Socket | null = null

    function connect() {
      socket = io(WS_BASE, {
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionAttempts: Infinity,
        reconnectionDelay: 2000,
        auth: { token }, // JWT for WS auth
      })

      socket.on('connect', () => {
        if (DEV) console.log('🔌 WebSocket connected:', socket?.id)
        setWsConnected(true)
        socket?.emit('join-admin')
        load()
        loadScanStats()
      })

      socket.on('disconnect', (reason) => {
        if (DEV) console.log('🔌 WebSocket disconnected:', reason)
        setWsConnected(false)
      })

      socket.on('connect_error', (err) => {
        if (DEV) console.log('🔌 WS connection error:', err.message)
        setWsConnected(false)
        addToast('error', 'Ошибка подключения к серверу реального времени')
      })

      // Handle WS auth errors from server (expired token, etc.)
      socket.on('error', (err: { code?: string; message?: string }) => {
        if (DEV) console.log('🔌 WS error:', err)
        if (err?.code === 'AUTH_REQUIRED') {
          addToast('error', 'Сессия истекла — обновите страницу')
        }
      })

      socket.on('request-update', (data) => {
        const msg = data.type === 'approved'
          ? `Запрос ${data.pcUsername} одобрен администратором ${data.admin}`
          : `Запрос ${data.pcUsername} отклонён администратором ${data.admin}`
        addToast('success', msg)
        load()
        loadScanStats()
      })

      socket.on('token-generated', (data) => {
        addToast('success', `Создано ${data.count} новых токенов администратором ${data.admin}`)
        loadScanStats()
      })

      socket.on('new-request', (data) => {
        addToast('warning', `Новый запрос на доступ от ${data.pcUsername} (ID: ${data.requestId})`)
        load()
      })

      socket.on('scan-result', (data) => {
        addToast('info', `Новое сканирование от ${data.pc_username}: режим ${data.mode}, ${data.suspicious_files} угроз`)
        loadScanStats()
      })
    }

    connect()

    return () => {
      if (socket) {
        socket.removeAllListeners()
        socket.disconnect()
      }
    }
  }, [auth, addToast])

  // ── Chart data ──

  const dayChartData = useMemo(() => {
    return (scanStats?.byDay || []).map(d => ({
      day: new Date(d.day).toLocaleDateString('ru-RU', { day: 'numeric', month: 'short' }),
      scans: d.cnt,
      threats: d.threats,
    }))
  }, [scanStats])

  const modeChartData = useMemo(() => {
    const colors: Record<string, string> = {
      files: '#ff4444', processes: '#3B82F6', cheats: '#F59E0B',
      dma: '#8B5CF6', extended: '#22c55e', network: '#06b6d4',
    }
    const names: Record<string, string> = {
      files: 'Файлы', processes: 'Процессы', cheats: 'Читы',
      dma: 'DMA', extended: 'Расширенный', network: 'Сеть',
    }
    return (scanStats?.byMode || []).map(m => ({
      name: names[m.mode] || m.mode,
      value: m.cnt,
      color: colors[m.mode] || '#3B82F6',
    }))
  }, [scanStats])

  // ── Stat cards ──

  const statCards = [
    { icon: Clock, color: 'yellow', value: stats?.pendingCount ?? 0, label: 'Ожидающих запросов' },
    { icon: Key, color: 'green', value: stats?.activeTokens ?? 0, label: 'Активных токенов' },
    { icon: UserCheck, color: 'red', value: stats?.usedTokens ?? 0, label: 'Использованных токенов' },
    { icon: Activity, color: 'blue', value: scanStats?.totalScans ?? 0, label: 'Всего сканирований' },
    { icon: AlertTriangle, color: 'red', value: scanStats?.totalSuspicious ?? 0, label: 'Найдено угроз' },
    { icon: Search, color: 'green', value: scanStats?.totalScanned ?? 0, label: 'Файлов проверено' },
  ]

  const containerVariants = {
    hidden: {},
    show: { transition: { staggerChildren: 0.08 } },
  }

  const cardVariants = {
    hidden: { opacity: 0, y: 16 },
    show: { opacity: 1, y: 0, transition: { duration: 0.4, ease: springEase } },
  }

  const rowVariants = {
    hidden: { opacity: 0, y: 8 },
    show: { opacity: 1, y: 0, transition: { duration: 0.3, ease: springEase } },
  }

  // ── Loading / error ──

  if (loading) {
    return (
      <div>
        <div className="page-header">
          <div>
            <h1>Панель управления</h1>
            <p>Сводка по системе авторизации и сканированиям Predator</p>
          </div>
        </div>
        <div className="stats-grid">
          {Array.from({ length: 6 }).map((_, i) => <SkeletonStatCard key={i} />)}
        </div>
        <div className="stats-grid dashboard-charts">
          <div className="table-container chart-card"><SkeletonTable rows={5} cols={4} /></div>
          <div className="table-container chart-card"><SkeletonTable rows={5} cols={4} /></div>
        </div>
        <div className="table-container dashboard-table"><SkeletonTable rows={5} cols={5} /></div>
        <div className="table-container dashboard-table"><SkeletonTable rows={4} cols={3} /></div>
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
        <div className="page-actions">
          <div className={`ws-status ${wsConnected ? 'connected' : 'disconnected'}`}>
            {wsConnected ? <Wifi size={14} /> : <WifiOff size={14} />}
            <span>{wsConnected ? 'Real-time' : 'Disconnected'}</span>
          </div>
        </div>
      </div>

      {/* ── Stats cards ── */}
      <motion.div
        className="stats-grid"
        variants={containerVariants}
        initial="hidden"
        animate="show"
      >
        {statCards.map((card, idx) => {
          const Icon = card.icon
          return (
            <motion.div
              key={card.label}
              className="stat-card"
              variants={cardVariants}
              whileHover={{ scale: 1.02, y: -2, transition: { duration: 0.2 } }}
            >
              <div className={`stat-card-icon ${card.color}`}>
                <Icon size={20} />
              </div>
              <div className="stat-card-value">
                <AnimatedNumber value={card.value} />
              </div>
              <div className="stat-card-label">{card.label}</div>
            </motion.div>
          )
        })}
      </motion.div>

      {/* ── Charts ── */}
      {!scanLoading && scanStats && (
        <motion.div
          className="stats-grid dashboard-charts"
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.2, ease: springEase }}
        >
          <div className="table-container chart-card">
            <div className="table-header"><h3>Статистика сканирований</h3></div>
            <div style={{ padding: 16 }}>
              {scanStats.totalScans > 0 ? (
                <div style={{ height: 260 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={dayChartData} margin={{ top: 10, right: 20, left: -10, bottom: 0 }}>
                      <defs>
                        <linearGradient id="scansGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.35} />
                          <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="threatsGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ff4444" stopOpacity={0.35} />
                          <stop offset="95%" stopColor="#ff4444" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid stroke="rgba(255,255,255,0.03)" vertical={false} />
                      <XAxis dataKey="day" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                      <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                      <ReTooltip
                        contentStyle={{ background: 'rgba(12,12,26,0.9)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8 }}
                        itemStyle={{ fontSize: 12 }}
                      />
                      <Area type="monotone" dataKey="scans" stroke="#3B82F6" strokeWidth={2} fill="url(#scansGradient)" animationDuration={1500} />
                      <Area type="monotone" dataKey="threats" stroke="#ff4444" strokeWidth={2} fill="url(#threatsGradient)" animationDuration={1500} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <EmptyState icon={BarChart3} title="Нет данных сканирований" subtitle="Данные появятся после того, как пользователи начнут сканировать систему" />
              )}
            </div>
          </div>

          <div className="table-container chart-card">
            <div className="table-header"><h3>По режимам</h3></div>
            <div style={{ padding: 16 }}>
              {modeChartData.length > 0 ? (
                <div style={{ height: 260, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={modeChartData}
                        dataKey="value"
                        nameKey="name"
                        innerRadius={60}
                        outerRadius={90}
                        paddingAngle={2}
                        animationDuration={1500}
                      >
                        {modeChartData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} stroke="rgba(0,0,0,0.3)" />
                        ))}
                      </Pie>
                      <ReTooltip
                        contentStyle={{ background: 'rgba(12,12,26,0.9)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8 }}
                        itemStyle={{ fontSize: 12 }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <EmptyState icon={PieChartIcon} title="Нет данных" subtitle="Статистика по режимам недоступна" />
              )}
            </div>
          </div>
        </motion.div>
      )}

      {/* ── Recent scans ── */}
      <motion.div
        className="table-container dashboard-table"
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.3, ease: springEase }}
      >
        <div className="table-header">
          <h3>Последние сканирования</h3>
          <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>{scanStats?.totalScans ?? 0} всего</span>
        </div>
        {scanStats && scanStats.recent.length > 0 ? (
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
              {scanStats.recent.slice(0, 10).map((r, i) => (
                <motion.tr
                  key={r.id}
                  variants={rowVariants}
                  initial="hidden"
                  animate="show"
                  transition={{ delay: i * 0.05, duration: 0.3, ease: springEase }}
                >
                  <td style={{ fontWeight: 500 }}>{r.pc_username}</td>
                  <td><span className="badge badge-pending" style={{ fontSize: 11 }}>{r.mode}</span></td>
                  <td>{r.total_scanned}</td>
                  <td>
                    <span className={`threat-count ${r.suspicious_files > 0 ? 'active' : ''}`}>
                      {r.suspicious_files > 0 ? r.suspicious_files : '0'}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                    {new Date(r.created_at).toLocaleString('ru-RU')}
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState icon={Inbox} title="Нет сканирований" subtitle="Последние сканирования появятся здесь" />
        )}
      </motion.div>

      {/* ── Recent requests ── */}
      <motion.div
        className="table-container dashboard-table"
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.35, ease: springEase }}
      >
        <div className="table-header"><h3>Последние запросы</h3></div>
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
              {stats.recentRequests.map((r, i) => (
                <motion.tr
                  key={r.id}
                  variants={rowVariants}
                  initial="hidden"
                  animate="show"
                  transition={{ delay: i * 0.05, duration: 0.3, ease: springEase }}
                >
                  <td style={{ fontWeight: 500 }}>{r.pc_username}</td>
                  <td>
                    <span className={`badge badge-${r.status}`}>
                      {r.status === 'pending' ? 'Ожидает' : r.status === 'approved' ? 'Одобрен' : 'Отклонён'}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }}>
                    {new Date(r.created_at).toLocaleString('ru-RU')}
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState icon={Inbox} title="Нет запросов на доступ" subtitle="Запросы появятся после обращения пользователей" />
        )}
      </motion.div>

      {/* ── Recent tokens ── */}
      <motion.div
        className="table-container dashboard-table"
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.4, ease: springEase }}
      >
        <div className="table-header"><h3>Последние токены</h3></div>
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
              {stats.recentTokens.map((t, i) => (
                <motion.tr
                  key={t.id}
                  variants={rowVariants}
                  initial="hidden"
                  animate="show"
                  transition={{ delay: i * 0.05 }}
                >
                  <td><span className="token-code token-code-sm">{t.code_display}</span></td>
                  <td>
                    <span className={`badge ${t.is_active ? 'badge-active' : 'badge-inactive'}`}>
                      {t.is_active ? 'Активен' : t.used_by ? 'Использован' : 'Отозван'}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }}>
                    {new Date(t.created_at).toLocaleString('ru-RU')}
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState icon={Inbox} title="Токены ещё не созданы" subtitle="Сгенерируйте токены для пользователей" />
        )}
      </motion.div>

      {/* ── Toasts ── */}
      <ToastContainer toasts={toasts} onRemove={removeToast} />
    </div>
  )
})

// ── Empty state helper ──

interface EmptyStateProps {
  icon: LucideIcon
  title: string
  subtitle: string
}

function EmptyState({ icon: Icon, title, subtitle }: EmptyStateProps) {
  return (
    <div className="table-empty">
      <Icon size={36} style={{ marginBottom: 12, opacity: 0.5 }} />
      <p>{title}</p>
      <p style={{ fontSize: 13, marginTop: 4, color: 'var(--text-muted)' }}>{subtitle}</p>
    </div>
  )
}
