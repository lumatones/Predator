import { useState, useEffect, memo } from 'react'
import { useAuth } from '../App'
import { getSafeFilesStats, type SafeFilesStats } from '../api'
import { motion } from 'framer-motion'
import { Shield, ShieldCheck } from 'lucide-react'
import AnimatedNumber from '../components/AnimatedNumber'
import { SkeletonStatCard, SkeletonTable } from '../components/Skeleton'
import { springEase } from '../constants'

export default memo(function SafeFiles() {
  const { auth } = useAuth()
  const [stats, setStats] = useState<SafeFilesStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = async () => {
    if (!auth) return
    setLoading(true)
    setError('')
    try {
      const data = await getSafeFilesStats(auth.token)
      setStats(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка загрузки')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [auth])

  const containerVariants = {
    hidden: {},
    show: { transition: { staggerChildren: 0.08 } },
  }

  const cardVariants = {
    hidden: { opacity: 0, y: 16 },
    show: { opacity: 1, y: 0, transition: { duration: 0.4, ease: springEase } },
  }

  const statCards = [
    {
      icon: ShieldCheck,
      color: 'green',
      value: stats?.totalFiles ?? 0,
      label: 'Всего безопасных файлов',
    },
    {
      icon: Shield,
      color: 'blue',
      value: stats?.highConfidence ?? 0,
      label: 'Высокая уверенность (≥50)',
    },
    {
      icon: Shield,
      color: 'yellow',
      value: stats?.mediumConfidence ?? 0,
      label: 'Средняя уверенность (≥10)',
    },
  ]

  if (loading) {
    return (
      <div>
        <div className="page-header">
          <div>
            <h1>Безопасные файлы</h1>
            <p>Community Whitelist — краудсорсинговая база безопасных файлов</p>
          </div>
        </div>
        <div className="stats-grid">
          {Array.from({ length: 3 }).map((_, i) => <SkeletonStatCard key={i} />)}
        </div>
        <div className="table-container" style={{ marginTop: 24 }}>
          <SkeletonTable rows={8} cols={5} />
        </div>
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
          <h1>Безопасные файлы</h1>
          <p>
            Community Whitelist — база файлов, подтверждённых как безопасные
            через краудсорсинг. Все устройства Predator синхронизируют этот список
            при запуске.
          </p>
        </div>
      </div>

      {/* ── Stats cards ── */}
      <motion.div
        className="stats-grid"
        variants={containerVariants}
        initial="hidden"
        animate="show"
      >
        {statCards.map((card) => {
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

      {/* ── Top confirmed ── */}
      {stats?.topConfirmed && stats.topConfirmed.length > 0 && (
        <motion.div
          className="table-container"
          style={{ marginTop: 24 }}
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.2, ease: springEase }}
        >
          <div className="table-header">
            <h3>Наиболее подтверждённые файлы</h3>
            <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>
              Больше всего устройств подтвердили
            </span>
          </div>
          <table>
            <thead>
              <tr>
                <th>Имя файла</th>
                <th>Частичный Hash</th>
                <th>Размер</th>
                <th>Подтверждений</th>
                <th>Последний раз</th>
              </tr>
            </thead>
            <tbody>
              {stats.topConfirmed.map((entry, i) => (
                <motion.tr
                  key={entry.partialHash}
                  variants={cardVariants}
                  initial="hidden"
                  animate="show"
                  transition={{ delay: i * 0.05 }}
                >
                  <td style={{ fontWeight: 500 }}>{entry.fileName || '—'}</td>
                  <td>
                    <code style={{ fontSize: 11, opacity: 0.7 }}>
                      {entry.partialHash.slice(0, 16)}...
                    </code>
                  </td>
                  <td>{(entry.fileSize / 1024).toFixed(1)} KB</td>
                  <td>
                    <span className="badge badge-active">
                      {entry.confirmCount}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                    {new Date(entry.lastSeen).toLocaleString('ru-RU')}
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </motion.div>
      )}

      {/* ── Recent safe files ── */}
      <motion.div
        className="table-container"
        style={{ marginTop: 24 }}
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.3, ease: springEase }}
      >
        <div className="table-header">
          <h3>Последние добавленные</h3>
          <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>
            {stats?.recent?.length ?? 0} из {stats?.totalFiles ?? 0}
          </span>
        </div>
        {stats?.recent && stats.recent.length > 0 ? (
          <table>
            <thead>
              <tr>
                <th>Имя файла</th>
                <th>Частичный Hash</th>
                <th>Размер</th>
                <th>Подтверждений</th>
                <th>Добавлен</th>
                <th>Последний раз</th>
              </tr>
            </thead>
            <tbody>
              {stats.recent.slice(0, 20).map((entry, i) => (
                <motion.tr
                  key={entry.partialHash + i}
                  variants={cardVariants}
                  initial="hidden"
                  animate="show"
                  transition={{ delay: i * 0.03 }}
                >
                  <td style={{ fontWeight: 500 }}>{entry.fileName || '—'}</td>
                  <td>
                    <code style={{ fontSize: 11, opacity: 0.7 }}>
                      {entry.partialHash.slice(0, 16)}...
                    </code>
                  </td>
                  <td>{(entry.fileSize / 1024).toFixed(1)} KB</td>
                  <td>
                    <span className={`badge ${entry.confirmCount >= 50 ? 'badge-active' : entry.confirmCount >= 10 ? 'badge-pending' : 'badge-inactive'}`}>
                      {entry.confirmCount}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                    {new Date(entry.createdAt || entry.lastSeen).toLocaleString('ru-RU')}
                  </td>
                  <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                    {new Date(entry.lastSeen).toLocaleString('ru-RU')}
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="table-empty">
            <Shield size={40} style={{ opacity: 0.5, marginBottom: 12 }} />
            <p>База безопасных файлов пуста</p>
            <p style={{ fontSize: 13, marginTop: 4, color: 'var(--text-muted)' }}>
              Данные появятся после того, как пользователи начнут сканирование и
              отправят safe-файлы на сервер
            </p>
          </div>
        )}
      </motion.div>
    </div>
  )
})
