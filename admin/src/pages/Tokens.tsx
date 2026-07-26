import { useState, useEffect, useRef, memo } from 'react'
import { motion } from 'framer-motion'
import { useAuth } from '../App'
import { getTokens, generateTokens, revokeToken, type Token } from '../api'
import SpeedometerGauge from '../components/SpeedometerGauge'
import TypewriterText from '../components/TypewriterText'
import MatrixRain from '../components/MatrixRain'
import { SkeletonStatCard, SkeletonTable } from '../components/Skeleton'
import {
  Key,
  Users,
  Database,
  Copy,
  Check,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from 'lucide-react'
import { springEase } from '../constants'

const AUTO_HIDE_MS = 8000

export default memo(function Tokens() {
  const { auth } = useAuth()
  const [tokens, setTokens] = useState<Token[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null)
  const [genCount, setGenCount] = useState(1)
  const [generating, setGenerating] = useState(false)
  const [generatedCodes, setGeneratedCodes] = useState<string[] | null>(null)
  const [copiedId, setCopiedId] = useState<number | null>(null)
  const [autoHideProgress, setAutoHideProgress] = useState(100)
  const toastTimer = useRef<ReturnType<typeof setTimeout>>(undefined)
  const genTimeout = useRef<ReturnType<typeof setTimeout>>(undefined)
  const progressInterval = useRef<ReturnType<typeof setInterval>>(undefined)
  const copyTimeout = useRef<ReturnType<typeof setTimeout>>(undefined)

  useEffect(() => {
    return () => {
      if (toastTimer.current) clearTimeout(toastTimer.current)
      if (genTimeout.current) clearTimeout(genTimeout.current)
      if (progressInterval.current) clearInterval(progressInterval.current)
      if (copyTimeout.current) clearTimeout(copyTimeout.current)
    }
  }, [])

  function showToast(type: 'success' | 'error', message: string) {
    setToast({ type, message })
    if (toastTimer.current) clearTimeout(toastTimer.current)
    toastTimer.current = setTimeout(() => setToast(null), 4000)
  }

  function clearGenerated() {
    setGeneratedCodes(null)
    setAutoHideProgress(100)
    if (progressInterval.current) clearInterval(progressInterval.current)
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
    setAutoHideProgress(100)
    if (progressInterval.current) clearInterval(progressInterval.current)
    try {
      const result = await generateTokens(auth.token, genCount)
      setGeneratedCodes(result.tokens)
      showToast('success', `Создано ${result.tokens.length} токен(ов)`)
      if (genTimeout.current) clearTimeout(genTimeout.current)
      genTimeout.current = setTimeout(clearGenerated, AUTO_HIDE_MS)
      startAutoHideProgress()
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Ошибка генерации')
    } finally {
      setGenerating(false)
    }
  }

  function startAutoHideProgress() {
    if (progressInterval.current) clearInterval(progressInterval.current)
    setAutoHideProgress(100)
    const step = 100 / (AUTO_HIDE_MS / 100)
    progressInterval.current = setInterval(() => {
      setAutoHideProgress(prev => {
        if (prev <= step) {
          if (progressInterval.current) clearInterval(progressInterval.current)
          return 0
        }
        return prev - step
      })
    }, 100)
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
    try { navigator.clipboard.writeText(code) } catch { /* clipboard unavailable */ }
    setCopiedId(id)
    if (copyTimeout.current) clearTimeout(copyTimeout.current)
    copyTimeout.current = setTimeout(() => setCopiedId(null), 2000)
  }

  const activeTokens = tokens.filter(t => t.is_active)
  const usedTokens = tokens.filter(t => !t.is_active && t.used_by)
  const revokedTokens = tokens.filter(t => !t.is_active && !t.used_by)

  const cardVariants = {
    hidden: { opacity: 0, y: 16 },
    visible: (i: number) => ({
      opacity: 1,
      y: 0,
      transition: { delay: i * 0.08, duration: 0.4, ease: springEase },
    }),
  }

  const rowVariants = {
    hidden: { opacity: 0, x: -12 },
    visible: (i: number) => ({
      opacity: 1,
      x: 0,
      transition: { delay: i * 0.04, duration: 0.35, ease: springEase },
    }),
  }

  return (
    <div className="tokens-page">
      <MatrixRain />

      <div className="page-header">
        <div>
          <h1>Управление токенами</h1>
          <p>Создание и управление токенами доступа</p>
        </div>
        <div className="page-actions">
          <button className="btn btn-outline" onClick={load} disabled={loading}>
            <RefreshCw size={16} className={loading ? 'spin' : ''} />
            {loading ? 'Загрузка...' : 'Обновить'}
          </button>
        </div>
      </div>

      {/* Speedometer + stat cards */}
      <div className="stats-grid token-stats-grid">
        <motion.div
          className="stat-card token-speedometer-card"
          initial="hidden"
          animate="visible"
          custom={0}
          variants={cardVariants}
        >
          <div className="token-speedometer-wrap">
            <SpeedometerGauge value={activeTokens.length} max={10} size={200} strokeWidth={14} />
          </div>
          <div className="token-speedometer-meta">
            <div className="stat-card-label">Запас токенов</div>
            <p className="token-speedometer-hint">
              {activeTokens.length < 2
                ? 'Критический запас — генерируйте новые'
                : activeTokens.length <= 5
                  ? 'Средний запас'
                  : 'Запас в норме'}
            </p>
          </div>
        </motion.div>

        <motion.div className="stat-card" initial="hidden" animate="visible" custom={1} variants={cardVariants}>
          <div className="stat-card-icon green"><Key size={20} /></div>
          <div className="stat-card-value">{activeTokens.length}</div>
          <div className="stat-card-label">Активных / {tokens.length}</div>
        </motion.div>

        <motion.div className="stat-card" initial="hidden" animate="visible" custom={2} variants={cardVariants}>
          <div className="stat-card-icon red"><Users size={20} /></div>
          <div className="stat-card-value">{usedTokens.length}</div>
          <div className="stat-card-label">Использовано</div>
        </motion.div>

        <motion.div className="stat-card" initial="hidden" animate="visible" custom={3} variants={cardVariants}>
          <div className="stat-card-icon yellow"><Database size={20} /></div>
          <div className="stat-card-value">{tokens.length}</div>
          <div className="stat-card-label">Всего</div>
        </motion.div>
      </div>

      {/* Generate form */}
      <motion.div
        className="table-container token-generate-card"
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.32, duration: 0.4, ease: springEase }}
      >
        <div className="table-header">
          <h3><Zap size={16} /> Создать токены</h3>
        </div>
        <div className="token-generate-body">
          <div className="token-generate-form">
            <label>Количество:</label>
            <input
              type="number"
              min={1}
              max={10}
              value={genCount}
              onChange={e => setGenCount(Math.min(10, Math.max(1, parseInt(e.target.value) || 1)))}
              className="token-count-input"
            />
            <button
              className="btn btn-primary token-generate-btn"
              onClick={handleGenerate}
              disabled={generating}
            >
              <span className="token-btn-progress" />
              {generating ? 'Генерация...' : 'Сгенерировать'}
            </button>
          </div>

          {generatedCodes && (
            <div className="generate-result token-generated-result">
              <div className="token-generated-header">
                <h4><ShieldCheck size={14} /> Созданные токены</h4>
                <span className="token-generated-timer">исчезнут через {Math.ceil(autoHideProgress / 12.5)}с</span>
              </div>
              <div className="token-generated-countdown">
                <div className="token-generated-bar" style={{ width: `${autoHideProgress}%` }} />
              </div>
              <div className="token-list">
                {generatedCodes.map((code, i) => (
                  <div key={i} className="token-item">
                    <TypewriterText text={code} speed={35} />
                    <button className="copy-btn" onClick={() => handleCopy(code, -1)}>
                      {copiedId === -1 ? <Check size={14} /> : <Copy size={14} />}
                      {copiedId === -1 ? 'Скопировано' : 'Копировать'}
                    </button>
                  </div>
                ))}
              </div>
              <p className="token-generated-hint">
                Эти токены будут показаны здесь ещё 8 секунд. Скопируйте их сейчас.
              </p>
            </div>
          )}
        </div>
      </motion.div>

      {error && (
        <motion.div
          className="token-error"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <ShieldAlert size={16} />
          {error}
        </motion.div>
      )}

      {/* Tokens list */}
      <motion.div
        className="table-container token-table-card"
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.44, duration: 0.4, ease: springEase }}
      >
        <div className="table-header">
          <h3>Все токены</h3>
          {tokens.length > 0 && <span className="token-table-count">{tokens.length} шт.</span>}
        </div>

      {loading && !tokens.length ? (
        <>
          <div className="stats-grid token-stats-grid">
            <SkeletonStatCard className="stat-card token-speedometer-card" />
            <SkeletonStatCard className="stat-card" />
            <SkeletonStatCard className="stat-card" />
            <SkeletonStatCard className="stat-card" />
          </div>
          <div className="table-container token-generate-card"><SkeletonTable rows={3} cols={3} /></div>
          <div className="table-container token-table-card"><SkeletonTable rows={6} cols={5} /></div>
        </>
      ) : tokens.length === 0 ? (
          <div className="table-empty token-empty">
            <div className="table-empty-icon"><Key size={40} /></div>
            <p>Токены ещё не созданы</p>
            <p>Используйте форму выше для создания первых токенов</p>
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
              {tokens.map((t, i) => (
                <motion.tr
                  key={t.id}
                  initial="hidden"
                  animate="visible"
                  custom={i}
                  variants={rowVariants}
                >
                  <td>
                    <span className="token-code">{t.code_display}</span>
                    <button
                      className="copy-btn token-copy-inline"
                      onClick={() => handleCopy(t.code_display, t.id)}
                      aria-label="Копировать токен"
                    >
                      {copiedId === t.id ? <Check size={14} /> : <Copy size={14} />}
                    </button>
                  </td>
                  <td>
                    <span className={`badge ${t.is_active ? 'badge-active' : 'badge-inactive'}`}>
                      {t.is_active ? 'Активен' : t.used_by ? 'Использован' : 'Отозван'}
                    </span>
                  </td>
                  <td className="token-cell-secondary">
                    {t.used_by ? (
                      <>
                        {t.used_by}
                        <span>{t.used_at ? new Date(t.used_at).toLocaleString('ru-RU') : ''}</span>
                      </>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="token-cell-secondary">
                    {new Date(t.created_at).toLocaleString('ru-RU')}
                    <span>{t.created_by_name}</span>
                  </td>
                  <td>
                    {t.is_active && (
                      <button className="btn btn-danger btn-sm" onClick={() => handleRevoke(t.id)}>
                        Отозвать
                      </button>
                    )}
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        )}
      </motion.div>

      {/* Toast */}
      {toast && (
        <div className="toast-container">
          <div className={`toast glass-toast toast-${toast.type}`}>
            <span
              className="toast-glow"
              style={{ background: toast.type === 'success' ? 'var(--green)' : '#ff6b6b' }}
            />
            <span className="toast-message">{toast.message}</span>
          </div>
        </div>
      )}
    </div>
  )
})
