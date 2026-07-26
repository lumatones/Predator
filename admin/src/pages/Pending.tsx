import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { CheckCircle, User, Check, X } from 'lucide-react'
import { useAuth } from '../App'
import { getPending, approveRequest, rejectRequest, PendingRequest } from '../api'
import CountdownCircle from '../components/CountdownCircle'
import { SkeletonPendingCard } from '../components/Skeleton'

// ── Toast helpers ──

type ToastType = 'success' | 'error'

interface Toast {
  id: number
  type: ToastType
  message: string
}

const springEase = [0.16, 1, 0.3, 1] as const

function ToastItem({ toast, onDone }: { toast: Toast; onDone: () => void }) {
  useEffect(() => {
    const timer = setTimeout(onDone, 4000)
    return () => clearTimeout(timer)
  }, [onDone])

  return (
    <motion.div
      className={`toast toast-${toast.type}`}
      initial={{ x: 80, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: 80, opacity: 0 }}
      transition={{ duration: 0.25, ease: springEase }}
    >
      {toast.message}
    </motion.div>
  )
}

export default function Pending() {
  const { auth } = useAuth()
  const [requests, setRequests] = useState<PendingRequest[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [toasts, setToasts] = useState<Toast[]>([])
  const [actionId, setActionId] = useState<number | null>(null)
  const [exitAction, setExitAction] = useState<{ id: number; action: 'approve' | 'reject' } | null>(null)
  const toastId = useRef(0)

  const showToast = (type: ToastType, message: string) => {
    const id = ++toastId.current
    setToasts(prev => [...prev, { id, type, message }])
  }

  const removeToast = (id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id))
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
    setExitAction({ id, action: 'approve' })
    try {
      await approveRequest(auth.token, id)
      showToast('success', 'Запрос одобрен')
      setRequests(prev => prev.filter(r => r.id !== id))
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Ошибка')
    } finally {
      setActionId(null)
      setExitAction(null)
    }
  }

  async function handleReject(id: number) {
    if (!auth) return
    setActionId(id)
    setExitAction({ id, action: 'reject' })
    try {
      await rejectRequest(auth.token, id)
      showToast('success', 'Запрос отклонён')
      setRequests(prev => prev.filter(r => r.id !== id))
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Ошибка')
    } finally {
      setActionId(null)
      setExitAction(null)
    }
  }

  const containerVariants = {
    hidden: {},
    show: { transition: { staggerChildren: 0.06 } },
  }

  const cardVariants = {
    hidden: { opacity: 0, y: 20, scale: 0.96 },
    show: { opacity: 1, y: 0, scale: 1, transition: { duration: 0.35, ease: springEase } },
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
        <div className="pending-error">
          {error}
        </div>
      )}

      {loading && !requests.length ? (
        <div className="pending-grid">
          {Array.from({ length: 6 }).map((_, i) => <SkeletonPendingCard key={i} />)}
        </div>
      ) : requests.length === 0 ? (
        <motion.div
          className="pending-empty"
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.4, ease: springEase }}
        >
          <CheckCircle size={48} className="pending-empty-icon" />
          <h3>Все запросы обработаны</h3>
          <p>Новые запросы появятся здесь</p>
        </motion.div>
      ) : (
        <motion.div
          className="pending-grid"
          variants={containerVariants}
          initial="hidden"
          animate="show"
        >
          <AnimatePresence mode="popLayout">
            {requests.map(r => {
              const isApproving = exitAction?.id === r.id && exitAction.action === 'approve'
              const isRejecting = exitAction?.id === r.id && exitAction.action === 'reject'
              return (
              <motion.div
                key={r.id}
                className={`pending-card ${isApproving ? 'exiting-approve' : ''} ${isRejecting ? 'exiting-reject' : ''}`}
                variants={cardVariants}
                layout
                whileHover={{ y: -4, transition: { duration: 0.2 } }}
                exit={
                  isApproving
                    ? { x: 200, opacity: 0, transition: { duration: 0.35, ease: springEase } }
                    : isRejecting
                    ? { x: [-10, 10, -10, -200], opacity: 0, transition: { duration: 0.45, ease: springEase } }
                    : { opacity: 0, transition: { duration: 0.2 } }
                }
              >
                <div className="pending-card-header">
                  <div className="pending-avatar">
                    <User size={20} />
                  </div>
                  <div className="pending-meta">
                    <h4 className="pending-username">{r.pc_username}</h4>
                    <span className="pending-id">#{r.id}</span>
                  </div>
                </div>

                <div className="pending-card-body">
                  <div className="pending-countdown">
                    {r.expires_at ? (
                      <CountdownCircle expiresAt={r.expires_at} createdAt={r.created_at} size={64} stroke={5} />
                    ) : (
                      <span className="pending-no-expiry">Без срока</span>
                    )}
                  </div>
                  <div className="pending-created">
                    <span>Запрос от</span>
                    <time>{new Date(r.created_at).toLocaleString('ru-RU')}</time>
                  </div>
                </div>

                <div className="pending-card-actions">
                  <button
                    className="btn btn-green btn-sm pending-approve"
                    onClick={() => handleApprove(r.id)}
                    disabled={actionId === r.id}
                  >
                    <Check size={14} />
                    {actionId === r.id ? '...' : 'Одобрить'}
                  </button>
                  <button
                    className="btn btn-danger btn-sm pending-reject"
                    onClick={() => handleReject(r.id)}
                    disabled={actionId === r.id}
                  >
                    <X size={14} />
                    {actionId === r.id ? '...' : 'Отклонить'}
                  </button>
                </div>
              </motion.div>
            )})}
          </AnimatePresence>
        </motion.div>
      )}

      {/* Toasts */}
      <div className="toast-container">
        <AnimatePresence>
          {toasts.map(t => (
            <ToastItem key={t.id} toast={t} onDone={() => removeToast(t.id)} />
          ))}
        </AnimatePresence>
      </div>
    </div>
  )
}
