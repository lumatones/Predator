import { useState, useEffect, useRef, type ReactNode, memo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useAuth } from '../App'
import {
  getSuspiciousHashes, approveHash, rejectHash,
  getScanResultHashes, confirmHashFromScan,
  type SuspiciousHash, type ScanResultHash,
} from '../api'
import HashRow from '../components/HashRow'
import HashDetailModal from '../components/HashDetailModal'
import { Search, ShieldAlert, Clock, Check, X } from 'lucide-react'
import { SkeletonTable } from '../components/Skeleton'
import { smoothEase } from '../constants'

interface TabDef {
  key: string
  label: string
  icon: ReactNode
}

const TABS: TabDef[] = [
  { key: 'pending', label: 'На проверке', icon: <Clock size={14} /> },
  { key: 'confirmed', label: 'Подтверждённые', icon: <Check size={14} /> },
  { key: 'false_positive', label: 'Ложные', icon: <X size={14} /> },
  { key: 'scan_results', label: 'Из сканов', icon: <Search size={14} /> },
]

export default memo(function SuspiciousHashes() {
  const { auth } = useAuth()
  const [tab, setTab] = useState<string>('pending')
  const [hashes, setHashes] = useState<(SuspiciousHash | ScanResultHash)[]>([])
  const [scanResultsTotal, setScanResultsTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [confettiId, setConfettiId] = useState<string | number | null>(null)
  const [glowId, setGlowId] = useState<string | number | null>(null)
  const [rejectingId, setRejectingId] = useState<string | number | null>(null)
  const [selectedHash, setSelectedHash] = useState<SuspiciousHash | ScanResultHash | null>(null)
  const confettiTimer = useRef<ReturnType<typeof setTimeout>>(undefined)
  const glowTimer = useRef<ReturnType<typeof setTimeout>>(undefined)
  const rejectTimer = useRef<ReturnType<typeof setTimeout>>(undefined)

  useEffect(() => {
    return () => {
      if (confettiTimer.current) clearTimeout(confettiTimer.current)
      if (glowTimer.current) clearTimeout(glowTimer.current)
      if (rejectTimer.current) clearTimeout(rejectTimer.current)
    }
  }, [])

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

  const triggerConfetti = (id: string | number) => {
    setConfettiId(id)
    setGlowId(id)
    confettiTimer.current = setTimeout(() => setConfettiId(null), 800)
    glowTimer.current = setTimeout(() => setGlowId(null), 1200)
  }

  const triggerReject = (id: string | number) => {
    setRejectingId(id)
    rejectTimer.current = setTimeout(() => setRejectingId(null), 600)
  }

  const handleApprove = async (id: number) => {
    if (!auth) return
    try {
      await approveHash(auth.token, id)
      triggerConfetti(id)
      load(tab)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка')
    }
  }

  const handleReject = async (id: number) => {
    if (!auth) return
    try {
      await rejectHash(auth.token, id)
      triggerReject(id)
      load(tab)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка')
    }
  }

  const handleConfirmFromScan = async (sha256: string, fileName: string, fileSize: number) => {
    if (!auth) return
    try {
      await confirmHashFromScan(auth.token, sha256, fileName, fileSize)
      triggerConfetti(sha256)
      load(tab)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка')
    }
  }

  const isScanTab = tab === 'scan_results'

  const rowId = (h: SuspiciousHash | ScanResultHash) => (isScanTab ? (h as ScanResultHash).sha256 : (h as SuspiciousHash).id)

  const handleRowClick = (h: SuspiciousHash | ScanResultHash) => {
    setSelectedHash(h)
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

      <div className="hashes-segmented-tabs">
        {TABS.map(t => (
          <button
            key={t.key}
            className={`hashes-tab ${tab === t.key ? 'active' : ''}`}
            onClick={() => setTab(t.key)}
          >
            {tab === t.key && (
              <motion.div className="hashes-tab-indicator" layoutId="hashes-tab-indicator" />
            )}
            <span className="hashes-tab-content">
              {t.icon} {t.label}
              {t.key === 'scan_results' && scanResultsTotal > 0 && (
                <span className="hashes-tab-count">{scanResultsTotal}</span>
              )}
            </span>
          </button>
        ))}
      </div>

      {error && (
        <div className="history-error">
          <ShieldAlert size={16} />
          {error}
        </div>
      )}

      <AnimatePresence mode="wait">
        {loading ? (
          <motion.div
            key="loading"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <div className="table-container hash-table-container">
              <SkeletonTable rows={6} cols={8} />
            </div>
          </motion.div>
        ) : hashes.length === 0 ? (
          <motion.div
            key="empty"
            className="table-container"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.3, ease: smoothEase }}
          >
            <div className="table-empty hash-empty">
              <div className="table-empty-icon"><Search size={40} /></div>
              <p>Нет хешей в статусе «{TABS.find(t => t.key === tab)?.label}»</p>
              <p>
                {tab === 'pending'
                  ? 'Хеши появляются после того, как пользователи запускают сканирование и находят подозрительные файлы'
                  : tab === 'scan_results'
                    ? 'Хеши появятся после того, как пользователи отправят результаты сканирования'
                    : 'Подтверждённые хеши автоматически попадают в базу и используются при проверках'}
              </p>
            </div>
          </motion.div>
        ) : (
          <motion.div
            key="table"
            className="table-container hash-table-container"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3, ease: smoothEase }}
          >
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
                  <th>{isScanTab ? 'Последний раз' : 'Дата'}</th>
                  <th style={{ width: 220 }}>Действия</th>
                </tr>
              </thead>
              <tbody>
                {hashes.map((h, idx) => {
                  const id = rowId(h)
                  return (
                    <HashRow
                      key={isScanTab ? `scan-${id}-${idx}` : `hash-${id}`}
                      data={h}
                      isScan={isScanTab}
                      tab={tab}
                      index={idx}
                      isGlowing={glowId === id}
                      isRejecting={rejectingId === id}
                      showConfetti={confettiId === id}
                      onApprove={handleApprove}
                      onReject={handleReject}
                      onConfirmFromScan={handleConfirmFromScan}
                      onClick={() => handleRowClick(h)}
                    />
                  )
                })}
              </tbody>
            </table>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Hash Detail Modal */}
      <HashDetailModal
        data={selectedHash}
        isScan={isScanTab}
        onClose={() => setSelectedHash(null)}
        onApprove={tab === 'pending' ? handleApprove : undefined}
        onReject={tab === 'pending' ? handleReject : undefined}
        onConfirmFromScan={isScanTab ? handleConfirmFromScan : undefined}
      />
    </div>
  )
})
