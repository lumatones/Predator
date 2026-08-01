import { useEffect, useRef, useState, memo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  X, Copy, Check, Terminal, Calendar, User, HardDrive,
  FileCode, Shield, ShieldCheck, ShieldAlert, Hash,
  Activity, Clock, AlertTriangle, Fingerprint, FileWarning,
  ChevronDown, ChevronUp
} from 'lucide-react'
import type { SuspiciousHash, ScanResultHash } from '../api'

interface HashDetailModalProps {
  data: SuspiciousHash | ScanResultHash | null
  isScan: boolean
  onClose: () => void
  onApprove?: (id: number) => void
  onReject?: (id: number) => void
  onConfirmFromScan?: (sha256: string, fileName: string, fileSize: number) => void
}

const formatSize = (size: number) => {
  if (!size && size !== 0) return '—'
  return size > 1024 * 1024
    ? `${(size / (1024 * 1024)).toFixed(1)} MB`
    : `${(size / 1024).toFixed(0)} KB`
}

const getRiskColor = (score: number) => {
  if (score >= 70) return { color: '#ff4444', bg: 'rgba(255,68,68,0.15)', label: 'Высокий' }
  if (score >= 40) return { color: '#eab308', bg: 'rgba(234,179,8,0.15)', label: 'Средний' }
  return { color: '#22c55e', bg: 'rgba(34,197,94,0.15)', label: 'Низкий' }
}

const getStatusMeta = (status: string) => {
  switch (status) {
    case 'new': return { label: 'Новый', color: '#60a5fa', bg: 'rgba(59,130,246,0.15)' }
    case 'pending': return { label: 'На проверке', color: '#eab308', bg: 'rgba(234,179,8,0.15)' }
    case 'confirmed': return { label: 'Чит', color: '#22c55e', bg: 'rgba(34,197,94,0.15)' }
    case 'false_positive': return { label: 'Спам', color: '#ff6b6b', bg: 'rgba(255,68,68,0.15)' }
    default: return { label: status, color: '#64748b', bg: 'rgba(100,116,139,0.15)' }
  }
}

const DetailRow = memo(function DetailRow({
  icon,
  label,
  value,
  mono,
  highlight,
}: {
  icon: React.ReactNode
  label: string
  value: React.ReactNode
  mono?: boolean
  highlight?: boolean
}) {
  return (
    <div className={`hash-detail-row ${highlight ? 'hash-detail-row-highlight' : ''}`}>
      <div className="hash-detail-label">
        <span className="hash-detail-icon">{icon}</span>
        <span>{label}</span>
      </div>
      <div className={`hash-detail-value ${mono ? 'hash-detail-value-mono' : ''}`}>
        {value}
      </div>
    </div>
  )
})

function CopyButton({ text, label = 'Копировать' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    try {
      navigator.clipboard.writeText(text)
    } catch { /* fallback */ }
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <button className="hash-detail-copy-btn" onClick={handleCopy} title={label}>
      {copied ? <Check size={14} /> : <Copy size={14} />}
      {copied ? 'Скопировано' : label}
    </button>
  )
}

export default memo(function HashDetailModal({
  data,
  isScan,
  onClose,
  onApprove,
  onReject,
  onConfirmFromScan,
}: HashDetailModalProps) {
  const overlayRef = useRef<HTMLDivElement>(null)
  const [showFullSha, setShowFullSha] = useState(false)

  // Close on Escape
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKey)
    return () => window.removeEventListener('keydown', handleKey)
  }, [onClose])

  // Prevent body scroll
  useEffect(() => {
    document.body.style.overflow = 'hidden'
    return () => { document.body.style.overflow = '' }
  }, [])

  if (!data) return null

  const scanData = isScan ? (data as ScanResultHash) : null
  const susData = !isScan ? (data as SuspiciousHash) : null
  const riskMeta = susData ? getRiskColor(susData.risk_score) : null
  const statusMeta = getStatusMeta(data.status || (isScan ? 'new' : 'pending'))

  const shaShort = data.sha256.length > 32
    ? `${data.sha256.slice(0, 24)}...${data.sha256.slice(-8)}`
    : data.sha256

  const shaLines = data.sha256.match(/.{1,32}/g) || [data.sha256]

  return (
    <AnimatePresence>
      <motion.div
        ref={overlayRef}
        className="hash-detail-overlay"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.2 }}
        onClick={(e) => { if (e.target === overlayRef.current) onClose() }}
      >
        <motion.div
          className="hash-detail-modal"
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
        >
          {/* ── Header ── */}
          <div className="hash-detail-header">
            <div className="hash-detail-header-left">
              <div className="hash-detail-header-icon">
                <FileWarning size={22} />
              </div>
              <div>
                <h2 className="hash-detail-title">Детали сигнатуры</h2>
                <span className="hash-detail-subtitle">
                  {isScan ? 'Из результатов сканирования' : 'Из облачной базы'}
                </span>
              </div>
            </div>
            <button className="hash-detail-close-btn" onClick={onClose} aria-label="Закрыть">
              <X size={20} />
            </button>
          </div>

          {/* ── Body ── */}
          <div className="hash-detail-body">
            {/* Status bar */}
            <div className="hash-detail-status-bar">
              <div className="hash-detail-status-info" style={{ background: statusMeta.bg, color: statusMeta.color }}>
                <Shield size={14} />
                <span>{statusMeta.label}</span>
              </div>
              {susData && (
                <div className="hash-detail-risk-badge" style={{ background: riskMeta!.bg, color: riskMeta!.color }}>
                  <AlertTriangle size={14} />
                  <span>Риск: {riskMeta!.label} ({susData.risk_score})</span>
                </div>
              )}
              {scanData && (
                <div className="hash-detail-occurrence-badge">
                  <Activity size={14} />
                  <span>Найден {scanData.occurrences} раз(а)</span>
                </div>
              )}
            </div>

            {/* SHA256 — full width copy block */}
            <div className="hash-detail-sha-block">
              <div className="hash-detail-sha-header">
                <div className="hash-detail-sha-label">
                  <Fingerprint size={14} />
                  <span>SHA256</span>
                </div>
                <CopyButton text={data.sha256} label="Копировать SHA256" />
              </div>
              <div className="hash-detail-sha-value" onClick={() => setShowFullSha(!showFullSha)}>
                {showFullSha ? (
                  <div className="hash-detail-sha-full">
                    {shaLines.map((line, i) => (
                      <span key={i} className="hash-detail-sha-line">{line}</span>
                    ))}
                  </div>
                ) : (
                  <span className="hash-detail-sha-truncated">{shaShort}</span>
                )}
                <button className="hash-detail-sha-toggle" title={showFullSha ? 'Свернуть' : 'Показать полностью'}>
                  {showFullSha ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                </button>
              </div>
            </div>

            {/* Divider */}
            <div className="hash-detail-divider" />

            {/* Details grid */}
            <div className="hash-detail-grid">
              <DetailRow
                icon={<FileCode size={15} />}
                label="Имя файла"
                value={data.file_name || '—'}
                highlight
              />
              <DetailRow
                icon={<HardDrive size={15} />}
                label="Размер файла"
                value={formatSize(data.file_size)}
              />
              
              {susData && (
                <>
                  <DetailRow
                    icon={<User size={15} />}
                    label="Пользователь"
                    value={susData.pc_username}
                  />
                  <DetailRow
                    icon={<Hash size={15} />}
                    label="ID записи"
                    value={`#${susData.id}`}
                    mono
                  />
                  <DetailRow
                    icon={<Terminal size={15} />}
                    label="Риск-скop"
                    value={
                      <div className="hash-detail-risk-bar-wrap">
                        <div className="hash-detail-risk-bar">
                          <div
                            className="hash-detail-risk-fill"
                            style={{
                              width: `${susData.risk_score}%`,
                              background: riskMeta!.color,
                              boxShadow: `0 0 8px ${riskMeta!.color}40`,
                            }}
                          />
                        </div>
                        <span style={{ color: riskMeta!.color, fontWeight: 600 }}>
                          {susData.risk_score}
                        </span>
                      </div>
                    }
                  />
                </>
              )}

              {scanData && (
                <>
                  <DetailRow
                    icon={<User size={15} />}
                    label="Пользователи"
                    value={scanData.pc_usernames?.slice(0, 5).join(', ') || '—'}
                    highlight
                  />
                  {scanData.pc_usernames && scanData.pc_usernames.length > 5 && (
                    <DetailRow
                      icon={<User size={15} />}
                      label="Ещё пользователей"
                      value={`+${scanData.pc_usernames.length - 5}`}
                    />
                  )}
                  <DetailRow
                    icon={<Activity size={15} />}
                    label="Найдено раз"
                    value={scanData.occurrences}
                  />
                </>
              )}

              <DetailRow
                icon={<Calendar size={15} />}
                label={susData ? 'Создан' : 'Первый раз замечен'}
                value={susData
                  ? new Date(susData.created_at).toLocaleString('ru-RU')
                  : scanData
                    ? new Date(scanData.first_seen).toLocaleString('ru-RU')
                    : '—'
                }
              />

              {scanData && (
                <DetailRow
                  icon={<Clock size={15} />}
                  label="Последний раз"
                  value={new Date(scanData.last_seen).toLocaleString('ru-RU')}
                />
              )}

              {susData && susData.reviewed_at && (
                <DetailRow
                  icon={<Calendar size={15} />}
                  label="Проверен"
                  value={new Date(susData.reviewed_at).toLocaleString('ru-RU')}
                />
              )}
            </div>

            {/* Reviewer info */}
            {susData && susData.reviewed_by_name && (
              <div className="hash-detail-reviewer">
                <ShieldCheck size={14} />
                <span>Проверен: <strong>{susData.reviewed_by_name}</strong></span>
              </div>
            )}
          </div>

          {/* ── Footer (actions) ── */}
          <div className="hash-detail-footer">
            {susData && (
              <div className="hash-detail-footer-info">
                <span className="hash-detail-footer-status" style={{ color: statusMeta.color }}>
                  Статус: {statusMeta.label}
                </span>
              </div>
            )}

            <div className="hash-detail-footer-actions">
              <button className="btn btn-outline btn-sm" onClick={onClose}>
                <X size={14} /> Закрыть
              </button>

              {/* For pending suspicious hashes — approve/reject */}
              {!isScan && susData && susData.status === 'pending' && onApprove && onReject && (
                <>
                  <button
                    className="btn btn-green btn-sm"
                    onClick={() => onApprove(susData.id)}
                  >
                    <ShieldCheck size={14} /> Подтвердить чит
                  </button>
                  <button
                    className="btn btn-danger btn-sm"
                    onClick={() => onReject(susData.id)}
                  >
                    <ShieldAlert size={14} /> Отметить как спам
                  </button>
                </>
              )}

              {/* For scan results — confirm */}
              {isScan && scanData && scanData.status === 'new' && onConfirmFromScan && (
                <button
                  className="btn btn-green btn-sm"
                  onClick={() => onConfirmFromScan(scanData.sha256, scanData.file_name, scanData.file_size)}
                >
                  <ShieldCheck size={14} /> Подтвердить чит
                </button>
              )}
            </div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  )
})
