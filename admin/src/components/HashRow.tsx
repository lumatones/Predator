import { motion } from 'framer-motion'
import { Clock, Check, X, FileCheck } from 'lucide-react'
import { SuspiciousHash, ScanResultHash } from '../api'
import Confetti from './Confetti'
import { smoothEase } from '../constants'

interface HashRowProps {
  data: SuspiciousHash | ScanResultHash
  isScan: boolean
  tab: string
  index: number
  isGlowing: boolean
  isRejecting: boolean
  showConfetti: boolean
  onApprove: (id: number) => void
  onReject: (id: number) => void
  onConfirmFromScan: (sha256: string, fileName: string, fileSize: number) => void
  onClick?: () => void
}

const rowVariants = {
  hidden: { opacity: 0, y: 10 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { delay: i * 0.03, duration: 0.35, ease: smoothEase },
  }),
}

const formatSize = (size: number) => {
  if (!size) return '—'
  return size > 1024 * 1024
    ? `${(size / (1024 * 1024)).toFixed(1)} MB`
    : `${(size / 1024).toFixed(0)} KB`
}

const getStatusMeta = (status: string) => {
  switch (status) {
    case 'new':
      return { label: 'Новый', className: 'hash-status-new' }
    case 'pending':
      return { label: 'На проверке', className: 'hash-status-pending' }
    case 'confirmed':
      return { label: 'Чит', className: 'hash-status-confirmed' }
    case 'false_positive':
      return { label: 'Спам', className: 'hash-status-false' }
    default:
      return { label: status, className: '' }
  }
}

export default function HashRow({
  data,
  isScan,
  tab,
  index,
  isGlowing,
  isRejecting,
  showConfetti,
  onApprove,
  onReject,
  onConfirmFromScan,
  onClick,
}: HashRowProps) {
  const sha = data.sha256
  const fileName = data.file_name
  const fileSize = data.file_size
  const date = isScan
    ? new Date((data as ScanResultHash).last_seen).toLocaleString('ru-RU')
    : new Date((data as SuspiciousHash).created_at).toLocaleString('ru-RU')

  const className = ['hash-row', isGlowing ? 'hash-row-confirm' : '', isRejecting ? 'hash-row-reject' : '']
    .filter(Boolean)
    .join(' ')

  const scanData = isScan ? (data as ScanResultHash) : null
  const suspiciousData = !isScan ? (data as SuspiciousHash) : null

  return (
    <motion.tr
      custom={index}
      initial="hidden"
      animate="visible"
      variants={rowVariants}
      className={`${className} ${onClick ? 'hash-row-clickable' : ''}`}
      onClick={onClick}
      style={onClick ? { cursor: 'pointer' } : undefined}
    >
      <td><code className="hash-sha">{sha.slice(0, 16)}...</code></td>
      <td className="hash-filename-cell"><span className="hash-filename">{fileName}</span></td>

      {isScan ? (
        <>
          <td className="hash-users">{scanData?.pc_usernames?.slice(0, 2).join(', ') || '—'}</td>
          <td className="hash-size">{formatSize(fileSize)}</td>
          <td className="hash-occurrences"><span>{scanData?.occurrences}</span></td>
          <td>
            <span className={`hash-status ${getStatusMeta(scanData?.status || '').className}`}>
              {getStatusMeta(scanData?.status || '').label}
            </span>
          </td>
        </>
      ) : (
        <>
          <td className="hash-users">{suspiciousData?.pc_username}</td>
          <td className="hash-size">{formatSize(fileSize)}</td>
          <td>
            <span className={`badge ${(suspiciousData?.risk_score || 0) > 60 ? 'badge-high' : (suspiciousData?.risk_score || 0) > 30 ? 'badge-medium' : 'badge-low'}`}>
              {suspiciousData?.risk_score}
            </span>
          </td>
        </>
      )}

      <td className="hash-date">{date}</td>

      <td className="hash-actions">
        <div className="hash-actions-inner">
          {!isScan && tab === 'pending' && suspiciousData && (
            <>
              <button className="btn btn-green btn-sm hash-approve-btn" onClick={() => onApprove(suspiciousData.id)}>
                <FileCheck size={14} /> Чит
              </button>
              <button className="btn btn-danger btn-sm hash-reject-btn" onClick={() => onReject(suspiciousData.id)}>
                <X size={14} /> Спам
              </button>
            </>
          )}
          {!isScan && tab === 'confirmed' && suspiciousData && (
            <span className="hash-reviewed-by">
              <Check size={14} /> Reviewed by {suspiciousData.reviewed_by_name || 'admin'}
            </span>
          )}
          {!isScan && tab === 'false_positive' && suspiciousData && (
            <span className="hash-reviewed-by rejected">
              <X size={14} /> Отклонён {suspiciousData.reviewed_by_name || 'admin'}
            </span>
          )}
          {isScan && scanData && (
            scanData.status === 'new' ? (
              <button
                className="btn btn-green btn-sm hash-approve-btn"
                onClick={() => onConfirmFromScan(scanData.sha256, scanData.file_name, scanData.file_size)}
              >
                <FileCheck size={14} /> Подтвердить чит
              </button>
            ) : (
              <span className="hash-reviewed-by">
                {scanData.status === 'confirmed' ? <FileCheck size={14} /> : scanData.status === 'pending' ? <Clock size={14} /> : <X size={14} />}
                {scanData.status === 'confirmed' ? 'В базе' : scanData.status === 'pending' ? 'На проверке' : 'Отклонён'}
              </span>
            )
          )}
        </div>
        {showConfetti && <Confetti />}
      </td>
    </motion.tr>
  )
}
