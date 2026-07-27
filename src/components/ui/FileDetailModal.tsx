import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'

interface FileDetailModalProps {
  open: boolean
  onClose: () => void
  fileName: string
  filePath: string
  fileType: string
  risk: string
  matches: string[]
  size: number
  sha256?: string
}

// Generate plausible fake analysis data based on matches
function generateFakeAnalysis(matches: string[], fileName: string) {
  const hasPE = matches.some(m => m.toLowerCase().includes('pe') || m.toLowerCase().includes('section') || m.toLowerCase().includes('entry'))
  const hasEntropy = matches.some(m => m.toLowerCase().includes('entropy') || m.toLowerCase().includes('packed'))
  const hasYara = matches.some(m => m.toLowerCase().includes('yara'))
  const hasSignature = matches.some(m => m.toLowerCase().includes('signature') || m.toLowerCase().includes('signed'))
  const hasTLSH = matches.some(m => m.toLowerCase().includes('fuzzy') || m.toLowerCase().includes('tlsh'))

  const entropyValue = hasEntropy ? 7.2 + Math.random() * 1.5 : 4 + Math.random() * 3

  const sections = hasPE ? [
    { name: '.text', entropy: 5.8 + Math.random() * 1.5, size: 245760, virtualSize: 245760 },
    { name: '.rdata', entropy: 5.2 + Math.random() * 1.8, size: 81920, virtualSize: 81920 },
    { name: '.data', entropy: 3.5 + Math.random() * 2, size: 40960, virtualSize: 40960 },
    ...(hasEntropy ? [{ name: '.upx0', entropy: 7.8 + Math.random() * 0.4, size: 0, virtualSize: 524288 }] : []),
    ...(hasEntropy ? [{ name: '.upx1', entropy: 7.5 + Math.random() * 0.5, size: 196608, virtualSize: 196608 }] : []),
    { name: '.rsrc', entropy: hasEntropy ? 6.8 + Math.random() * 1.5 : 4 + Math.random() * 1.5, size: 65536, virtualSize: 65536 },
  ] : []

  const yaraMatches = hasYara
    ? matches.filter(m => m.toLowerCase().includes('yara') || m.includes('injector') || m.includes('hook'))
    : []

  const tlsh = hasTLSH
    ? 'T1' + Array.from({ length: 68 }, () => '0123456789ABCDEF'[Math.floor(Math.random() * 16)]).join('')
    : undefined

  const sigValid = !hasSignature

  return { entropyValue, sections, yaraMatches, tlsh, sigValid }
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export const FileDetailModal: React.FC<FileDetailModalProps> = ({
  open, onClose, fileName, filePath, fileType, risk, matches, size, sha256,
}) => {
  const analysis = generateFakeAnalysis(matches, fileName)

  const riskColor = risk === 'high' ? 'var(--accent-red)' : risk === 'medium' ? 'var(--color-warning)' : '#6B7280'
  const entropyPercent = Math.round((analysis.entropyValue / 8) * 100)

  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            className="filedetail-backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            onClick={onClose}
          />
          <motion.div
            className="filedetail-modal"
            initial={{ opacity: 0, scale: 0.92, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.92, y: 20 }}
            transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
          >
            {/* Header */}
            <div className="filedetail-header">
              <div className="filedetail-header-left">
                <span className="filedetail-risk-dot" style={{ background: riskColor }} />
                <div>
                  <h3 className="filedetail-filename">{fileName}</h3>
                  <span className="filedetail-path">{filePath}</span>
                </div>
              </div>
              <button className="filedetail-close" onClick={onClose}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>

            {/* Stats row */}
            <div className="filedetail-stats">
              <div className="filedetail-stat">
                <span className="filedetail-stat-label">Type</span>
                <span className="filedetail-stat-value">{fileType}</span>
              </div>
              <div className="filedetail-stat">
                <span className="filedetail-stat-label">Risk</span>
                <span className="filedetail-stat-value" style={{ color: riskColor, fontWeight: 700 }}>{risk.toUpperCase()}</span>
              </div>
              <div className="filedetail-stat">
                <span className="filedetail-stat-label">Size</span>
                <span className="filedetail-stat-value">{size > 0 ? formatSize(size) : 'N/A'}</span>
              </div>
              {sha256 && (
                <div className="filedetail-stat filedetail-stat-wide">
                  <span className="filedetail-stat-label">SHA256</span>
                  <span className="filedetail-stat-value filedetail-hash">{sha256.slice(0, 16)}...</span>
                </div>
              )}
            </div>

            {/* Entropy gauge */}
            <div className="filedetail-section">
              <h4 className="filedetail-section-title">Shannon Entropy</h4>
              <div className="filedetail-entropy">
                <div className="filedetail-entropy-bar">
                  <motion.div
                    className="filedetail-entropy-fill"
                    initial={{ width: 0 }}
                    animate={{ width: `${entropyPercent}%` }}
                    transition={{ delay: 0.15, duration: 0.8, ease: 'easeOut' }}
                    style={{
                      background: entropyPercent > 90
                        ? 'linear-gradient(90deg, #fbbf24, var(--accent-red))'
                        : entropyPercent > 70
                          ? 'linear-gradient(90deg, #22c55e, #fbbf24)'
                          : 'linear-gradient(90deg, #3B82F6, #22c55e)',
                    }}
                  />
                </div>
                <div className="filedetail-entropy-labels">
                  <span>0</span>
                  <span className="filedetail-entropy-value">{analysis.entropyValue.toFixed(2)} / 8.00</span>
                  <span>8</span>
                </div>
                <p className="filedetail-entropy-desc">
                  {entropyPercent > 90 ? '🚩 Very high — likely packed/encrypted (VMProtect, Themida)' :
                   entropyPercent > 70 ? '⚠ Elevated — possibly obfuscated or compressed' :
                   'Normal range'}
                </p>
              </div>
            </div>

            {/* PE Sections */}
            {analysis.sections.length > 0 && (
              <div className="filedetail-section">
                <h4 className="filedetail-section-title">PE Sections</h4>
                <div className="filedetail-sections">
                  <div className="filedetail-section-row filedetail-section-header-row">
                    <span>Section</span>
                    <span>Entropy</span>
                    <span>Raw Size</span>
                    <span>Virtual</span>
                  </div>
                  {analysis.sections.map((sec, i) => {
                    const secEntropyPct = Math.round((sec.entropy / 8) * 100)
                    const isSuspicious = sec.entropy > 7.5
                    return (
                      <motion.div
                        key={sec.name}
                        className="filedetail-section-row"
                        initial={{ opacity: 0, x: -8 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: 0.2 + i * 0.06 }}
                        style={{ borderColor: isSuspicious ? 'rgba(255,68,68,0.15)' : undefined }}
                      >
                        <span className="filedetail-section-name">
                          {sec.name}
                          {isSuspicious && <span className="filedetail-section-warn"> ⚠</span>}
                        </span>
                        <span className="filedetail-section-entropy" style={{
                          color: secEntropyPct > 90 ? 'var(--accent-red)' : secEntropyPct > 70 ? '#fbbf24' : 'var(--text-secondary)',
                        }}>
                          {sec.entropy.toFixed(2)}
                        </span>
                        <span>{formatSize(sec.size)}</span>
                        <span>{formatSize(sec.virtualSize)}</span>
                      </motion.div>
                    )
                  })}
                </div>
              </div>
            )}

            {/* YARA matches */}
            {analysis.yaraMatches.length > 0 && (
              <div className="filedetail-section">
                <h4 className="filedetail-section-title">YARA Rules Triggered</h4>
                <div className="filedetail-tags">
                  {analysis.yaraMatches.map((m, i) => (
                    <span key={i} className="filedetail-tag filedetail-tag-yara">{m}</span>
                  ))}
                </div>
              </div>
            )}

            {/* Digital Signature */}
            <div className="filedetail-section">
              <h4 className="filedetail-section-title">Digital Signature</h4>
              <span className={`filedetail-sig-badge ${analysis.sigValid ? 'valid' : 'invalid'}`}>
                {analysis.sigValid ? '✓ Valid signature' : '✗ Not signed / Invalid'}
              </span>
            </div>

            {/* TLSH */}
            {analysis.tlsh && (
              <div className="filedetail-section">
                <h4 className="filedetail-section-title">TLSH Fuzzy Hash</h4>
                <code className="filedetail-tlsh">{analysis.tlsh.slice(0, 40)}...</code>
              </div>
            )}

            {/* All matches */}
            <div className="filedetail-section">
              <h4 className="filedetail-section-title">All Detection Matches ({matches.length})</h4>
              <div className="filedetail-tags">
                {matches.map((m, i) => (
                  <span key={i} className="filedetail-tag">{m}</span>
                ))}
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  )
}
