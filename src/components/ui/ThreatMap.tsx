import React, { useMemo } from 'react'
import { motion } from 'framer-motion'
import type { ScanResult } from '../../types/electron'

interface ThreatMapProps {
  results: ScanResult[]
}

interface ThreatRegion {
  name: string
  path: string
  highCount: number
  mediumCount: number
  lowCount: number
  totalCount: number
  width: number
}

function extractRegion(filePath: string): string {
  const lower = filePath.toLowerCase()
  if (lower.includes('download') || lower.includes('загрузки')) return 'Downloads'
  if (lower.includes('desktop') || lower.includes('рабочий стол')) return 'Desktop'
  if (lower.includes('temp') || lower.includes('врем')) return 'Temp'
  if (lower.includes('appdata')) return 'AppData'
  if (lower.includes('fivem')) return 'FiveM'
  if (lower.includes('ragemp') || lower.includes('rage')) return 'RAGE MP'
  if (lower.includes('altv')) return 'ALT:V'
  if (lower.includes('prefetch')) return 'Prefetch'
  if (lower.includes('registry') || lower.includes('hkey') || lower.includes('hklm') || lower.includes('hkcu')) return 'Registry'
  if (lower.includes('process:')) return 'Processes'
  if (lower.includes('pci') || lower.includes('dma')) return 'DMA'
  if (lower.includes('browser') || lower.includes('chrome') || lower.includes('firefox')) return 'Browser'
  if (lower.includes('program files')) return 'Program Files'
  if (lower.includes('windows')) return 'Windows'
  return 'Other'
}

const REGION_COLORS: Record<string, string> = {
  'Downloads': 'var(--chart-red)',
  'Desktop': 'var(--chart-orange)',
  'Temp': 'var(--chart-coral)',
  'AppData': 'var(--chart-warning)',
  'FiveM': 'var(--chart-success)',
  'RAGE MP': 'var(--chart-info)',
  'ALT:V': 'var(--chart-purple)',
  'Prefetch': 'var(--chart-pink)',
  'Registry': 'var(--chart-cyan)',
  'Processes': 'var(--chart-tangerine)',
  'DMA': 'var(--chart-error)',
  'Browser': 'var(--chart-indigo)',
  'Windows': 'var(--chart-slate)',
  'Program Files': 'var(--chart-lime)',
  'Other': 'var(--chart-gray)',
}

// Raw hex for gradient alpha suffix (88 = ~53% transparency)
const REGION_HEX: Record<string, string> = {
  'Downloads': '#ff4444',
  'Desktop': '#ff6b35',
  'Temp': '#ff8a5b',
  'AppData': '#f59e0b',
  'FiveM': '#22c55e',
  'RAGE MP': '#3B82F6',
  'ALT:V': '#8B5CF6',
  'Prefetch': '#ec4899',
  'Registry': '#06b6d4',
  'Processes': '#f97316',
  'DMA': '#ef4444',
  'Browser': '#6366f1',
  'Windows': '#64748b',
  'Program Files': '#84cc16',
  'Other': '#6B7280',
}

export const ThreatMap: React.FC<ThreatMapProps> = ({ results }) => {
  const regions = useMemo(() => {
    const map = new Map<string, ThreatRegion>()
    for (const r of results) {
      const region = extractRegion(r.path)
      const existing = map.get(region)
      if (existing) {
        if (r.risk === 'high') existing.highCount++
        else if (r.risk === 'medium') existing.mediumCount++
        else existing.lowCount++
        existing.totalCount++
      } else {
        map.set(region, {
          name: region,
          path: region,
          highCount: r.risk === 'high' ? 1 : 0,
          mediumCount: r.risk === 'medium' ? 1 : 0,
          lowCount: r.risk === 'low' ? 1 : 0,
          totalCount: 1,
          width: 0,
        })
      }
    }
    const arr = Array.from(map.values()).sort((a, b) => b.totalCount - a.totalCount)
    const total = arr.reduce((s, r) => s + r.totalCount, 0)
    for (const region of arr) {
      region.width = total > 0 ? (region.totalCount / total) * 100 : 0
    }
    return arr.slice(0, 8) // Top 8 regions
  }, [results])

  if (regions.length === 0) return null

  return (
    <div className="threat-map card-section">
      <h4 className="threat-map-title section-title">Threat Distribution</h4>
      <div className="threat-map-bars">
        {regions.map((region, i) => (
          <motion.div
            key={region.name}
            className="threat-map-row"
            initial={{ opacity: 0, x: -16 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.06, duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
          >
            <div className="threat-map-label">
              <span className="threat-map-dot" style={{ background: REGION_COLORS[region.name] || REGION_COLORS['Other'] }} />
              <span className="threat-map-name">{region.name}</span>
              <span className="threat-map-count">{region.totalCount}</span>
            </div>
            <div className="threat-map-track">
              <motion.div
                className="threat-map-fill"
                initial={{ width: 0 }}
                animate={{ width: `${Math.max(region.width, 2)}%` }}
                transition={{ delay: i * 0.06 + 0.2, duration: 0.6, ease: 'easeOut' }}
                style={{
                  background: `linear-gradient(90deg,
                    ${REGION_HEX[region.name] || REGION_HEX['Other']},
                    ${REGION_HEX[region.name] || REGION_HEX['Other']}88)`,
                }}
              />
              {region.highCount > 0 && (
                <motion.div
                  className="threat-map-segment threat-map-high"
                  initial={{ width: 0 }}
                  animate={{ width: `${Math.max((region.highCount / region.totalCount) * region.width, 1)}%` }}
                  transition={{ delay: i * 0.06 + 0.2, duration: 0.6, ease: 'easeOut' }}
                />
              )}
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  )
}
