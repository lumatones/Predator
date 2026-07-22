import { useState, useEffect, useRef } from 'react'
import type { SystemInfoSnapshot } from '../types/electron'

interface DashboardProps {
  lang: 'ru' | 'en'
  onBack: () => void
}

const T: Record<string, Record<string, string>> = {
  ru: {
    title: 'Мониторинг системы',
    cpu: 'ЦП',
    memory: 'Память',
    temp: 'Температура',
    uptime: 'Время работы',
    os: 'Система',
    processes: 'Процессы',
    noData: 'Нет данных',
    processName: 'Процесс',
    pid: 'PID',
    mem: 'Память',
    back: 'Назад',
    cores: 'ядер',
    online: 'Работает',
    loading: 'Загрузка...',
  },
  en: {
    title: 'System Monitor',
    cpu: 'CPU',
    memory: 'Memory',
    temp: 'Temperature',
    uptime: 'Uptime',
    os: 'System',
    processes: 'Processes',
    noData: 'No data',
    processName: 'Process',
    pid: 'PID',
    mem: 'Memory',
    back: 'Back',
    cores: 'cores',
    online: 'Online',
    loading: 'Loading...',
  },
}

// ── Helpers ──

function formatUptime(d: number, h: number, m: number, lang: string): string {
  if (lang === 'ru') {
    const parts: string[] = []
    if (d > 0) parts.push(`${d} ${decl(d, ['день', 'дня', 'дней'])}`)
    if (h > 0) parts.push(`${h} ${decl(h, ['час', 'часа', 'часов'])}`)
    parts.push(`${m} ${decl(m, ['мин', 'мин', 'мин'])}`)
    return parts.join(' ')
  }
  const parts: string[] = []
  if (d > 0) parts.push(`${d}d`)
  if (h > 0) parts.push(`${h}h`)
  parts.push(`${m}m`)
  return parts.join(' ')
}

function decl(n: number, forms: [string, string, string]): string {
  n = Math.abs(n) % 100
  const n1 = n % 10
  if (n > 10 && n < 20) return forms[2]
  if (n1 > 1 && n1 < 5) return forms[1]
  if (n1 === 1) return forms[0]
  return forms[2]
}

// ── Gauge Component ──

function Gauge({ value, label, sub, color, size = 100 }: {
  value: number
  label: string
  sub?: string
  color: string
  size?: number
}) {
  const radius = (size - 20) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference * (1 - value / 100)
  const strokeWidth = size > 80 ? 6 : 4

  return (
    <div className="dash-gauge" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none"
          stroke="rgba(255,255,255,0.05)"
          strokeWidth={strokeWidth}
        />
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: 'stroke-dashoffset 0.5s ease' }}
        />
      </svg>
      <div className="dash-gauge-label">
        <span className="dash-gauge-value" style={{ color }}>{value}%</span>
        <span className="dash-gauge-text">{label}</span>
        {sub && <span className="dash-gauge-sub">{sub}</span>}
      </div>
    </div>
  )
}

// ── Dashboard Component ──

export default function Dashboard({ lang, onBack }: DashboardProps) {
  const t = (key: string) => T[lang][key] || key
  const [snapshot, setSnapshot] = useState<SystemInfoSnapshot | null>(null)
  const [processFilter, setProcessFilter] = useState('')
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    async function fetchSnapshot() {
      try {
        if (!window.electronAPI?.getSystemSnapshot) {
          // Dev mode — use mock data
          mockSnapshot()
          return
        }
        const data = await window.electronAPI.getSystemSnapshot()
        if (data) setSnapshot(data)
      } catch { /* ignore */ }
    }

    // Mock data for dev mode (no Electron)
    function mockSnapshot() {
      const totalMem = 16
      const usedMem = 5.2 + Math.random() * 2
      setSnapshot({
        cpu: { usagePercent: 23 + Math.round(Math.random() * 30), cores: 8, model: 'AMD Ryzen 7', loadAvg: [] },
        memory: { totalGB: totalMem, usedGB: parseFloat(usedMem.toFixed(1)), freeGB: parseFloat((totalMem - usedMem).toFixed(1)), usagePercent: Math.round((usedMem / totalMem) * 100) },
        temperature: 45 + Math.round(Math.random() * 15),
        uptime: { days: 0, hours: 2, minutes: 15 + Math.round(Math.random() * 30) },
        os: { platform: 'win32', release: '10.0.26100', arch: 'x64', hostname: 'DEV-PC' },
        processes: [
          { pid: 4821, name: 'Predator.exe', memoryMB: 89, cpuPercent: 0 },
          { pid: 1234, name: 'chrome.exe', memoryMB: 452, cpuPercent: 0 },
          { pid: 5678, name: 'Discord.exe', memoryMB: 234, cpuPercent: 0 },
          { pid: 9012, name: 'explorer.exe', memoryMB: 118, cpuPercent: 0 },
          { pid: 3456, name: 'spotify.exe', memoryMB: 167, cpuPercent: 0 },
          { pid: 7890, name: 'Code.exe', memoryMB: 312, cpuPercent: 0 },
          { pid: 1111, name: 'System', memoryMB: 45, cpuPercent: 0 },
          { pid: 2222, name: 'svchost.exe', memoryMB: 34, cpuPercent: 0 },
          { pid: 3333, name: 'powershell.exe', memoryMB: 67, cpuPercent: 0 },
          { pid: 4444, name: 'msedge.exe', memoryMB: 198, cpuPercent: 0 },
        ],
        timestamp: Date.now(),
      })
    }

    // Fetch immediately, then every 2 seconds
    fetchSnapshot()
    pollRef.current = setInterval(fetchSnapshot, 2000)

    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [])

  const filteredProcesses = snapshot
    ? snapshot.processes.filter(p =>
        !processFilter || p.name.toLowerCase().includes(processFilter.toLowerCase())
      )
    : []

  return (
    <div className="dash-wrapper">
      <div className="dash-header">
        <button className="checker-back-btn" onClick={onBack} title={t('back')}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="15 18 9 12 15 6" />
          </svg>
        </button>
        <h2 className="dash-title">{t('title')}</h2>
        <div className="dash-status">
          {snapshot ? (
            <span className="dash-online">{t('online')}</span>
          ) : (
            <span className="dash-loading">{t('loading')}</span>
          )}
        </div>
      </div>

      {snapshot && (
        <>
          {/* ── Top Gauges ── */}
          <div className="dash-gauges">
            <Gauge
              value={snapshot.cpu.usagePercent}
              label={t('cpu')}
              sub={`${snapshot.cpu.cores} ${t('cores')}`}
              color="#ff4444"
              size={110}
            />
            <Gauge
              value={snapshot.memory.usagePercent}
              label={t('memory')}
              sub={`${snapshot.memory.usedGB}/${snapshot.memory.totalGB} GB`}
              color="#3B82F6"
              size={110}
            />
            <Gauge
              value={snapshot.temperature !== null
                ? Math.min(Math.round((snapshot.temperature / 100) * 100), 100)
                : 0}
              label={t('temp')}
              sub={snapshot.temperature !== null ? `${snapshot.temperature}°C` : 'N/A'}
              color={snapshot.temperature !== null && snapshot.temperature > 70 ? '#F59E0B' : '#22c55e'}
              size={110}
            />
          </div>

          {/* ── Info Cards ── */}
          <div className="dash-info-row">
            <div className="dash-card">
              <span className="dash-card-label">{t('uptime')}</span>
              <span className="dash-card-value">
                {formatUptime(snapshot.uptime.days, snapshot.uptime.hours, snapshot.uptime.minutes, lang)}
              </span>
            </div>
            <div className="dash-card">
              <span className="dash-card-label">{t('os')}</span>
              <span className="dash-card-value" style={{ fontSize: 11 }}>
                {snapshot.os.platform} {snapshot.os.arch}
              </span>
              <span className="dash-card-sub">{snapshot.os.release}</span>
            </div>
            <div className="dash-card">
              <span className="dash-card-label">{t('os')}</span>
              <span className="dash-card-value" style={{ fontSize: 11 }}>{snapshot.os.hostname}</span>
            </div>
          </div>

          {/* ── Process List ── */}
          <div className="dash-processes">
            <div className="dash-processes-header">
              <span className="dash-card-label">{t('processes')} ({snapshot.processes.length})</span>
              <input
                type="text"
                className="dash-process-filter"
                placeholder="Filter..."
                value={processFilter}
                onChange={e => setProcessFilter(e.target.value)}
              />
            </div>
            <div className="dash-process-list">
              <div className="dash-process-row header">
                <span className="dash-pid">PID</span>
                <span className="dash-pname">{t('processName')}</span>
                <span className="dash-pmem">{t('mem')}</span>
              </div>
              {filteredProcesses.map((p, i) => (
                <div key={`${p.pid}-${i}`} className="dash-process-row" style={{ animationDelay: `${i * 0.02}s` }}>
                  <span className="dash-pid">{p.pid}</span>
                  <span className="dash-pname">
                    <span className="dash-pname-dot" />
                    {p.name}
                  </span>
                  <span className="dash-pmem">{p.memoryMB} MB</span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {!snapshot && (
        <div className="dash-empty">
          <div className="spinner" style={{ width: 36, height: 36 }}>
            <div className="spinner-ring" style={{ borderWidth: 2 }} />
          </div>
          <p className="dash-empty-text">{t('loading')}</p>
        </div>
      )}
    </div>
  )
}
