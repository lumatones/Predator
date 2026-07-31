import { useState, useEffect, useRef, useMemo } from 'react'
import type { SystemInfoSnapshot } from '../types/electron'
import ServerStatus from '../components/ServerStatus'
import { SkeletonGauge, SkeletonCard, SkeletonTable } from '../components/ui/Skeleton'
import { Button } from '../components/ui/Button'

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
    search: 'Поиск по процессам, именам читов, директориям...',
    searchNoResults: 'Ничего не найдено',
    path: 'Путь',
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
    search: 'Search by process, cheat names, directories...',
    searchNoResults: 'Nothing found',
    path: 'Path',
  },
}

// ── Helpers ──

function formatUptime(d: number, h: number, m: number, lang: string): string {
  if (lang === 'ru') {
    const parts: string[] = []
    if (d > 0) parts.push(`${d} ${decl(d, ['день', 'дня', 'дней'])}`)
    if (h > 0) parts.push(`${h} ${decl(h, ['час', 'часа', 'часов'])}`)
    parts.push(`${m} ${decl(m, ['минута', 'минуты', 'минут'])}`)
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
  const [searchQuery, setSearchQuery] = useState('')
  const isMounted = useRef(true)

  useEffect(() => {
    return () => { isMounted.current = false }
  }, [])

  useEffect(() => {      // Dev mode — use mock data with periodic updates
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
          { pid: 4821, name: 'Predator.exe', memoryMB: 89, cpuPercent: 0, path: 'C:\\Program Files\\Predator\\Predator.exe' },
          { pid: 1234, name: 'chrome.exe', memoryMB: 452, cpuPercent: 0, path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe' },
          { pid: 5678, name: 'Discord.exe', memoryMB: 234, cpuPercent: 0, path: 'C:\\Users\\Luma\\AppData\\Local\\Discord\\app-1.0.9171\\Discord.exe' },
          { pid: 9012, name: 'explorer.exe', memoryMB: 118, cpuPercent: 0, path: 'C:\\Windows\\explorer.exe' },
          { pid: 3456, name: 'spotify.exe', memoryMB: 167, cpuPercent: 0, path: 'C:\\Users\\Luma\\AppData\\Roaming\\Spotify\\Spotify.exe' },
          { pid: 7890, name: 'Code.exe', memoryMB: 312, cpuPercent: 0, path: 'C:\\Users\\Luma\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe' },
          { pid: 1111, name: 'System', memoryMB: 45, cpuPercent: 0, path: 'C:\\Windows\\System32\\ntoskrnl.exe' },
          { pid: 2222, name: 'svchost.exe', memoryMB: 34, cpuPercent: 0, path: 'C:\\Windows\\System32\\svchost.exe' },
          { pid: 3333, name: 'powershell.exe', memoryMB: 67, cpuPercent: 0, path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' },
          { pid: 4444, name: 'msedge.exe', memoryMB: 198, cpuPercent: 0, path: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe' },
        ],
        timestamp: Date.now(),
      })
    }

    // Check if IPC streaming is available (Electron main process)
    const api = window.electronAPI
    const hasStream = typeof api?.startSystemStream === 'function' && typeof api?.onSystemUpdate === 'function'

    if (hasStream && api) {
      const handler = (data: SystemInfoSnapshot) => {
        if (isMounted.current) setSnapshot(data)
      }
      const unsubscribeSystemUpdate = api.onSystemUpdate(handler)
      api.startSystemStream(2000)

      return () => {
        api.stopSystemStream()
        if (typeof unsubscribeSystemUpdate === 'function') unsubscribeSystemUpdate()
      }
    }

    // Dev mode fallback — mock polling
    mockSnapshot()
    const pollTimer = setInterval(mockSnapshot, 2000)
    return () => clearInterval(pollTimer)
  }, [])

  const filteredProcesses = useMemo(() => {
    if (!snapshot) return []
    const q = searchQuery.toLowerCase().trim()
    if (!q) return snapshot.processes
    return snapshot.processes.filter(p => {
      return p.name.toLowerCase().includes(q) ||
        String(p.pid).includes(q) ||
        (p.path && p.path.toLowerCase().includes(q))
    })
  }, [snapshot, searchQuery])

  return (
    <div className="dash-wrapper">
      <div className="dash-header">
        <Button className="checker-back-btn" variant="ghost" size="sm" onClick={onBack} title={t('back')}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="15 18 9 12 15 6" />
          </svg>
        </Button>
        <h2 className="dash-title">{t('title')}</h2>
        <div className="dash-header-right">
          <ServerStatus lang={lang} />
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

          {/* ── Global Search ── */}
          <div className="dash-search">
            <svg className="dash-search-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
            </svg>
            <input
              type="text"
              className="dash-search-input"
              placeholder={t('search')}
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
            />
            {searchQuery && (
              <button className="dash-search-clear" onClick={() => setSearchQuery('')} aria-label="Clear">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            )}
            {searchQuery && (
              <span className="dash-search-count">{filteredProcesses.length}/{snapshot.processes.length}</span>
            )}
          </div>

          {/* ── Process List ── */}
          <div className="dash-processes card-section">
            <div className="dash-processes-header">
              <span className="dash-card-label">{t('processes')} ({snapshot.processes.length})</span>
            </div>
            {filteredProcesses.length > 0 ? (
              <div className="dash-process-list">
                <div className="dash-process-row header">
                  <span className="dash-pid">PID</span>
                  <span className="dash-pname">{t('processName')}</span>
                  <span className="dash-ppath">{t('path')}</span>
                  <span className="dash-pmem">{t('mem')}</span>
                </div>
                {filteredProcesses.map((p, i) => {
                  return (
                    <div key={`${p.pid}-${i}`} className="dash-process-row" style={{ animationDelay: `${i * 0.02}s` }}>
                      <span className="dash-pid">{p.pid}</span>
                      <span className="dash-pname">
                        <span className="dash-pname-dot" />
                        {p.name}
                      </span>
                      <span className="dash-ppath" title={p.path}>{p.path ? (p.path.length > 40 ? '...' + p.path.slice(-37) : p.path) : '—'}</span>
                      <span className="dash-pmem">{p.memoryMB} MB</span>
                    </div>
                  )
                })}
              </div>
            ) : (
              <div className="dash-search-empty">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--text-secondary)" strokeWidth="1.5" style={{ opacity: 0.3 }}>
                  <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
                  <line x1="8" y1="11" x2="14" y2="11" strokeWidth="2" opacity="0.5" />
                </svg>
                <span>{t('searchNoResults')}</span>
                <button className="dash-search-reset" onClick={() => setSearchQuery('')}>
                  {lang === 'ru' ? 'Сбросить поиск' : 'Reset search'}
                </button>
              </div>
            )}
          </div>
        </>
      )}

      {!snapshot && (
        <>
          <SkeletonGauge count={3} />
          <div className="dash-info-row">
            <SkeletonCard lines={2} />
            <SkeletonCard lines={2} />
            <SkeletonCard lines={2} />
          </div>
          <SkeletonTable rows={6} cols={3} />
        </>
      )}
    </div>
  )
}
