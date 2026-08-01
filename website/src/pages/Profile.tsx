import { useState } from 'react'
import { motion } from 'framer-motion'
import { User, Shield, Server, Link2, Bell, Settings, Check } from 'lucide-react'

const TABS = [
  { id: 'profile', label: 'Профиль', icon: User },
  { id: 'servers', label: 'Серверы', icon: Server },
  { id: 'connections', label: 'Связи', icon: Link2 },
  { id: 'notifications', label: 'Уведомления', icon: Bell },
]

export default function Profile() {
  const [activeTab, setActiveTab] = useState('profile')
  const [discordConnected, setDiscordConnected] = useState(false)
  const [telegramConnected, setTelegramConnected] = useState(false)

  return (
    <div className="pt-24 pb-20 px-4 sm:px-6 lg:px-8 max-w-5xl mx-auto">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}>
        {/* Header Card */}
        <div className="glass-card p-6 mb-6">
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-5">
            <div className="w-16 h-16 rounded-2xl bg-predator-accent/15 flex items-center justify-center text-predator-accent text-2xl font-bold">
              P
            </div>
            <div className="flex-1">
              <h1 className="text-xl font-bold text-predator-text">Predator Admin</h1>
              <p className="text-sm text-predator-muted">admin@predator.ac · Базовая подписка</p>
              <div className="flex items-center gap-3 mt-2">
                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-predator-accent/10 text-predator-accent text-xs font-medium">
                  <Shield size={10} /> Базовая
                </span>
                <span className="text-xs text-predator-muted">3 проверки/неделю · 1 Discord сервер</span>
              </div>
            </div>
            <button className="px-4 py-2 rounded-lg border border-predator-border text-sm text-predator-muted hover:text-predator-text hover:border-predator-accent/30 transition-all">
              <Settings size={14} className="inline mr-1.5" />
              Настройки
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-6 p-1 bg-predator-card rounded-xl border border-predator-border overflow-x-auto">
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium whitespace-nowrap transition-all ${
                activeTab === tab.id
                  ? 'bg-predator-accent/10 text-predator-accent'
                  : 'text-predator-muted hover:text-predator-text hover:bg-predator-bg/50'
              }`}
            >
              <tab.icon size={14} />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          {activeTab === 'profile' && (
            <div className="space-y-4">
              <div className="glass-card p-5">
                <h3 className="text-sm font-semibold text-predator-text mb-4">Статистика</h3>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  {[
                    { label: 'Проверок', value: '24', color: '#22c55e' },
                    { label: 'Найдено читов', value: '7', color: '#ef4444' },
                    { label: 'Игроков чистых', value: '18', color: '#8b5cf6' },
                    { label: 'Осталось лимит', value: '1/нед', color: '#f59e0b' },
                  ].map(s => (
                    <div key={s.label} className="text-center p-3 rounded-xl bg-predator-bg/50">
                      <div className="text-xl font-bold" style={{ color: s.color }}>{s.value}</div>
                      <div className="text-xs text-predator-muted mt-1">{s.label}</div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="glass-card p-5">
                <h3 className="text-sm font-semibold text-predator-text mb-3">История проверок</h3>
                <div className="space-y-2">
                  {[
                    { player: 'GhostRider99', date: '30.07.2026', result: 'Высокий риск', color: '#ef4444' },
                    { player: 'NightWolf', date: '29.07.2026', result: 'Средний риск', color: '#f59e0b' },
                    { player: 'SpeedDemon', date: '28.07.2026', result: 'Чисто', color: '#22c55e' },
                  ].map((h, i) => (
                    <div key={i} className="flex items-center justify-between py-2.5 px-3 rounded-lg bg-predator-bg/30 hover:bg-predator-bg/50 transition-colors">
                      <div className="flex items-center gap-3">
                        <div className="w-7 h-7 rounded-lg bg-predator-accent/10 flex items-center justify-center text-predator-accent text-xs font-bold">
                          {h.player.slice(0, 2)}
                        </div>
                        <div>
                          <div className="text-sm font-medium text-predator-text">{h.player}</div>
                          <div className="text-xs text-predator-muted">{h.date}</div>
                        </div>
                      </div>
                      <span className="text-xs font-medium" style={{ color: h.color }}>{h.result}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'servers' && (
            <div className="glass-card p-5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-semibold text-predator-text">Привязанные серверы</h3>
                <span className="text-xs text-predator-muted">Базовая: 1 сервер</span>
              </div>
              <div className="p-4 rounded-xl bg-predator-bg/50 border border-predator-border">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg bg-[#5865F2]/15 flex items-center justify-center">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="#5865F2">
                        <path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03z"/>
                      </svg>
                    </div>
                    <div>
                      <div className="text-sm font-medium text-predator-text">Majestic RP</div>
                      <div className="text-xs text-predator-muted">Подключён · 142 проверки</div>
                    </div>
                  </div>
                  <span className="flex items-center gap-1 text-xs text-predator-accent">
                    <Check size={12} /> Активен
                  </span>
                </div>
              </div>
              <button className="mt-4 w-full py-2.5 rounded-xl border border-dashed border-predator-border text-sm text-predator-muted hover:text-predator-accent hover:border-predator-accent/30 transition-all">
                + Добавить сервер
              </button>
            </div>
          )}

          {activeTab === 'connections' && (
            <div className="space-y-4">
              {/* Discord */}
              <div className="glass-card p-5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="w-11 h-11 rounded-xl bg-[#5865F2]/15 flex items-center justify-center">
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="#5865F2">
                        <path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03z"/>
                      </svg>
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-predator-text">Discord</h3>
                      <p className="text-xs text-predator-muted">
                        {discordConnected ? 'Подключено · Admin#1234' : 'Не подключено'}
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => setDiscordConnected(d => !d)}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                      discordConnected
                        ? 'bg-predator-danger/10 text-predator-danger hover:bg-predator-danger/20'
                        : 'bg-[#5865F2] text-white hover:bg-[#5865F2]/90'
                    }`}
                  >
                    {discordConnected ? 'Отвязать' : 'Подключить'}
                  </button>
                </div>
                {discordConnected && (
                  <div className="mt-4 p-3 rounded-lg bg-predator-bg/50 text-xs text-predator-muted">
                    Уведомления о заявках на проверку будут приходить в Discord
                  </div>
                )}
              </div>

              {/* Telegram */}
              <div className="glass-card p-5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="w-11 h-11 rounded-xl bg-[#26A5E4]/15 flex items-center justify-center">
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="#26A5E4">
                        <path d="M11.944 0A12 12 0 000 12a12 12 0 0012 12 12 12 0 0012-12A12 12 0 0012 0a12 12 0 00-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 01.171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.479.33-.913.492-1.302.48-.428-.013-1.252-.242-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/>
                      </svg>
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-predator-text">Telegram</h3>
                      <p className="text-xs text-predator-muted">
                        {telegramConnected ? 'Подключено · @predator_admin' : 'Не подключено'}
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => setTelegramConnected(t => !t)}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                      telegramConnected
                        ? 'bg-predator-danger/10 text-predator-danger hover:bg-predator-danger/20'
                        : 'bg-[#26A5E4] text-white hover:bg-[#26A5E4]/90'
                    }`}
                  >
                    {telegramConnected ? 'Отвязать' : 'Подключить'}
                  </button>
                </div>
                {telegramConnected && (
                  <div className="mt-4 p-3 rounded-lg bg-predator-bg/50 text-xs text-predator-muted">
                    Уведомления о результатах проверок будут приходить в Telegram
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'notifications' && (
            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold text-predator-text mb-4">Настройки уведомлений</h3>
              <div className="space-y-3">
                {[
                  { label: 'Новая заявка на проверку', desc: 'Когда игрок оставляет заявку через Discord', enabled: true },
                  { label: 'Результат проверки', desc: 'Когда сканирование завершено', enabled: true },
                  { label: 'Высокий риск', desc: 'Когда обнаружен чит или DMA', enabled: true },
                  { label: 'Еженедельный отчёт', desc: 'Сводка за неделю по всем серверам', enabled: false },
                ].map((n, i) => (
                  <div key={i} className="flex items-center justify-between py-3 border-b border-predator-border/50 last:border-0">
                    <div>
                      <div className="text-sm font-medium text-predator-text">{n.label}</div>
                      <div className="text-xs text-predator-muted">{n.desc}</div>
                    </div>
                    <div className={`w-10 h-6 rounded-full relative cursor-pointer transition-colors ${n.enabled ? 'bg-predator-accent' : 'bg-predator-border'}`}>
                      <div className={`w-4 h-4 rounded-full bg-white absolute top-1 transition-transform ${n.enabled ? 'left-5' : 'left-1'}`} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </motion.div>
      </motion.div>
    </div>
  )
}
