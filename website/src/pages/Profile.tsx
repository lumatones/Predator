import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { User, Shield, Server, Link2, Bell, Check, AlertTriangle, LogOut } from 'lucide-react'
import {
  getToken, setToken, fetchMe, fetchCheckRequests, fetchNotifications,
  type WebsiteUser, type CheckRequest, type Notification, type LinkedServer, type LinkedSocial,
} from '../api'

const TABS = [
  { id: 'profile', label: 'Профиль', icon: User },
  { id: 'servers', label: 'Серверы', icon: Server },
  { id: 'connections', label: 'Связи', icon: Link2 },
  { id: 'notifications', label: 'Уведомления', icon: Bell },
]

const RISK_COLORS: Record<string, string> = {
  clean: '#8da2ff', low: '#d8ad68', medium: '#d88b64', high: '#e17979',
}

const STATUS_LABELS: Record<string, string> = {
  pending: 'Ожидает', scanning: 'Сканируется', completed: 'Завершено', cancelled: 'Отменено',
}

function formatDate(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('ru-RU')
}

export default function Profile() {
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState('profile')
  const [user, setUser] = useState<WebsiteUser | null>(null)
  const [checks, setChecks] = useState<CheckRequest[]>([])
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    if (!getToken()) {
      setLoading(false)
      return
    }
    setLoading(true)
    setError(null)
    Promise.all([fetchMe(), fetchCheckRequests(), fetchNotifications()])
      .then(([me, reqs, notis]) => {
        setUser(me)
        setChecks(reqs)
        setNotifications(notis)
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  useEffect(load, [load])

  const handleLogout = () => {
    setToken(null)
    setUser(null)
    setChecks([])
    setNotifications([])
    navigate('/login')
  }

  const servers: LinkedServer[] = user?.servers || []
  const socials: LinkedSocial[] = user?.socials || []

  const isConnected = (provider: string) => socials.some(s => s.provider === provider)

  // ═══ Not authenticated ═══
  if (!getToken() && !loading) {
    return (
      <div className="pt-24 pb-20 px-4 sm:px-6 lg:px-8 max-w-5xl mx-auto">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}>
          <div className="evidence-panel p-12 text-center">
            <div className="w-14 h-14 rounded-2xl bg-predator-accent/10 flex items-center justify-center mx-auto mb-4">
              <Shield size={24} className="text-predator-accent" />
            </div>
            <h1 className="text-xl font-bold text-predator-text mb-2">Войдите в аккаунт</h1>
            <p className="text-sm text-predator-muted mb-6 max-w-md mx-auto">
              Личный кабинет доступен после входа. Здесь вы найдёте свои серверы, историю проверок и уведомления.
            </p>
            <button
              type="button"
              onClick={() => navigate('/login')}
              className="px-6 py-2.5 rounded-2xl bg-predator-accent text-black font-semibold text-sm hover:bg-predator-accent/90 transition-all"
            >
              Войти / Зарегистрироваться
            </button>
          </div>
        </motion.div>
      </div>
    )
  }

  // ═══ Loading / Error ═══
  if (loading || !user) {
    return (
      <div className="pt-24 pb-20 px-4 sm:px-6 lg:px-8 max-w-5xl mx-auto">
        {error ? (
          <div className="evidence-state p-10 text-center" role="alert"><AlertTriangle size={22} className="mx-auto mb-3 text-predator-danger" aria-hidden="true" /><p className="text-sm text-predator-text">Не удалось загрузить личный кабинет.</p><p className="mt-2 text-xs text-predator-muted">{error}</p><button type="button" onClick={load} className="mt-5 rounded-full border border-white/[0.1] px-4 py-2 text-xs text-predator-muted transition-colors hover:border-predator-accent hover:text-predator-accent">Повторить запрос</button></div>
        ) : (
          <div className="evidence-panel space-y-5 p-6" role="status" aria-label="Загрузка профиля"><div className="flex items-center gap-4"><span className="evidence-skeleton h-16 w-16 shrink-0 rounded-2xl" /><div className="flex-1 space-y-3"><span className="evidence-skeleton block h-4 w-40 rounded-full" /><span className="evidence-skeleton block h-3 w-64 rounded-full" /><span className="evidence-skeleton block h-3 w-32 rounded-full" /></div></div><div className="grid grid-cols-2 gap-3 sm:grid-cols-4">{Array.from({ length: 4 }, (_, index) => <span key={index} className="evidence-skeleton h-20 rounded-2xl" />)}</div><span className="evidence-skeleton block h-32 rounded-2xl" /></div>
        )}
      </div>
    )
  }

  const flaggedChecks = checks.filter(c => c.risk_level === 'high' || c.risk_level === 'medium').length
  const cleanChecks = checks.filter(c => c.risk_level === 'clean').length

  return (
    <div className="pt-24 pb-20 px-4 sm:px-6 lg:px-8 max-w-5xl mx-auto">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }}>
        {/* Header Card */}
        <div className="evidence-panel p-6 mb-6">
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-5">
            <div className="w-16 h-16 rounded-2xl bg-predator-accent/10 flex items-center justify-center text-predator-accent text-2xl font-bold">
              {user.display_name.slice(0, 1).toUpperCase()}
            </div>
            <div className="flex-1">
              <h1 className="text-xl font-bold text-predator-text">{user.display_name}</h1>
              <p className="text-sm text-predator-muted">{user.email || 'email не указан'} · {user.subscription === 'pro' ? 'Pro подписка' : 'Базовая подписка'}</p>
              <div className="flex items-center gap-3 mt-2">
                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-predator-accent/10 text-predator-accent text-xs font-medium">
                  <Shield size={10} /> {user.subscription === 'pro' ? 'Pro' : 'Базовая'}
                </span>
                <span className="text-xs text-predator-muted">
                  {servers.length === 0 ? 'Серверы не привязаны' : `${servers.length} сервер(а)`} · {checks.length} проверок
                </span>
              </div>
            </div>
            <button
              type="button"
              onClick={handleLogout}
              className="px-4 py-2 rounded-2xl border border-predator-border text-sm text-predator-muted hover:text-predator-danger hover:border-predator-danger/30 transition-all"
            >
              <LogOut size={14} className="inline mr-1.5" />
              Выйти
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div role="tablist" aria-label="Разделы личного кабинета" className="flex gap-1 mb-6 p-1 bg-predator-card rounded-3xl border border-predator-border overflow-x-auto">
          {TABS.map(tab => (
            <button
              key={tab.id}
              id={`profile-tab-${tab.id}`}
              type="button"
              role="tab"
              aria-selected={activeTab === tab.id}
              aria-controls={`profile-panel-${tab.id}`}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-2xl text-sm font-medium whitespace-nowrap transition-all ${
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
            <div id="profile-panel-profile" role="tabpanel" aria-labelledby="profile-tab-profile" className="space-y-4">
              <div className="evidence-panel p-5">
                <h3 className="text-sm font-semibold text-predator-text mb-4">Статистика</h3>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  {[
                    { label: 'Проверок', value: String(checks.length), color: '#8da2ff' },
                    { label: 'С нарушениями', value: String(flaggedChecks), color: '#e17979' },
                    { label: 'Чистых', value: String(cleanChecks), color: '#a7b1c4' },
                    { label: 'Серверов', value: String(servers.length), color: '#d8ad68' },
                  ].map(s => (
                    <div key={s.label} className="text-center p-3 rounded-2xl bg-predator-bg/50">
                      <div className="text-xl font-bold" style={{ color: s.color }}>{s.value}</div>
                      <div className="text-xs text-predator-muted mt-1">{s.label}</div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="evidence-panel p-5">
                <h3 className="text-sm font-semibold text-predator-text mb-3">История проверок</h3>
                {checks.length === 0 ? (
                  <p className="text-sm text-predator-muted py-4 text-center">
                    Проверок ещё не было — создайте заявку через Discord-сервер или на этой странице.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {checks.map(c => (
                      <div key={c.id} className="flex items-center justify-between py-2.5 px-3 rounded-2xl bg-predator-bg/30 hover:bg-predator-bg/50 transition-colors">
                        <div className="flex items-center gap-3">
                          <div className="w-7 h-7 rounded-2xl bg-predator-accent/10 flex items-center justify-center text-predator-accent text-xs font-bold">
                            {c.player_name.slice(0, 2).toUpperCase()}
                          </div>
                          <div>
                            <div className="text-sm font-medium text-predator-text">{c.player_name}</div>
                            <div className="text-xs text-predator-muted">{formatDate(c.created_at)} · {STATUS_LABELS[c.status] || c.status}</div>
                          </div>
                        </div>
                        <span className="text-xs font-medium" style={{ color: RISK_COLORS[c.risk_level || ''] || '#6b7280' }}>
                          {c.risk_level ? (c.risk_level === 'clean' ? 'Чисто' : c.risk_level === 'high' ? 'Высокий риск' : c.risk_level === 'medium' ? 'Средний риск' : 'Низкий риск') : '—'}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'servers' && (
            <div id="profile-panel-servers" role="tabpanel" aria-labelledby="profile-tab-servers" className="evidence-panel p-5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-semibold text-predator-text">Привязанные серверы</h3>
                <span className="text-xs text-predator-muted">{servers.length} сервер(а)</span>
              </div>
              {servers.length === 0 ? (
                <div className="p-6 rounded-2xl bg-predator-bg/50 border border-dashed border-predator-border text-center">
                  <Server size={20} className="text-predator-muted mx-auto mb-2" />
                  <p className="text-sm text-predator-muted">Серверы не привязаны.</p>
                  <p className="text-xs text-predator-muted/70 mt-1">Привяжите Discord-сервер через бота или позже здесь появится кнопка подключения.</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {servers.map(srv => (
                    <div key={srv.id} className="p-4 rounded-2xl bg-predator-bg/50 border border-predator-border">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className="w-9 h-9 rounded-2xl bg-[#7b8494]/15 flex items-center justify-center">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="#7b8494">
                              <path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03z"/>
                            </svg>
                          </div>
                          <div>
                            <div className="text-sm font-medium text-predator-text">{srv.guild_name}</div>
                            <div className="text-xs text-predator-muted">Проверок за неделю: {srv.checks_this_week}</div>
                          </div>
                        </div>
                        <span className="flex items-center gap-1 text-xs text-predator-accent">
                          <Check size={12} /> {srv.is_active ? 'Активен' : 'Неактивен'}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'connections' && (
            <div id="profile-panel-connections" role="tabpanel" aria-labelledby="profile-tab-connections" className="space-y-4">
              {(['discord', 'telegram'] as const).map(provider => {
                const connected = isConnected(provider)
                const social = socials.find(s => s.provider === provider)
                return (
                  <div key={provider} className="evidence-panel p-5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-4">
                        <div
                          className="w-11 h-11 rounded-2xl flex items-center justify-center"
                          style={{ background: provider === 'discord' ? '#7b849415' : '#7aa7bd15' }}
                        >
                          {provider === 'discord' ? (
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="#7b8494">
                              <path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03z"/>
                            </svg>
                          ) : (
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="#7aa7bd">
                              <path d="M11.944 0A12 12 0 000 12a12 12 0 0012 12 12 12 0 0012-12A12 12 0 0012 0a12 12 0 00-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 01.171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.479.33-.913.492-1.302.48-.428-.013-1.252-.242-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/>
                            </svg>
                          )}
                        </div>
                        <div>
                          <h3 className="text-sm font-semibold text-predator-text">{provider === 'discord' ? 'Discord' : 'Telegram'}</h3>
                          <p className="text-xs text-predator-muted">
                            {connected ? `Подключено · ${social?.provider_name || 'аккаунт'}` : 'Не подключено'}
                          </p>
                        </div>
                      </div>
                      <span className={`text-xs font-medium px-3 py-1.5 rounded-2xl ${connected ? 'text-predator-accent bg-predator-accent/10' : 'text-predator-muted bg-predator-bg/50'}`}>
                        {connected ? 'Подключено' : 'Не подключено'}
                      </span>
                    </div>
                  </div>
                )
              })}
              <p className="text-xs text-predator-muted text-center">
                OAuth-подключение будет доступно после настройки приложений Discord/Telegram.
              </p>
            </div>
          )}

          {activeTab === 'notifications' && (
            <div id="profile-panel-notifications" role="tabpanel" aria-labelledby="profile-tab-notifications" className="evidence-panel p-5">
              <h3 className="text-sm font-semibold text-predator-text mb-4">Уведомления</h3>
              {notifications.length === 0 ? (
                <p className="text-sm text-predator-muted py-6 text-center">
                  Уведомлений пока нет. Они появятся при новых заявках и результатах проверок.
                </p>
              ) : (
                <div className="space-y-3">
                  {notifications.map(n => (
                    <div key={n.id} className="flex items-start gap-3 py-3 border-b border-predator-border/50 last:border-0">
                      <div className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${n.is_read ? 'bg-predator-border' : 'bg-predator-accent'}`} />
                      <div>
                        <div className="text-sm font-medium text-predator-text">{n.title}</div>
                        {n.body && <div className="text-xs text-predator-muted mt-0.5">{n.body}</div>}
                        <div className="text-[11px] text-predator-muted/70 mt-1">{formatDate(n.created_at)}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </motion.div>
      </motion.div>
    </div>
  )
}
