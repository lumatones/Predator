import { useState } from 'react'
import { motion } from 'framer-motion'
import { Shield, Mail, Lock, Eye, EyeOff } from 'lucide-react'

export default function Login() {
  const [isLogin, setIsLogin] = useState(true)
  const [showPassword, setShowPassword] = useState(false)

  return (
    <div className="pt-24 pb-20 px-4 sm:px-6 lg:px-8 min-h-screen flex items-center justify-center">
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="w-full max-w-md"
      >
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-predator-accent/15 flex items-center justify-center mx-auto mb-4">
            <Shield size={24} className="text-predator-accent" />
          </div>
          <h1 className="text-2xl font-bold text-predator-text">
            {isLogin ? 'Вход в аккаунт' : 'Регистрация'}
          </h1>
          <p className="text-sm text-predator-muted mt-1">
            {isLogin ? 'Войдите для доступа к личному кабинету' : 'Создайте аккаунт для проверки игроков'}
          </p>
        </div>

        {/* Form */}
        <div className="glass-card p-6">
          <form onSubmit={e => e.preventDefault()} className="space-y-4">
            {!isLogin && (
              <div>
                <label className="block text-xs font-medium text-predator-muted mb-1.5">Имя</label>
                <div className="relative">
                  <input
                    type="text"
                    placeholder="Ваше имя"
                    className="w-full px-4 py-2.5 rounded-xl bg-predator-bg border border-predator-border text-predator-text text-sm placeholder:text-predator-muted/50 focus:outline-none focus:border-predator-accent/50 transition-colors"
                  />
                </div>
              </div>
            )}

            <div>
              <label className="block text-xs font-medium text-predator-muted mb-1.5">Email</label>
              <div className="relative">
                <Mail size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-predator-muted" />
                <input
                  type="email"
                  placeholder="you@server.com"
                  className="w-full pl-9 pr-4 py-2.5 rounded-xl bg-predator-bg border border-predator-border text-predator-text text-sm placeholder:text-predator-muted/50 focus:outline-none focus:border-predator-accent/50 transition-colors"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-predator-muted mb-1.5">Пароль</label>
              <div className="relative">
                <Lock size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-predator-muted" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  placeholder="••••••••"
                  className="w-full pl-9 pr-10 py-2.5 rounded-xl bg-predator-bg border border-predator-border text-predator-text text-sm placeholder:text-predator-muted/50 focus:outline-none focus:border-predator-accent/50 transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(s => !s)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-predator-muted hover:text-predator-text transition-colors"
                >
                  {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            <button className="w-full py-2.5 rounded-xl bg-predator-accent text-black font-semibold text-sm hover:bg-predator-accent/90 transition-all">
              {isLogin ? 'Войти' : 'Зарегистрироваться'}
            </button>
          </form>

          {/* Divider */}
          <div className="flex items-center gap-3 my-5">
            <div className="flex-1 h-px bg-predator-border" />
            <span className="text-xs text-predator-muted">или</span>
            <div className="flex-1 h-px bg-predator-border" />
          </div>

          {/* Social OAuth */}
          <div className="space-y-2.5">
            <button className="w-full flex items-center justify-center gap-2.5 py-2.5 rounded-xl bg-[#5865F2] text-white text-sm font-medium hover:bg-[#5865F2]/90 transition-all">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03z"/>
              </svg>
              Войти через Discord
            </button>
            <button className="w-full flex items-center justify-center gap-2.5 py-2.5 rounded-xl bg-[#26A5E4] text-white text-sm font-medium hover:bg-[#26A5E4]/90 transition-all">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <path d="M11.944 0A12 12 0 000 12a12 12 0 0012 12 12 12 0 0012-12A12 12 0 0012 0a12 12 0 00-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 01.171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.479.33-.913.492-1.302.48-.428-.013-1.252-.242-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/>
              </svg>
              Войти через Telegram
            </button>
          </div>

          {/* Toggle */}
          <p className="text-center text-xs text-predator-muted mt-5">
            {isLogin ? 'Нет аккаунта?' : 'Уже есть аккаунт?'}{' '}
            <button
              onClick={() => setIsLogin(l => !l)}
              className="text-predator-accent hover:underline font-medium"
            >
              {isLogin ? 'Зарегистрироваться' : 'Войти'}
            </button>
          </p>
        </div>

        {/* Subscription tiers */}
        <div className="mt-6 glass-card p-5">
          <h3 className="text-sm font-semibold text-predator-text mb-3 text-center">Тарифы</h3>
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 rounded-xl bg-predator-bg/50 border border-predator-accent/20 text-center">
              <div className="text-xs font-medium text-predator-accent mb-1">Базовый</div>
              <div className="text-lg font-bold text-predator-text">Бесплатно</div>
              <div className="text-xs text-predator-muted mt-1">1 сервер · 3 проверки/нед</div>
            </div>
            <div className="p-3 rounded-xl bg-predator-bg/50 border border-predator-border text-center">
              <div className="text-xs font-medium text-predator-muted mb-1">Pro</div>
              <div className="text-lg font-bold text-predator-text">$9.99<span className="text-xs font-normal text-predator-muted">/мес</span></div>
              <div className="text-xs text-predator-muted mt-1">∞ серверов · ∞ проверок</div>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  )
}
