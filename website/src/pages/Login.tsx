import { useState, useEffect, useMemo, useRef, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import { Shield, Mail, Lock, Eye, EyeOff, User, Loader2, AlertTriangle, Check, LogIn } from 'lucide-react'
import { ApiError, login, register, getToken } from '../api'

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase()
}

function passwordScore(password: string): number {
  return [
    password.length >= 8,
    /[A-ZА-Я]/.test(password),
    /\d/.test(password),
    /[^A-Za-zА-Яа-я0-9]/.test(password),
  ].filter(Boolean).length
}

function scoreLabel(score: number): string {
  if (score < 2) return 'Слабый пароль'
  if (score < 4) return 'Надёжный пароль'
  return 'Сильный пароль'
}

export default function Login() {
  const navigate = useNavigate()
  const displayNameRef = useRef<HTMLInputElement>(null)
  const emailRef = useRef<HTMLInputElement>(null)
  const [isLogin, setIsLogin] = useState(true)
  const [showPassword, setShowPassword] = useState(false)
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [accountExists, setAccountExists] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (getToken()) navigate('/profile')
    else if (isLogin) emailRef.current?.focus()
    else displayNameRef.current?.focus()
  }, [navigate, isLogin])

  const normalizedEmail = normalizeEmail(email)
  const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)
  const score = useMemo(() => passwordScore(password), [password])
  const passwordValid = password.length >= 8

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault()
    if (submitting) return

    if (!normalizedEmail || !password || (!isLogin && !displayName.trim())) {
      setError('Заполните все поля')
      return
    }
    if (!emailValid) {
      setError('Проверьте адрес электронной почты')
      return
    }
    if (!isLogin && !passwordValid) {
      setError('Пароль должен содержать минимум 8 символов')
      return
    }

    setSubmitting(true)
    setError(null)
    setAccountExists(false)
    try {
      if (isLogin) {
        await login(normalizedEmail, password)
      } else {
        await register(displayName.trim(), normalizedEmail, password)
        await login(normalizedEmail, password)
      }
      navigate('/profile')
    } catch (err: unknown) {
      if (!isLogin && err instanceof ApiError && err.status === 409) {
        setAccountExists(true)
      } else {
        setError(err instanceof Error ? err.message : 'Произошла ошибка')
      }
    } finally {
      setSubmitting(false)
    }
  }

  const fieldClass = 'w-full rounded-2xl border border-white/[0.1] bg-predator-bg/75 py-3.5 pl-10 pr-10 text-sm text-predator-text placeholder:text-predator-muted/50 transition-colors focus:border-predator-accent focus:outline-none'
  const switchMode = () => {
    setIsLogin(loginMode => !loginMode)
    setError(null)
    setAccountExists(false)
  }

  return (
    <div className="mx-auto flex min-h-[calc(100vh-76px)] max-w-5xl items-center px-4 py-24 sm:px-6 lg:px-8">
      <motion.div layout initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.55 }} className="mx-auto w-full max-w-md">
        <div className="mb-8 text-center">
          <motion.div layout className="mx-auto mb-5 grid h-12 w-12 place-items-center rounded-full bg-predator-accent text-predator-bg shadow-xl shadow-predator-accent/15"><Shield size={22} /></motion.div>
          <p className="data-mono text-[10px] uppercase tracking-[0.14em] text-predator-accent">Operator access</p>
          <h1 className="mt-3 text-3xl font-semibold tracking-[-0.05em] text-predator-text">{isLogin ? 'С возвращением' : 'Создать доступ'}</h1>
          <p className="mx-auto mt-2 max-w-sm text-sm leading-6 text-predator-muted">{isLogin ? 'Управляйте серверами, проверками и уведомлениями.' : 'Регистрация занимает минуту. Подтверждение email не требуется.'}</p>
        </div>

        <motion.div layout className="evidence-sheet p-6 sm:p-7">
          {accountExists && <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} className="mb-5 rounded-2xl border border-predator-accent/30 bg-predator-accent/10 p-4 text-sm text-predator-text" role="alert"><div className="flex items-start gap-2"><AlertTriangle size={15} className="mt-0.5 shrink-0 text-predator-accent" /><div><p className="font-medium">Этот email уже зарегистрирован</p><p className="mt-1 text-xs leading-5 text-predator-muted">Перейдите ко входу — подтверждение email не требуется.</p></div></div><button type="button" onClick={switchMode} className="mt-3 inline-flex items-center gap-2 rounded-full border border-predator-accent/40 px-3 py-2 text-xs font-semibold text-predator-accent transition-colors hover:bg-predator-accent hover:text-predator-bg"><LogIn size={13} /> Перейти ко входу</button></motion.div>}
          {error && <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} className="mb-5 flex items-start gap-2 rounded-2xl border border-predator-danger/30 bg-predator-danger/10 p-3 text-sm text-predator-danger" role="alert"><AlertTriangle size={15} className="mt-0.5 shrink-0" /><span>{error}</span></motion.div>}

          <form onSubmit={handleSubmit} noValidate className="space-y-5">
            <AnimatePresence initial={false} mode="popLayout">
              {!isLogin && (
                <motion.div key="display-name" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
                  <label htmlFor="display-name" className="mb-2 block text-xs text-predator-muted">Имя</label>
                  <div className="relative"><User size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-predator-muted" /><input ref={displayNameRef} id="display-name" type="text" value={displayName} onChange={event => { setDisplayName(event.target.value); setAccountExists(false) }} placeholder="Ваше имя" autoComplete="name" className={fieldClass} />{displayName.trim() && <Check size={14} className="absolute right-3.5 top-1/2 -translate-y-1/2 text-predator-accent" />}</div>
                </motion.div>
              )}
            </AnimatePresence>

            <div><label htmlFor="email" className="mb-2 block text-xs text-predator-muted">Email</label><div className="relative"><Mail size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-predator-muted" /><input ref={emailRef} id="email" type="email" value={email} onChange={event => { setEmail(event.target.value); setAccountExists(false) }} placeholder="you@server.com" autoComplete="email" aria-invalid={Boolean(email) && !emailValid} className={fieldClass} />{emailValid && <Check size={14} className="absolute right-3.5 top-1/2 -translate-y-1/2 text-predator-accent" />}</div></div>

            <div><div className="mb-2 flex items-center justify-between"><label htmlFor="password" className="text-xs text-predator-muted">Пароль</label>{!isLogin && password && <span className={`text-[10px] ${score >= 3 ? 'text-predator-accent' : 'text-predator-warning'}`}>{scoreLabel(score)}</span>}</div><div className="relative"><Lock size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-predator-muted" /><input id="password" type={showPassword ? 'text' : 'password'} value={password} onChange={event => setPassword(event.target.value)} placeholder="Минимум 8 символов" autoComplete={isLogin ? 'current-password' : 'new-password'} aria-invalid={Boolean(password) && !passwordValid} className={`${fieldClass} pr-11`} /><button type="button" aria-label={showPassword ? 'Скрыть пароль' : 'Показать пароль'} onClick={() => setShowPassword(show => !show)} className="absolute right-3.5 top-1/2 -translate-y-1/2 text-predator-muted transition-colors hover:text-predator-text">{showPassword ? <EyeOff size={14} /> : <Eye size={14} />}</button></div>{!isLogin && <div className="mt-2 flex gap-1" aria-label={`Надёжность пароля: ${score} из 4`}><span className={`h-1 flex-1 rounded-full ${score >= 1 ? 'bg-predator-danger' : 'bg-white/10'}`} /><span className={`h-1 flex-1 rounded-full ${score >= 2 ? 'bg-predator-warning' : 'bg-white/10'}`} /><span className={`h-1 flex-1 rounded-full ${score >= 3 ? 'bg-predator-accent/80' : 'bg-white/10'}`} /><span className={`h-1 flex-1 rounded-full ${score >= 4 ? 'bg-predator-accent' : 'bg-white/10'}`} /></div>}</div>

            <button type="submit" disabled={submitting} className="flex w-full items-center justify-center gap-2 rounded-full bg-predator-accent py-3.5 text-sm font-semibold text-predator-bg transition-colors hover:bg-predator-text disabled:cursor-not-allowed disabled:opacity-60">{submitting && <Loader2 size={14} className="animate-spin" />}{isLogin ? 'Войти' : 'Создать аккаунт'}</button>
          </form>

          <div className="mt-6 border-t border-white/[0.08] pt-5 text-center"><p className="text-xs text-predator-muted">{isLogin ? 'Нет аккаунта?' : 'Уже есть аккаунт?'}{' '}<button type="button" onClick={switchMode} className="font-medium text-predator-accent hover:underline">{isLogin ? 'Зарегистрироваться' : 'Войти'}</button></p></div>
        </motion.div>
      </motion.div>
    </div>
  )
}
