import { useState, FormEvent, memo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, User, Lock, Loader2 } from 'lucide-react'
import { login as apiLogin } from '../api'
import PredatorLogo3D from '../components/PredatorLogo3D'

interface LoginProps {
  onLogin: (token: string, admin: { id: number; username: string; role: string }) => void
}

export default memo(function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')

    if (!username.trim() || !password.trim()) {
      setError('Введите логин и пароль')
      return
    }

    setLoading(true)
    try {
      const result = await apiLogin(username.trim(), password)
      onLogin(result.token, result.admin)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка подключения к серверу')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-content">
      <div className="login-logo-3d">
        <PredatorLogo3D />
      </div>
      <motion.form
        className="login-card"
        onSubmit={handleSubmit}
        initial={{ scale: 0.9, opacity: 0, y: 20 }}
        animate={{ scale: 1, opacity: 1, y: 0 }}
        transition={{ type: 'spring', stiffness: 260, damping: 20 }}
      >
        <div className="login-logo">
          <div className="login-logo-icon">
            <Shield size={32} strokeWidth={1.5} />
          </div>
          <h1>Predator</h1>
        </div>
        <p className="login-subtitle">Панель администратора</p>

        <AnimatePresence mode="wait">
          {error && (
          <motion.div
            className="login-error"
            role="alert"
            initial={{ x: 0 }}
            animate={{ x: [0, -5, 5, -5, 5, 0] }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.4 }}
          >
            {error}
          </motion.div>
          )}
        </AnimatePresence>

        <div className="form-group">
          <label htmlFor="username">Логин</label>
          <div className="form-input-wrap">
            <User size={16} className="form-input-icon" />
            <input
              id="username"
              type="text"
              className="form-input with-icon"
              placeholder="admin"
              value={username}
              onChange={(e) => { setUsername(e.target.value); setError('') }}
              autoFocus
            />
          </div>
        </div>

        <div className="form-group">
          <label htmlFor="password">Пароль</label>
          <div className="form-input-wrap">
            <Lock size={16} className="form-input-icon" />
            <input
              id="password"
              type="password"
              className="form-input with-icon"
              placeholder="••••••"
              value={password}
              onChange={(e) => { setPassword(e.target.value); setError('') }}
            />
          </div>
        </div>

        <motion.button
          type="submit"
          className="btn btn-primary full"
          disabled={loading}
          whileHover={{ y: -2 }}
          whileTap={{ scale: 0.98 }}
          transition={{ type: 'spring', stiffness: 400, damping: 25 }}
        >
          {loading ? (
            <>
              <Loader2 size={16} className="spinner-svg" />
              Вход...
            </>
          ) : (
            'Войти'
          )}
        </motion.button>
      </motion.form>
    </div>
  )
})
