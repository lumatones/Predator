import { useState, FormEvent } from 'react'
import { login as apiLogin } from '../api'

interface LoginProps {
  onLogin: (token: string, admin: { id: number; username: string; role: string }) => void
}

export default function Login({ onLogin }: LoginProps) {
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
    <form className="login-card" onSubmit={handleSubmit}>
      <div className="login-logo">
        <svg viewBox="0 0 36 36" fill="none">
          <path d="M18 3L3 18L18 33L33 18L18 3Z" fill="url(#lg)" opacity="0.15"/>
          <path d="M18 8L8 18L18 28L28 18L18 8Z" fill="url(#lg)" opacity="0.3"/>
          <path d="M18 13L13 18L18 23L23 18L18 13Z" fill="url(#lg)"/>
          <defs>
            <linearGradient id="lg" x1="3" y1="3" x2="33" y2="33">
              <stop stopColor="#ff4444"/>
              <stop offset="1" stopColor="#ff6b35"/>
            </linearGradient>
          </defs>
        </svg>
        <h1>Predator</h1>
      </div>
      <p className="login-subtitle">Панель администратора</p>

      {error && <div className="login-error">{error}</div>}

      <div className="form-group">
        <label htmlFor="username">Логин</label>
        <input
          id="username"
          type="text"
          className="form-input"
          placeholder="admin"
          value={username}
          onChange={e => setUsername(e.target.value)}
          autoFocus
        />
      </div>

      <div className="form-group">
        <label htmlFor="password">Пароль</label>
        <input
          id="password"
          type="password"
          className="form-input"
          placeholder="••••••"
          value={password}
          onChange={e => setPassword(e.target.value)}
        />
      </div>

      <button type="submit" className="btn btn-primary full" disabled={loading}>
        {loading ? (
          <>
            <span className="spinner" style={{ width: 16, height: 16, borderWidth: 2 }} />
            Вход...
          </>
        ) : (
          'Войти'
        )}
      </button>
    </form>
  )
}
