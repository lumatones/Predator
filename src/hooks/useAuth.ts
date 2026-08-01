import { useState, useCallback, useRef, useEffect, useMemo } from 'react'
import { validateToken, useToken, requestAccess, checkRequestStatus } from '../api'
import type { Lang } from '../types'
import { T } from '../types'

interface UseAuthReturn {
  token: string
  setToken: (t: string) => void
  tokenId: number | null
  tokenError: string
  setTokenError: (e: string) => void
  authLoading: boolean
  authError: string
  setAuthError: (e: string) => void
  pcName: string
  requestId: number | null
  requestStatus: 'pending' | 'approved' | 'rejected' | null
  handleAuth: () => Promise<boolean>
  handleRequestAccess: () => Promise<boolean>
  cancelRequest: () => void
}

export function useAuth(lang: Lang): UseAuthReturn {
  const [token, setToken] = useState('')
  const [tokenId, setTokenId] = useState<number | null>(null)
  const [tokenError, setTokenError] = useState('')
  const [authLoading, setAuthLoading] = useState(false)
  const [authError, setAuthError] = useState('')
  const [pcName, setPCName] = useState('')
  const [requestId, setRequestId] = useState<number | null>(null)
  const [requestStatus, setRequestStatus] = useState<'pending' | 'approved' | 'rejected' | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const t = useMemo(() => (key: string) => T[lang][key] || key, [lang])

  useEffect(() => {
    if (window.electronAPI?.getPCName) {
      window.electronAPI.getPCName().then(setPCName).catch(() => setPCName('unknown'))
    } else {
      setPCName('dev-' + Math.random().toString(36).slice(2, 8))
    }
  }, [])

  // Restore a previously activated token so the app skips onboarding
  // on the next launch (server tokens are single-use).
  useEffect(() => {
    const api = window.electronAPI
    if (!api?.getConfig) return
    api.getConfig()
      .then(cfg => {
        if (cfg.tokenId != null) setTokenId(cfg.tokenId)
      })
      .catch(() => { /* no config yet */ })
  }, [])

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [])

  const clearPolling = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
  }, [])

  const handleAuth = useCallback(async (): Promise<boolean> => {
    const clean = token.replace(/[-\s]/g, '')
    if (clean.length !== 32) { setTokenError(t('authError')); return false }
    setAuthLoading(true); setAuthError(''); setTokenError('')
    try {
      const vr = await validateToken(token)
      if (!vr.valid) { setAuthError(vr.error || 'Токен недействителен'); return false }
      const ur = await useToken(token, pcName || 'unknown')
      if (!ur.valid) { setAuthError(ur.error || 'Не удалось активировать токен'); return false }
      if (ur.token_id) {
        setTokenId(ur.token_id)
        // Persist activation — server tokens are single-use, so the client
        // must remember the assigned token_id across restarts.
        window.electronAPI?.saveConfig?.({ tokenId: ur.token_id }).catch(() => {})
      }
      return true
    } catch (err) { setAuthError(err instanceof Error ? err.message : 'Ошибка подключения к серверу'); return false }
    finally { setAuthLoading(false) }
  }, [token, pcName, t])

  const handleRequestAccess = useCallback(async (): Promise<boolean> => {
    setAuthLoading(true); setAuthError('')
    try {
      const result = await requestAccess(pcName || 'unknown')
      if (result.success && result.request_id) {
        setRequestId(result.request_id); setRequestStatus('pending')
        clearPolling()
        pollRef.current = setInterval(async () => {
          try {
            const status = await checkRequestStatus(result.request_id!)
            setRequestStatus(status.status as 'pending' | 'approved' | 'rejected')
            if (status.status === 'approved' || status.status === 'rejected') {
              clearPolling()
            }
          } catch { /* retry */ }
        }, 3000)
        return true
      }
      setAuthError(result.error || 'Ошибка отправки запроса')
      return false
    } catch (err) { setAuthError(err instanceof Error ? err.message : 'Ошибка подключения к серверу'); return false }
    finally { setAuthLoading(false) }
  }, [pcName, t, clearPolling])

  const cancelRequest = useCallback(() => {
    clearPolling()
    setRequestId(null)
    setRequestStatus(null)
  }, [clearPolling])

  return { token, setToken, tokenId, tokenError, setTokenError, authLoading, authError, setAuthError, pcName, requestId, requestStatus, handleAuth, handleRequestAccess, cancelRequest }
}
