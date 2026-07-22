// ── Config ──

// ── Config ──
// Change this to your public IP if you want friends to connect
// For local-only development, use http://localhost:3001

const API_BASE = 'http://5.164.42.189:3001'

// ── Types ──

export interface TokenValidateResponse {
  valid: boolean
  token_id?: number
  error?: string
}

export interface TokenUseResponse {
  valid: boolean
  token_id?: number
  message?: string
  error?: string
}

export interface RequestAccessResponse {
  success: boolean
  request_id?: number
  message?: string
  error?: string
}

export interface RequestStatusResponse {
  id: number
  pc_username: string
  status: 'pending' | 'approved' | 'rejected'
  created_at: string
  error?: string
}

// ── Helpers ──

async function fetchApi<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = await res.json()
  if (!res.ok) {
    // Validation endpoints return { valid, error } — return as data, don't throw
    if (typeof data.valid === 'boolean') return data as T
    throw new Error(data.error || `HTTP ${res.status}`)
  }
  return data as T
}

async function fetchGet<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`)
  const data = await res.json()
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
  return data as T
}

// ── Auth API ──

export async function validateToken(token: string): Promise<TokenValidateResponse> {
  return fetchApi<TokenValidateResponse>('/api/auth/token', { token })
}

export async function useToken(token: string, pc_username: string): Promise<TokenUseResponse> {
  return fetchApi<TokenUseResponse>('/api/auth/token/use', { token, pc_username })
}

export async function requestAccess(pc_username: string): Promise<RequestAccessResponse> {
  return fetchApi<RequestAccessResponse>('/api/auth/request', { pc_username })
}

export async function checkRequestStatus(id: number): Promise<RequestStatusResponse> {
  return fetchGet<RequestStatusResponse>(`/api/auth/status/${id}`)
}
