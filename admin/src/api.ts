const API_BASE = '/api'

interface RequestOptions {
  method?: string
  body?: unknown
  token?: string
}

async function request<T = unknown>(path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }

  if (opts.token) {
    headers['Authorization'] = `Bearer ${opts.token}`
  }

  const res = await fetch(`${API_BASE}${path}`, {
    method: opts.method || 'GET',
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  })

  const data = await res.json()

  if (!res.ok) {
    throw new Error(data.error || `HTTP ${res.status}`)
  }

  return data as T
}

// ── Auth ──

export interface LoginResponse {
  token: string
  admin: { id: number; username: string; role: string }
}

export function login(username: string, password: string) {
  return request<LoginResponse>('/admin/login', {
    method: 'POST',
    body: { username, password },
  })
}

// ── Pending Requests ──

export interface PendingRequest {
  id: number
  pc_username: string
  status: string
  created_at: string
  expires_at: string | null
}

export function getPending(token: string) {
  return request<PendingRequest[]>('/admin/pending', { token })
}

export function approveRequest(token: string, id: number) {
  return request<{ success: boolean; message: string }>(`/admin/approve/${id}`, {
    method: 'POST',
    token,
  })
}

export function rejectRequest(token: string, id: number) {
  return request<{ success: boolean; message: string }>(`/admin/reject/${id}`, {
    method: 'POST',
    token,
  })
}

// ── Tokens ──

export interface Token {
  id: number
  code: string
  code_display: string
  is_active: boolean
  used_by: string | null
  used_at: string | null
  created_at: string
  created_by_name: string
}

export function getTokens(token: string) {
  return request<Token[]>('/admin/tokens', { token })
}

export function generateTokens(token: string, count: number = 1) {
  return request<{ success: boolean; tokens: string[] }>('/admin/tokens/generate', {
    method: 'POST',
    body: { count },
    token,
  })
}

export function revokeToken(token: string, id: number) {
  return request<{ success: boolean; message: string }>(`/admin/tokens/revoke/${id}`, {
    method: 'POST',
    token,
  })
}

// ── Health / Stats ──

export function getDashboardStats(token: string) {
  return Promise.all([
    getPending(token),
    getTokens(token),
  ]).then(([pending, tokens]) => ({
    pendingCount: pending.length,
    activeTokens: tokens.filter(t => t.is_active).length,
    usedTokens: tokens.filter(t => t.used_by).length,
    recentRequests: pending.slice(0, 5),
    recentTokens: tokens.slice(0, 5),
  }))
}

export interface DashboardStats {
  pendingCount: number
  activeTokens: number
  usedTokens: number
  recentRequests: PendingRequest[]
  recentTokens: Token[]
}

// ── History ──

export interface HistoryItem {
  id: string
  date: string
  type: 'token' | 'request'
  subType: string
  description: string
  detail: string
  created_at: string
  actor: string
}

export interface HistoryResponse {
  total: number
  items: HistoryItem[]
  stats: {
    totalTokensUsed: number
    totalRequestsProcessed: number
  }
}

export function getHistory(token: string, limit: number = 100) {
  return request<HistoryResponse>(`/admin/history?limit=${limit}`, { token })
}
